// https://github.com/galacticoder
#include "headers/header-files/Server/SendAndReceive.hpp"
#include "headers/header-files/Server/Decryption.hpp"
#include "headers/header-files/Server/Encryption.hpp"
#include "headers/header-files/Server/HandleClient.hpp"
#include "headers/header-files/Server/Keys.hpp"
#include "headers/header-files/Server/NcursesMenu.hpp"
#include "headers/header-files/Server/Networking.hpp"
#include "headers/header-files/Server/SignalHandling.hpp"
#include "headers/header-files/Server/TLS.hpp"
#include "headers/header-files/Server/hostHttp.h"
#include <boost/asio.hpp>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fmt/core.h>
#include <iostream>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <queue>
#include <regex>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#define pong "pong"

#define FormatPath(username) \
  fmt::format("keys-from-server/{}-pubkeyserver.pem", username)

std::mutex clientsMutex;

int serverSock;
std::vector<int> connectedClients;
std::vector<std::string> clientsKeyContents;
std::vector<std::string> clientUsernames;
std::vector<int> PasswordVerifiedClients;
std::vector<SSL *> SSLsocks;
std::map<std::string, std::chrono::seconds::rep> timeMap;
std::map<std::string, short> amountOfTriesFromIP;
std::map<std::string, short> clp;
std::queue<std::string> serverJoinRequests;

unsigned int limitOfUsers = 2;
short timeLimit = 90;
short running;
bool cleanUpInPing = true;
long int totalClientJoins;
short exitSignal = 0;
unsigned long pingCount = 0;

extern bool PasswordNeeded;
extern bool RequestNeeded;

void skip() {};
std::function<void(int)> shutdownHandler;
void signalHandleServer(int signal) { shutdownHandler(signal); }

void pingClient(SSL *clientSocketSSL, int &clientTcpSocket, int &clientServerPort, unsigned int &clientIndex)
{
  std::cout << "Started thread for pinging client" << std::endl;
  while (1)
  {
    try
    {
      int pingingSocket = socket(AF_INET, SOCK_STREAM, 0);

      sockaddr_in serverAddress;
      serverAddress.sin_family = AF_INET;
      serverAddress.sin_port = htons(clientServerPort);

      if (inet_pton(AF_INET, "127.0.0.1" /*replace with user ip*/, &serverAddress.sin_addr) <= 0)
        std::cerr << "Pton conversion error in clStat" << std::endl;

      if (connect(pingingSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
      {
        std::cout << fmt::format("Client disconnected [CANNOT CONNECT TO SERVER] [P:{}]", clientServerPort) << std::endl;

        std::cout << "Kicking client index: " << clientIndex << std::endl;

        if (cleanUpInPing != false)
          connectedClients.size() > 0 ? CleanUp::CleanUpClient(clientIndex) : CleanUp::CleanUpClient(-1, clientSocketSSL, clientTcpSocket);
        else
        {
          std::cout << "cleanUpInPing is false. Clean up occuring somewhere else." << std::endl;
          cleanUpInPing = true; // set back to default
        }

        break;
      }

      const std::string statusCheckMsg = ServerSetMessage::GetMessageBySignal(SignalType::STATUSCHECKSIGNAL);
      send(pingingSocket, statusCheckMsg.c_str(), statusCheckMsg.length(), 0);

      std::string readStr = Receive::ReceiveMessageTcp(pingingSocket);

      close(pingingSocket);
    }
    catch (const std::exception &e)
    {
      std::cout << "Exception caught in clStat function: " << e.what() << std::endl;
      break;
    }
  }
  exitSignal = 1;
}

void waitTimer(const std::string hashedClientIp)
{
  // std::lock_guard<std::mutex> lock(mutex);
  static std::default_random_engine generator(time(0));
  static std::uniform_int_distribution<int> distribution(10, 30);

  int additionalDelay = distribution(generator);
  timeLimit += additionalDelay;

  if (running == 0)
  {
    std::cout << "Starting timer timeout for user with hash ip: " << hashedClientIp << std::endl;
    running = 1;
    int len = hashedClientIp.length();
    while (timeLimit != 0)
    {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      timeLimit--;
      std::cout << fmt::format("Timer user [{}..]: ", hashedClientIp.substr(0, len / 4)) << timeLimit << std::endl;
      std::cout << "\x1b[A";
      std::cout << eraseLine;
    }

    if (timeLimit == 0)
    {
      amountOfTriesFromIP[hashedClientIp] = 0;
      timeMap[hashedClientIp] = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
      timeLimit = 90;
      running = 0;
      std::cout << fmt::format("Tries for IP hash ({}) has been resetted and can now join", hashedClientIp) << std::endl;
    }
  }
}

std::string getTime()
{
  auto now = std::chrono::system_clock::now();
  std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
  std::tm *localTime = std::localtime(&currentTime);

  bool isPM = localTime->tm_hour >= 12;
  std::string stringFormatTime = asctime(localTime);

  int tHour = (localTime->tm_hour > 12)
                  ? (localTime->tm_hour - 12)
                  : ((localTime->tm_hour == 0) ? 12 : localTime->tm_hour);

  std::stringstream ss;
  ss << tHour << ":" << (localTime->tm_min < 10 ? "0" : "") << localTime->tm_min << " " << (isPM ? "PM" : "AM");
  std::string formattedTime = ss.str();

  std::regex time_pattern(R"(\b\d{2}:\d{2}:\d{2}\b)");
  std::smatch match;
  if (regex_search(stringFormatTime, match, time_pattern))
  {
    std::string str = match.str(0);
    size_t pos = stringFormatTime.find(str);
    stringFormatTime.replace(pos, str.length(), formattedTime);
  }
  if (!stringFormatTime.empty())
    return stringFormatTime;

  return "";
}

void GetUsersConnected()
{
  std::string clientUsernamesString;
  for (std::string clientUsername : clientUsernames)
  {
    clientUsernamesString.append(clientUsername);
    clientUsernamesString.append(",");
  }
  clientUsernamesString.pop_back();

  clientUsernamesString.size() <= 0 ? std::cout << "No connected clients" << std::endl : std::cout << fmt::format("Connected clients: {}", clientUsernamesString) << std::endl;
};

void waitForAnotherClient(SSL *clientSocket, unsigned int &clientIndex)
{
  std::cout << "1 client connected. Waiting for another client to connect to continue" << std::endl;

  while (1)
  {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    if (clientsKeyContents.size() > 1)
    {
      std::cout << "Another user connected, proceeding..." << std::endl;
      Send::SendKey(clientSocket, 1, clientIndex);
      break;
    }
  }
  return;
}

void handleClient(SSL *clientSocket, int &ClientTcpSocket, bool &PasswordNeeded, const std::string &clientHashedIp, const std::string &serverHash)
{
  try
  {
    const std::string connectionSignal = ServerSetMessage::GetMessageBySignal(SignalType::CONNECTIONSIGNAL);

    std::string ConnectionSignalCheck = Receive::ReceiveMessageSSL(clientSocket);

    if (ConnectionSignalCheck != connectionSignal)
    {
      CleanUp::CleanUpClient(-1, clientSocket, ClientTcpSocket);
      std::cout << "Kicked user due to not sending connection signal" << std::endl;
      return;
    }

    const std::string clientServerPort = Receive::ReceiveMessageSSL(clientSocket);

    std::cout << "Client server port: " << clientServerPort << std::endl;

    try
    {
      clp[clientHashedIp] = atoi(clientServerPort.c_str());
    }
    catch (const std::exception &e)
    {
      std::cout << "Cannot use atoi on clientServerPort: " << e.what() << std::endl;
      std::cout << "Kicked thread: " << std::this_thread::get_id() << std::endl;
      CleanUp::CleanUpClient(-1, clientSocket, ClientTcpSocket);
      return;
    }

    int clientServerPortInt = clp[clientHashedIp];
    std::cout << "clientServerPortInt: " << clientServerPortInt << std::endl;

    {
      std::lock_guard<std::mutex> lock(clientsMutex);
      connectedClients.push_back(ClientTcpSocket);
      SSLsocks.push_back(clientSocket);
    }

    unsigned int clientIndex = (std::find(connectedClients.begin(), connectedClients.end(), ClientTcpSocket)) - connectedClients.begin(); // find Client index to use for deleting and managing client

    std::thread(pingClient, clientSocket, std::ref(ClientTcpSocket), std::ref(clientServerPortInt), std::ref(clientIndex)).detach();

    while (exitSignal != 1)
    {
      {
        std::lock_guard<std::mutex> lock(clientsMutex);
        PasswordVerifiedClients.push_back(0);
      }

      std::cout << "Size of clientHashVerifiedClients vector: " << PasswordVerifiedClients.size() << std::endl;
      std::cout << "Password needed: " << PasswordNeeded << std::endl;

      std::cout << "Sending password signal to thread [" << std::this_thread::get_id() << "]" << std::endl;

      const std::string passwordNeededSignal = PasswordNeeded == true ? ServerSetMessage::GetMessageBySignal(SignalType::PASSWORDNEEDED, 1) : ServerSetMessage::GetMessageBySignal(SignalType::PASSWORDNOTNEEDED, 1);

      Send::SendMessage(clientSocket, passwordNeededSignal);

      if (HandleClient::ClientPasswordVerification(clientSocket, clientIndex, ServerPrivateKeyPath, clientHashedIp, serverHash) != 0)
        return;

      std::string clientUsername = Receive::ReceiveMessageSSL(clientSocket);

      if (HandleClient::ClientUsernameValidity(clientSocket, clientIndex, clientUsername) != 0)
        return;

      Send::SendMessage(clientSocket, ServerSetMessage::GetMessageBySignal(SignalType::OKAYSIGNAL)); // send the user an okay signal if their username is validated

      {
        std::lock_guard<std::mutex> lock(clientsMutex);
        totalClientJoins++;
        clientUsernames.push_back(clientUsername);
      }

      std::cout << "Client username added to clientUsernames vector" << std::endl;

      std::cout << "Sending usersactive amount" << std::endl;
      Send::SendMessage(clientSocket, std::to_string(clientUsernames.size())); // send the connected users amount
      std::cout << "Sent usersactive amount: " << clientUsernames.size() << std::endl;

      std::string formattedPublicKeyPath = fmt::format("keys-server/{}-pubkeyserver.pem", clientUsername);
      const std::string userPublicKeyPath = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.pem", clientUsername);

      // receive the client public key and save it
      std::string encodedUserPublicKey = Receive::ReceiveMessageSSL(clientSocket);
      std::string decodedUserPublicKey = Decode::Base64Decode(encodedUserPublicKey);
      SaveFile::saveFile(userPublicKeyPath, decodedUserPublicKey, std::ios::binary);

      if (!std::filesystem::is_regular_file(userPublicKeyPath))
        Error::CaughtERROR(clientUsername, clientIndex, clientSocket, SignalType::EXISTERR, fmt::format("User [{}] public key file on server does not exist", clientUsername));

      EVP_PKEY *testLoadKey = LoadKey::LoadPublicKey(userPublicKeyPath);

      !testLoadKey ? Error::CaughtERROR(clientUsername, clientIndex, clientSocket, SignalType::LOADERR, fmt::format("Cannot load user [{}] public key", clientUsername)) : EVP_PKEY_free(testLoadKey);

      const std::string keyReceived = ReadFile::ReadPemKeyContents(PublicPath(clientUsernames[clientIndex]));

      std::cout << "Received key: " << keyReceived << std::endl;
      clientsKeyContents.push_back(keyReceived);

      Send::SendMessage(clientSocket, ServerSetMessage::GetMessageBySignal(SignalType::OKAYSIGNAL));

      switch (clientUsernames.size())
      {
      case 2: // if clientusernames vector is 2
        Send::SendKey(clientSocket, 0, clientIndex);
        break;
      case 1: // if clientusernames vector is 1
        std::thread(waitForAnotherClient, clientSocket, std::ref(clientIndex)).join();
        break;
      default:
        return;
      }

      if (totalClientJoins > 2)
        Send::SendKey(clientSocket, 0, clientIndex);

      const std::string ServerJoinMessage = fmt::format("{} has joined the chat", clientUsername);

      std::string UserJoinMessage;
      bool isConnected = true;

      clientIndex < 1 ? UserJoinMessage = fmt::format("{} has joined the chat", clientUsernames[clientIndex + 1]) : UserJoinMessage = fmt::format("{} has joined the chat", clientUsernames[clientIndex - 1]);

      EVP_PKEY *LoadedUserPubKey = LoadKey::LoadPublicKey(PublicPath(clientUsername));

      !LoadedUserPubKey ? Error::CaughtERROR(clientUsername, clientIndex, clientSocket, SignalType::LOADERR, "Cannot load user key for sending join message") : skip();

      std::string EncryptedJoinMessage = Encrypt::EncryptData(LoadedUserPubKey, UserJoinMessage);
      EVP_PKEY_free(LoadedUserPubKey);
      EncryptedJoinMessage = Encode::Base64Encode(EncryptedJoinMessage);
      Send::SendMessage(clientSocket, EncryptedJoinMessage);
      std::cout << ServerJoinMessage << std::endl;

      GetUsersConnected();

      while (isConnected)
      {
        std::string exitMsg = fmt::format("{} has left the chat", clientUsername);
        char buffer[4096] = {0};
        ssize_t bytesReceived = SSL_read(clientSocket, buffer, sizeof(buffer));
        if (bytesReceived <= 0)
        {
          isConnected = false;
          if (clientUsernames.size() > 1)
            Send::BroadcastEncryptedExitMessage(clientIndex, (clientIndex + 1) % clientUsernames.size());

          std::cout << exitMsg << std::endl;
          // CleanUp::CleanUpClient(clientIndex);

          GetUsersConnected();

          if (clientUsernames.size() < 1)
          {
            std::cout << "Shutting down server due to no users." << std::endl;
            raise(SIGINT);
          }
        }
        else
        {
          buffer[bytesReceived] = '\0';
          std::string receivedData(buffer);
          std::cout << "Received data: " << receivedData << std::endl;
          std::cout << "Ciphertext message length: " << receivedData.length() << std::endl;
          std::string cipherText = receivedData;

          if (cipherText.length() < 4096)
          {
            const std::string CurrentTime = getTime();
            const std::string formattedCipher = clientUsername + "|" + CurrentTime + "|" + cipherText;

            if (Encode::CheckBase64(cipherText) != -1)
              Send::BroadcastMessage(clientSocket, formattedCipher);
            else
              std::cout << "Ciphertext base 64 received invalid. Not sending" << std::endl;
          }
          else
          {
            if (clientUsernames.size() > 1)
              Send::BroadcastEncryptedExitMessage(clientIndex, (clientIndex + 1) % clientUsernames.size());

            std::cout << exitMsg << std::endl;
            {
              cleanUpInPing = false;
              CleanUp::CleanUpClient(clientIndex);
            }
            std::cout << "Kicked user for invalid message length" << std::endl;
            return;
          }
        }
      }
      return;
    }
  }
  catch (const std::exception &e)
  {
    std::cout << "Server has been killed due to error (2): " << e.what() << std::endl;
    raise(SIGINT);
  }
}

int main()
{
  // initialize variables
  SSL_CTX *serverCtx;
  int serverSocket;

  const std::string serverHash = NcursesMenu::StartMenu();
  signal(SIGINT, signalHandleServer);

  // setup signal handler
  shutdownHandler = [&](int signal)
  {
    std::cout << "\b\b\b\b"; // backspace to remove ^C when pressing ctrl+c
    CleanUp::CleanUpServer(serverCtx, serverSocket);
    std::cout << "Server has been shutdown" << std::endl;
    exit(signal);
  };

  // find available port to use and setup the server to start listening for
  // connections
  int port = Networking::findAvailablePort();
  serverSocket = Networking::startServerSocket(port);

  // make directories for storing server keys and received server keys
  Create::CreateDirectory(ServerKeysPath);
  Create::CreateDirectory(ServerReceivedKeysPath);

  std::cout << "Generating server keys.." << std::endl;
  GenerateServerCert serverKeyGeneration(ServerPrivateKeyPath, ServerCertPath);

  std::cout << fmt::format("Saved server keys in path '{}'", ServerKeysPath) << std::endl;

  EVP_PKEY *serverPrivateKey = LoadKey::LoadPrivateKey(ServerPrivateKeyPath);

  if (serverPrivateKey)
  {
    std::cout << "Server's private key has been loaded" << std::endl;
    EVP_PKEY_free(serverPrivateKey);
  }
  else
  {
    std::cout << "Cannot load server's private key. Killing server." << std::endl;
    raise(SIGINT);
  }

  TlsSetup InitOpenSSL;
  serverCtx = TlsSetup::CreateCtx();

  std::cout << "Configuring server ctx" << std::endl;
  TlsSetup::ConfigureCtx(serverCtx, ServerCertPath, ServerPrivateKeyPath);
  std::cout << "Done configuring server ctx" << std::endl;

  std::cout << "Server is now accepting connections" << std::endl;

  std::thread(startHost).detach();
  std::cout << "Started hosting server cert key" << std::endl;

  // sigignore(SIGPIPE);
  signal(SIGPIPE, SIG_IGN);
  const std::string connectionSignal = ServerSetMessage::GetMessageBySignal(SignalType::CONNECTIONSIGNAL);

  while (true)
  {
    // check if its a ping or user
    sockaddr_in clientAddress;
    socklen_t clientLen = sizeof(clientAddress);
    int clientSocketTCP = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientLen);

    std::string ConnectionSignalCheck = Receive::ReceiveMessageTcp(clientSocketTCP);

    if (ConnectionSignalCheck == connectionSignal)
    {
      const std::string userOkaySignal = ServerSetMessage::GetMessageBySignal(SignalType::OKAYSIGNAL);
      send(clientSocketTCP, userOkaySignal.c_str(), strlen(userOkaySignal.c_str()), 0);
      SSL *clientSocketSSL = SSL_new(serverCtx);
      SSL_set_fd(clientSocketSSL, clientSocketTCP);

      if (SSL_accept(clientSocketSSL) <= 0)
      {
        ERR_print_errors_fp(stderr);
        CleanUp::CleanUpClient(-1, clientSocketSSL, clientSocketTCP);
        std::cout << "Closed user that failed at SSL/TLS handshake" << std::endl;
        continue;
      }

      const std::string clientHashedIp = Networking::GetClientIpHash(clientSocketTCP); // get the hashed client ip

      // increment amount of tries on the users hashed ip (if new user then set
      // to 1)
      auto it = amountOfTriesFromIP.find(clientHashedIp);

      it == amountOfTriesFromIP.end() ? amountOfTriesFromIP[clientHashedIp] = 1 : amountOfTriesFromIP[clientHashedIp]++;

      std::cout << "Client hashed ip amount of tries: " << amountOfTriesFromIP[clientHashedIp] << std::endl;

      int userLimitReachedCheck = HandleClient::CheckUserLimitReached(
          clientSocketSSL, clientSocketTCP, limitOfUsers);

      if (userLimitReachedCheck == -1)
        continue;

      int userRateLimitedCheck = HandleClient::CheckUserRatelimited(
          clientSocketSSL, clientSocketTCP, clientHashedIp);

      if (userRateLimitedCheck == -1)
        continue;

      int requestNeededForServerCheck = HandleClient::CheckRequestNeededForServer(clientSocketSSL, clientSocketTCP, RequestNeeded, clientHashedIp);

      if (requestNeededForServerCheck == -1)
        continue;

      std::thread(handleClient, clientSocketSSL, std::ref(clientSocketTCP), std::ref(PasswordNeeded), std::ref(clientHashedIp), std::ref(serverHash)).detach();
    }

    else if (ConnectionSignalCheck == "ping")
    {
      send(clientSocketTCP, pong, strlen(pong), 0);
      close(clientSocketTCP);
      pingCount++;
      std::cout << fmt::format("Server has been pinged [{}]", pingCount) << std::endl;
      std::cout << "\x1b[A" << eraseLine;
    }

    else
    {
      close(clientSocketTCP);
    }
  }

  raise(SIGINT);
  return 0;
}
