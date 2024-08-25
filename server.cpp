// https://github.com/galacticoder
#include <iostream>
#include <atomic>
#include <boost/asio.hpp>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fmt/core.h>
#include <fstream>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <queue>
#include <regex>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include "headers/header-files/Server/hostHttp.h"
#include "headers/header-files/Server/NcursesMenu.hpp"
#include "headers/header-files/Server/SendAndReceive.hpp"
#include "headers/header-files/Server/Keys.hpp"
#include "headers/header-files/Server/Decryption.hpp"
#include "headers/header-files/Server/Encryption.hpp"
#include "headers/header-files/Server/HandleClient.hpp"
#include "headers/header-files/Server/SignalHandling.hpp"
#include "headers/header-files/Server/Networking.hpp"
#include "headers/header-files/Server/TLS.hpp"

#define userPath "txt-files/usersActive.txt"
#define OKSIG "OKAYSIGNAL"
#define conSig "C"
#define pong "pong"

#define FormatPath(username) fmt::format("keys-from-server/{}-pubkeyserver.pem", username)

using boost::asio::ip::tcp;

std::mutex clientsMutex;

int serverSock;
std::vector<int> connectedClients;
std::vector<std::string> clientUsernames;
std::vector<int> PasswordVerifiedClients;
std::vector<SSL *> SSLsocks;
std::map<std::string, std::chrono::seconds::rep> timeMap;
std::map<std::string, short> amountOfTriesFromIP;
std::map<std::string, short> clp;
std::map<std::string, std::string> usernames;
std::queue<std::string> serverJoinRequests;

int limitOfUsers = 2;
int serverSocket;
short timeLimit = 90;
short running;
long int totalClientJoins;
short exitSignal = 0;
unsigned long pingCount = 0;

const std::string limReached = "The limit of users has been reached for this chat. Exiting..";
const std::string NotVerifiedMessage = "Wrong password. You have been kicked.#N"; // #N
const std::string VerifiedMessage = "You have joined the server#V";               // #V

std::function<void(int)> shutdownHandler;
void signalHandleServer(int signal)
{
  shutdownHandler(signal);
}

void clStat(SSL *clientSocket, int &clsock, const std::string &ClientHashedIp)
{
  std::cout << "Started thread for clstat" << std::endl;
  while (1)
  {
    try
    {
      int cSockStatus = socket(AF_INET, SOCK_STREAM, 0);

      sockaddr_in serverAddress;
      serverAddress.sin_family = AF_INET;
      serverAddress.sin_port = htons(clp[ClientHashedIp]);

      if (inet_pton(AF_INET, "127.0.0.1" /*replace with user ip*/, &serverAddress.sin_addr) <= 0)
      {
        std::cerr << "Pton conversion error in clStat" << std::endl;
      }

      if (connect(cSockStatus, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
      {
        std::cout << fmt::format("Client disconnected [CANNOT CONNECT TO SERVER] [P:{}]", clp[ClientHashedIp]) << std::endl;
        std::string username;

        auto itCl = -1;

        if (connectedClients.size() > 0)
          itCl = (find(connectedClients.begin(), connectedClients.end(), clsock)) - connectedClients.begin();

        usernames.erase(ClientHashedIp);

        clientUsernames.size() > 0 &&itCl != -1 ? username = clientUsernames[itCl] : username = "";

        // leaveCl(clientSocket, clsock, ClientHashedIp, itCl, username);
        break;
      }

      const std::string statusCheckMsg = "SCHECK";
      send(cSockStatus, statusCheckMsg.c_str(), statusCheckMsg.length(), 0);

      char buffer[8] = {0};
      int valread = recv(cSockStatus, buffer, sizeof(buffer), 0);
      buffer[valread] = '\0';
      std::string readStr(buffer);

      if (readStr == "S>UP")
      {
        close(cSockStatus);
      }

      else
      {
        close(cSockStatus);
      }
    }
    catch (const std::exception &e)
    {
      std::cout << "Exception caught in clStat function: " << e.what() << std::endl;
      // leaveCl(clientSocket, clsock, ClientHashedIp, itCl, username);
      break;
    }
  }
  {
    // std::lock_guard<std::mutex> lock(mutex);
    exitSignal = 1;
  }
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

int CheckBase64(const std::string &message)
{
  const std::string store = Decode::Base64Decode(message);
  for (unsigned i = 0; i < store.size(); i++)
  {
    if (char(int(store[i])) > 128 && char(int(store[i])) < 0)
    {
      return -1;
    }
  }

  return 0;
}

std::string getTime()
{
  auto now = std::chrono::system_clock::now();
  std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
  std::tm *localTime = std::localtime(&currentTime);

  bool isPM = localTime->tm_hour >= 12;
  std::string stringFormatTime = asctime(localTime);

  int tHour = (localTime->tm_hour > 12) ? (localTime->tm_hour - 12) : ((localTime->tm_hour == 0) ? 12 : localTime->tm_hour);

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

void handleClient(SSL *clientSocket, int &ClientTcpSocket, int &PasswordNeeded, const std::string &ClientHashedIp, const std::string &serverHash)
{
  try
  {
    std::string ConnectionSignalCheck = Receive::ReceiveMessageSSL(clientSocket);

    if (ConnectionSignalCheck != conSig)
    {
      CleanUp::CleanUpClient(-1, clientSocket, ClientTcpSocket);
      std::cout << "Kicked user due to not sending connection signal" << std::endl;
      return;
    }

    const std::string ClientServerPort = Receive::ReceiveMessageSSL(clientSocket);

    try
    {
      clp[ClientHashedIp] = atoi(ClientServerPort.c_str());
    }
    catch (const std::exception &e)
    {
      std::cout << "Cannot use atoi on ClientServerPort: " << e.what() << std::endl;
      std::cout << "Kicked thread: " << std::this_thread::get_id() << e.what() << std::endl;
      CleanUp::CleanUpClient(-1, clientSocket, ClientTcpSocket);
      return;
    }

    std::thread(clStat, clientSocket, std::ref(ClientTcpSocket), std::ref(ClientHashedIp)).detach();

    while (exitSignal != 1)
    {
      {
        std::lock_guard<std::mutex> lock(clientsMutex);
        connectedClients.push_back(ClientTcpSocket);
        SSLsocks.push_back(clientSocket);
      }

      int ClientIndex = (std::find(connectedClients.begin(), connectedClients.end(), ClientTcpSocket)) - connectedClients.begin(); // find Client index to use for deleting and managing client

      PasswordVerifiedClients.push_back(0);

      std::cout << "Size of clientHashVerifiedClients vector: " << PasswordVerifiedClients.size() << std::endl;

      if (PasswordNeeded == 1)
      {
        std::cout << "Sending password needed signal to thread [{}]" << std::this_thread::get_id() << std::endl;
        const std::string PasswordNeededSignal = ServerSetMessage::GetMessageBySignal(SignalType::PASSWORDNEEDED);
        Send::SendMessage(clientSocket, PasswordNeededSignal);
        HandleClient::ClientPasswordVerification(clientSocket, ClientIndex, ServerPrivateKeyPath, ClientHashedIp, serverHash);
      }
      else
      {
        const std::string PasswordNotNeededSignal = ServerSetMessage::GetMessageBySignal(SignalType::PASSWORDNOTNEEDED);
        Send::SendMessage(clientSocket, PasswordNotNeededSignal);
      }

      std::string ClientUsername = Receive::ReceiveMessageSSL(clientSocket);

      HandleClient::ClientUsernameValidity(clientSocket, ClientIndex, ClientUsername);

      totalClientJoins++;
      clientUsernames.push_back(ClientUsername);
      std::cout << "Client username added to clientUsernames vector" << std::endl;

      Send::SendMessage(clientSocket, std::to_string(clientUsernames.size())); // send the connected users amount

      usernames[ClientHashedIp] = ClientUsername;

      std::string FormattedPublicKeyPath = fmt::format("keys-server/{}-pubkeyserver.pem", ClientUsername);
      const std::string UserPublicKeyPath = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.pem", ClientUsername);

      // receive the client public and save it
      std::string EncodedUserPublicKey = Receive::ReceiveMessageSSL(clientSocket);
      std::string DecodedUserPublicKey = Decode::Base64Decode(EncodedUserPublicKey);
      SaveFile::saveFile(UserPublicKeyPath, DecodedUserPublicKey, std::ios::binary);

      if (std::filesystem::is_regular_file(UserPublicKeyPath))
      {
        EVP_PKEY *LoadedUserPubKey = LoadKey::LoadPublicKey(UserPublicKeyPath);

        if (!LoadedUserPubKey)
        {
          std::cout << fmt::format("Cannot load user [{}] public key", ClientUsername) << std::endl;
          const std::string ErrorLoadingPublicKeyMessage = Encode::Base64Encode(ServerSetMessage::GetMessageBySignal(SignalType::LOADERR, 1));
          Send::SendMessage(clientSocket, ErrorLoadingPublicKeyMessage);
          CleanUp::CleanUpClient(ClientIndex);
          std::cout << fmt::format("Kicked user [{}]", ClientUsername) << std::endl;
          return;
        }
        EVP_PKEY_free(LoadedUserPubKey);
      }
      else
      {
        std::cout << fmt::format("User [{}] public key file on server does not exist", ClientUsername) << std::endl;
        const std::string ErrorLoadingPublicKeyMessage = Encode::Base64Encode(ServerSetMessage::GetMessageBySignal(SignalType::EXISTERR, 1));
        Send::SendMessage(clientSocket, ErrorLoadingPublicKeyMessage);
        CleanUp::CleanUpClient(ClientIndex);
        std::cout << fmt::format("Kicked user [{}]", ClientUsername) << std::endl;
        return;
      }

      if (clientUsernames.size() == 2)
      {
        std::cout << "Sending Client 1's key to Client 2" << std::endl;
        const std::string PublicKeyPath = PublicPath(clientUsernames[0]); // set the path for key to send
        const std::string SavePath = PublicPath(clientUsernames[0]);      // set the path for client to save as
        Send::SendMessage(clientSocket, SavePath);                        // send path for client to save as
        std::string KeyContents = ReadFile::ReadPemKeyContents(PublicKeyPath);
        std::string EncodedKeyContents = Encode::Base64Encode(KeyContents);
        Send::SendMessage(clientSocket, EncodedKeyContents); // send the encoded key
      }
      else if (clientUsernames.size() == 1)
      {
        std::cout << "1 client connected. Waiting for another client to connect to continue" << std::endl;
        while (1)
        {
          std::this_thread::sleep_for(std::chrono::seconds(1));

          if (clientUsernames.size() < 1)
            return;
          else if (clientUsernames.size() > 1)
          {
            std::cout << "Another user connected, proceeding..." << std::endl;
            std::cout << "Sending Client 2's key to Client 1" << std::endl;
            const std::string PublicKeyPath = PublicPath(clientUsernames[1]); // set the path for key to send
            const std::string SavePath = PublicPath(clientUsernames[1]);      // set the path for client to save as
            Send::SendMessage(clientSocket, SavePath);                        // send path for client to save as
            std::string KeyContents = ReadFile::ReadPemKeyContents(PublicKeyPath);
            std::string EncodedKeyContents = Encode::Base64Encode(KeyContents);
            Send::SendMessage(clientSocket, EncodedKeyContents); // send the encoded key
            break;
          }
        }
      }

      if (totalClientJoins > 2)
      {
        for (SSL *client : SSLsocks)
        {
          if (client != SSLsocks[1])
          {
            std::cout << "Sending Client 2's key to Client 1" << std::endl;
            const std::string PublicKeyPath = PublicPath(clientUsernames[1]); // set the path for key to send
            const std::string SavePath = PublicPath(clientUsernames[1]);      // set the path for client to save as
            const std::string RejoinSignal = ServerSetMessage::GetMessageBySignal(SignalType::CLIENTREJOIN);
            Send::SendMessage(clientSocket, RejoinSignal);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            Send::SendMessage(clientSocket, SavePath); // send the path for the user to save as
            std::string KeyContents = ReadFile::ReadPemKeyContents(PublicKeyPath);
            std::string EncodedKeyContents = Encode::Base64Encode(KeyContents);
            Send::SendMessage(clientSocket, EncodedKeyContents); // send the encoded key
          }
        }
      }

      const std::string ServerJoinMessage = fmt::format("{} has joined the chat", ClientUsername);

      std::string UserJoinMessage;
      bool isConnected = true;

      ClientIndex < 1 ? UserJoinMessage = fmt::format("{} has joined the chat", clientUsernames[ClientIndex + 1]) : UserJoinMessage = fmt::format("{} has joined the chat", clientUsernames[ClientIndex - 1]);

      EVP_PKEY *LoadedUserPubKey = LoadKey::LoadPublicKey(PublicPath(ClientUsername));

      if (!LoadedUserPubKey)
      {
        std::cout << "Cannot load user key for sending join message" << std::endl;
        const std::string KeyLoadingErrorMessage = ServerSetMessage::GetMessageBySignal(SignalType::LOADERR, 1);
        Send::SendMessage(clientSocket, KeyLoadingErrorMessage);
        CleanUp::CleanUpClient(ClientIndex);
        return;
      }

      std::string EncryptedJoinMessage = Encrypt::EncryptData(LoadedUserPubKey, UserJoinMessage);
      EVP_PKEY_free(LoadedUserPubKey);
      EncryptedJoinMessage = Encode::Base64Encode(EncryptedJoinMessage);
      Send::SendMessage(clientSocket, EncryptedJoinMessage);
      std::cout << ServerJoinMessage << std::endl;

      auto GetUsersConnected = []()
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

      GetUsersConnected();

      while (isConnected)
      {
        std::string exitMsg = fmt::format("{} has left the chat", ClientUsername);
        char buffer[4096] = {0};
        ssize_t bytesReceived = SSL_read(clientSocket, buffer, sizeof(buffer));
        if (bytesReceived <= 0)
        {
          isConnected = false;
          if (clientUsernames.size() > 1)
            Send::BroadcastEncryptedExitMessage(ClientIndex, clientUsernames.size() - 1 - ClientIndex);
          std::cout << exitMsg << std::endl;
          CleanUp::CleanUpClient(ClientIndex);

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
            const std::string formattedCipher = ClientUsername + "|" + CurrentTime + "|" + cipherText;

            if (CheckBase64(cipherText) != -1)
              Send::BroadcastMessage(clientSocket, formattedCipher);
            else
              std::cout << "Ciphertext base 64 received invalid. Not sending" << std::endl;
          }
          else
          {
            if (clientUsernames.size() > 1)
              Send::BroadcastEncryptedExitMessage(ClientIndex, clientUsernames.size() - 1 - ClientIndex);
            std::cout << exitMsg << std::endl;
            CleanUp::CleanUpClient(ClientIndex);
            std::cout << "Kicked user for invalid message length" << std::endl;
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

  int PasswordNeeded;
  int RequestNeeded;

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

  // find available port to use and setup the server to start listening for connections
  int port = Networking::findAvailablePort();
  std::cout << "Port is: " << port << std::endl;
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

  while (true)
  {
    // check if its a ping or user
    sockaddr_in clientAddress;
    socklen_t clientLen = sizeof(clientAddress);
    int clientSocketTCP = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientLen);

    std::string ConnectionSignalCheck = Receive::ReceiveMessageTcp(clientSocketTCP);

    if (ConnectionSignalCheck == conSig)
    {
      send(clientSocketTCP, OKSIG, strlen(OKSIG), 0);
      SSL *clientSocketSSL = SSL_new(serverCtx);
      SSL_set_fd(clientSocketSSL, clientSocketTCP);

      if (SSL_accept(clientSocketSSL) <= 0)
      {
        ERR_print_errors_fp(stderr);
        CleanUp::CleanUpClient(-1, clientSocketSSL, clientSocketTCP);
        std::cout << "Closed user that failed at ssl/tls handshake" << std::endl;
        continue;
      }

      const std::string ClientHashedIp = Networking::GetClientIpHash(clientSocketTCP); // get the hashed client ip

      // increment amount of tries on the users hashed ip (if new user then set to 1)
      auto it = amountOfTriesFromIP.find(ClientHashedIp);

      it == amountOfTriesFromIP.end() ? amountOfTriesFromIP[ClientHashedIp] = 1 : amountOfTriesFromIP[ClientHashedIp]++;

      std::cout << "Client hashed ip amount of tries: " << amountOfTriesFromIP[ClientHashedIp] << std::endl;

      int userLimitReachedCheck = HandleClient::CheckUserLimitReached(clientSocketSSL, clientSocketTCP, limitOfUsers);
      if (userLimitReachedCheck == -1)
        continue;

      int userRateLimitedCheck = HandleClient::CheckUserRatelimited(clientSocketSSL, clientSocketTCP, ClientHashedIp);
      if (userRateLimitedCheck == -1)
        continue;

      int requestNeededForServerCheck = HandleClient::CheckRequestNeededForServer(clientSocketSSL, clientSocketTCP, RequestNeeded, ClientHashedIp);
      if (requestNeededForServerCheck == -1)
        continue;

      std::thread(handleClient, clientSocketSSL, std::ref(clientSocketTCP), std::ref(PasswordNeeded), std::ref(ClientHashedIp), std::ref(serverHash)).detach();
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