// https://github.com/galacticoder
#include <iostream>
#include <boost/asio.hpp>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fmt/core.h>
#include <mutex>
#include <netinet/in.h>
#include <regex>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>
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
#include "headers/header-files/Server/ServerSettings.hpp"

std::mutex clientsMutex;

std::function<void(int)> shutdownHandler;
void signalHandleServer(int signal) { shutdownHandler(signal); }

void waitTimer(const std::string hashedClientIp)
{
  static std::default_random_engine generator(time(0));
  static std::uniform_int_distribution<int> distribution(10, 30);

  int additionalDelay = distribution(generator);
  ServerSettings::timeLimit += additionalDelay;

  std::cout << "Starting timer timeout for user with hash ip: " << hashedClientIp << std::endl;

  while (ServerSettings::timeLimit != 0)
  {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    ServerSettings::timeLimit--;
    std::cout << fmt::format("Timer user [{}..]: ", hashedClientIp.substr(0, hashedClientIp.length() / 4)) << ServerSettings::timeLimit << std::endl;
    std::cout << "\x1b[A";
    std::cout << eraseLine;
  }

  ClientResources::amountOfTriesFromIP[hashedClientIp] = 0;
  ClientResources::timeMap[hashedClientIp] = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  ServerSettings::timeLimit = 90;
  std::cout << fmt::format("Tries for IP hash ({}) has been resetted and can now join", hashedClientIp) << std::endl;

  return;
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

  std::regex timePattern(R"(\b\d{2}:\d{2}:\d{2}\b)");
  std::smatch match;
  if (regex_search(stringFormatTime, match, timePattern))
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
  for (std::string clientUsername : ClientResources::clientUsernames)
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
    if (ClientResources::clientsKeyContents.size() > 1)
    {
      std::cout << "Another user connected, proceeding..." << std::endl;
      Send::SendKey(clientSocket, 1, clientIndex);
      break;
    }
  }
  return;
}

void handleClient(SSL *clientSocket, int &clientTcpSocket, const std::string &clientHashedIp, const std::string &serverHash)
{
  try
  {
    const std::string clientServerPort = Receive::ReceiveMessageSSL<__LINE__>(clientSocket);

    while (ServerSettings::exitSignal != true)
    {
      std::cout << "Client server port: " << clientServerPort << std::endl;

      try
      {
        ClientResources::clientServerPorts[clientHashedIp] = atoi(clientServerPort.c_str());
      }
      catch (const std::exception &e)
      {
        std::cout << "Cannot use atoi on clientServerPort: " << e.what() << std::endl;
        std::cout << "Kicked thread: " << std::this_thread::get_id() << std::endl;
        CleanUp::CleanUpClient(-1, clientSocket);
        return;
      }

      int clientServerPortInt = ClientResources::clientServerPorts[clientHashedIp];
      std::cout << "clientServerPortInt: " << clientServerPortInt << std::endl;

      {
        std::lock_guard<std::mutex> lock(clientsMutex);
        ClientResources::clientSocketsTcp.push_back(clientTcpSocket);
        ClientResources::clientSocketsSSL.push_back(clientSocket);
      }

      // find Client index to use for deleting and managing client
      unsigned int clientIndex = (std::find(ClientResources::clientSocketsTcp.begin(), ClientResources::clientSocketsTcp.end(), clientTcpSocket)) - ClientResources::clientSocketsTcp.begin();

      std::thread(Networking::pingClient, clientSocket, std::ref(clientServerPortInt), std::ref(clientIndex)).detach();

      {
        std::lock_guard<std::mutex> lock(clientsMutex);
        ClientResources::passwordVerifiedClients.push_back(0);
      }

      std::cout << "Size of clientHashVerifiedClients vector: " << ClientResources::passwordVerifiedClients.size() << std::endl;
      std::cout << "Password needed: " << ServerSettings::passwordNeeded << std::endl;

      std::cout << "Sending password signal to thread [" << std::this_thread::get_id() << "]" << std::endl;

      const std::string passwordNeededSignal = ServerSettings::passwordNeeded == true ? ServerSetMessage::GetMessageBySignal(SignalType::PASSWORDNEEDED, 1) : ServerSetMessage::GetMessageBySignal(SignalType::PASSWORDNOTNEEDED, 1);

      Send::SendMessage(clientSocket, passwordNeededSignal);

      if (HandleClient::ClientPasswordVerification(clientSocket, clientIndex, ServerPrivateKeyPath, clientHashedIp, serverHash) != 0)
        return;

      std::string clientUsername = Receive::ReceiveMessageSSL<__LINE__>(clientSocket);

      if (HandleClient::ClientUsernameValidity(clientSocket, clientIndex, clientUsername) != 0)
        return;

      // send the user an okay signal if their username is validated
      Send::SendMessage(clientSocket, ServerSetMessage::GetMessageBySignal(SignalType::OKAYSIGNAL));

      {
        std::lock_guard<std::mutex> lock(clientsMutex);
        ServerSettings::totalClientJoins++;
        ClientResources::clientUsernames.push_back(clientUsername);
      }

      std::cout << "Client username added to clientUsernames vector" << std::endl;

      std::cout << "Sending usersactive amount" << std::endl;
      Send::SendMessage(clientSocket, std::to_string(ClientResources::clientUsernames.size())); // send the connected users amount
      std::cout << "Sent usersactive amount: " << ClientResources::clientUsernames.size() << std::endl;

      std::string formattedPublicKeyPath = fmt::format("keys-server/{}-pubkeyserver.pem", clientUsername);
      const std::string userPublicKeyPath = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.pem", clientUsername);

      // receive the client public key and save it
      std::string encodedUserPublicKey = Receive::ReceiveMessageSSL<__LINE__>(clientSocket);
      std::string decodedUserPublicKey = Decode::Base64Decode(encodedUserPublicKey);
      SaveFile::saveFile(userPublicKeyPath, decodedUserPublicKey, std::ios::binary);

      if (!std::filesystem::is_regular_file(userPublicKeyPath))
        Error::CaughtERROR(clientUsername, clientIndex, clientSocket, SignalType::KEYEXISTERR, fmt::format("User [{}] public key file on server does not exist", clientUsername));

      EVP_PKEY *testLoadKey = LoadKey::LoadPublicKey(userPublicKeyPath);

      !testLoadKey ? Error::CaughtERROR(clientUsername, clientIndex, clientSocket, SignalType::LOADERR, fmt::format("Cannot load user [{}] public key", clientUsername)) : EVP_PKEY_free(testLoadKey);

      const std::string keyReceived = ReadFile::ReadPemKeyContents(PublicPath(ClientResources::clientUsernames[clientIndex]));

      std::cout << "Received key: " << keyReceived << std::endl;
      ClientResources::clientsKeyContents.push_back(keyReceived);

      Send::SendMessage(clientSocket, ServerSetMessage::GetMessageBySignal(SignalType::OKAYSIGNAL));

      switch (ClientResources::clientUsernames.size())
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

      if (ServerSettings::totalClientJoins > 2)
        Send::SendKey(clientSocket, 0, clientIndex);

      const std::string serverJoinMessage = fmt::format("{} has joined the chat", clientUsername);

      std::string userJoinMessage;

      bool isConnected = true;

      clientIndex < 1 ? userJoinMessage = fmt::format("{} has joined the chat", ClientResources::clientUsernames[clientIndex + 1]) : userJoinMessage = fmt::format("{} has joined the chat", ClientResources::clientUsernames[clientIndex - 1]);

      EVP_PKEY *LoadedUserPubKey = LoadKey::LoadPublicKey(PublicPath(clientUsername));

      !LoadedUserPubKey ? Error::CaughtERROR(clientUsername, clientIndex, clientSocket, SignalType::LOADERR, "Cannot load user key for sending join message") : (void)0;

      std::string encryptedJoinMessage = Encrypt::EncryptData(LoadedUserPubKey, userJoinMessage);
      EVP_PKEY_free(LoadedUserPubKey);
      encryptedJoinMessage = Encode::Base64Encode(encryptedJoinMessage);
      Send::SendMessage(clientSocket, encryptedJoinMessage);
      std::cout << serverJoinMessage << std::endl;

      GetUsersConnected();

      while (isConnected)
      {
        std::string exitMsg = fmt::format("{} has left the chat", clientUsername);
        char buffer[4096] = {0};
        ssize_t bytesReceived = SSL_read(clientSocket, buffer, sizeof(buffer));
        if (bytesReceived == 0)
        {
          std::cout << exitMsg << std::endl;
          ClientResources::cleanUpInPing = false;
          isConnected = false;

          if (ClientResources::clientUsernames.size() > 1)
          {
            std::cout << fmt::format("Sending exit message to [{}]", ClientResources::clientUsernames[(clientIndex + 1) % ClientResources::clientUsernames.size()]) << std::endl;
            Send::BroadcastEncryptedExitMessage(clientIndex, (clientIndex + 1) % ClientResources::clientUsernames.size());
          }

          CleanUp::CleanUpClient(clientIndex);

          GetUsersConnected();
        }

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
          std::cout << exitMsg << std::endl;

          if (ClientResources::clientUsernames.size() > 1)
            Send::BroadcastEncryptedExitMessage(clientIndex, (clientIndex + 1) % ClientResources::clientUsernames.size());

          {
            ClientResources::cleanUpInPing = false;
            CleanUp::CleanUpClient(clientIndex);
          }

          std::cout << "Kicked user for invalid message length" << std::endl;
          return;
        }
      }

      if (ClientResources::clientUsernames.size() < 1)
      {
        std::cout << "Shutting down server due to no users." << std::endl;
        raise(SIGINT);
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

  ServerSettings::serverHash = NcursesMenu::StartMenu();
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

  signal(SIGPIPE, SIG_IGN);

  while (true)
  {
    // check if its a ping or user connection request
    int clientSocketTCP = Networking::acceptClientConnection(serverSocket);
    SSL *clientSocketSSL = nullptr;

    std::string getClientConnectionSignal = Receive::ReceiveMessageTcp(clientSocketTCP);

    if (getClientConnectionSignal == ServerSetMessage::GetMessageBySignal(SignalType::CONNECTIONSIGNAL))
    {
      std::cout << "User sent the connection signal. Continuing with connection" << std::endl;
      const std::string okaySignalMessage = ServerSetMessage::GetMessageBySignal(SignalType::OKAYSIGNAL);
      send(clientSocketTCP, okaySignalMessage.c_str(), okaySignalMessage.length(), 0);

      clientSocketSSL = SSL_new(serverCtx);
      SSL_set_fd(clientSocketSSL, clientSocketTCP);

      if (SSL_accept(clientSocketSSL) <= 0)
      {
        ERR_print_errors_fp(stderr);
        CleanUp::CleanUpClient(-1, clientSocketSSL);
        std::cout << "Closed user that failed at SSL/TLS handshake" << std::endl;
        continue;
      }

      // get the hashed client ip
      const std::string clientHashedIp = Networking::GetClientIpHash(clientSocketTCP);

      // increment amount of tries on the users hashed ip (if new user then set to 1)
      auto clientIpExistenceCheck = ClientResources::amountOfTriesFromIP.find(clientHashedIp);

      clientIpExistenceCheck == ClientResources::amountOfTriesFromIP.end() ? ClientResources::amountOfTriesFromIP[clientHashedIp] = 1 : ClientResources::amountOfTriesFromIP[clientHashedIp]++;

      std::cout << "Client hashed ip amount of tries: " << ClientResources::amountOfTriesFromIP[clientHashedIp] << std::endl;

      if (HandleClient::CheckUserRatelimited(clientSocketSSL, clientHashedIp) == -1 || HandleClient::CheckUserLimitReached(clientSocketSSL, ServerSettings::limitOfUsers) == -1 || HandleClient::CheckRequestNeededForServer(clientSocketSSL, ServerSettings::requestNeeded, clientHashedIp) == -1)
        continue;

      std::thread(handleClient, clientSocketSSL, std::ref(clientSocketTCP), std::ref(clientHashedIp)).detach();
    }

    else if (getClientConnectionSignal == ServerSetMessage::GetMessageBySignal(SignalType::PING))
    {
      const std::string pingBackMessage = ServerSetMessage::GetMessageBySignal(SignalType::PINGBACK);
      send(clientSocketTCP, pingBackMessage.c_str(), pingBackMessage.length(), 0);
      close(clientSocketTCP);
      ServerSettings::pingCount++;

      std::cout << fmt::format("Server has been pinged [{}]", ServerSettings::pingCount) << std::endl;
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
