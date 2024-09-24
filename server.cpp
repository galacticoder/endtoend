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

#define LINE __LINE__
#define FUNC __func__
#define FILE __FILE__

std::mutex clientsMutex;

std::function<void(int)> shutdownHandler;
void signalHandleServer(int signal) { shutdownHandler(signal); }

void RateLimitTimer(const std::string hashedClientIp)
{
  static std::default_random_engine generator(time(0));
  static std::uniform_int_distribution<int> distribution(10, 30);

  int additionalDelay = distribution(generator);

  ClientResources::clientTimeLimits[hashedClientIp] = ServerSettings::defaultTimeLimit + additionalDelay;

  std::cout << "Starting timer timeout for user for hashed ip: " << hashedClientIp << std::endl;

  while (ClientResources::clientTimeLimits[hashedClientIp] != 0)
  {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    ClientResources::clientTimeLimits[hashedClientIp]--;
    std::cout << fmt::format("Hashed ip [{}] time remaining: {}", TrimmedHashedIp(hashedClientIp), ClientResources::clientTimeLimits[hashedClientIp]) << std::endl;
    std::cout << "\x1b[A";
    std::cout << eraseLine;
  }

  ClientResources::amountOfTriesFromIP[hashedClientIp] = 0;
  ClientResources::clientTimeLimits[hashedClientIp] = ServerSettings::defaultTimeLimit;

  std::cout << fmt::format("Tries for hashed ip [{}] has been resetted and can now join", TrimmedHashedIp(hashedClientIp)) << std::endl;

  return;
}

std::string GetTime()
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
  if (ClientResources::clientUsernames.size() <= 0)
  {
    std::cout << "No clients connected" << std::endl;
    return;
  }

  std::string clientUsernamesString;
  for (std::string clientUsername : ClientResources::clientUsernames)
  {
    clientUsernamesString.append(clientUsername);
    clientUsernamesString.append(",");
  }
  clientUsernamesString.pop_back();

  clientUsernamesString.size() <= 0 ? std::cout << "No connected clients" << std::endl : std::cout << fmt::format("Connected clients: {}", clientUsernamesString) << std::endl;
};

void WaitForAnotherClient(SSL *clientSocket, unsigned int &clientIndex)
{
  std::cout << "1 client connected. Waiting for another client to connect to continue" << std::endl;

  while (1)
  {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    if (ClientResources::clientsKeyContents.size() > 1)
    {
      if (Send::SendMessage<LINE>(clientSocket, std::to_string(ClientResources::clientUsernames.size()), FILE))
        return;
      std::cout << "Another user connected, proceeding..." << std::endl;
      Send::SendKey(clientSocket, 1, clientIndex);
      break;
    }
  }

  return;
}

void handleClient(SSL *clientSocketSSL, int &clientTcpSocket, const std::string &clientHashedIp)
{
  try
  {
    const std::string clientServerPort = Receive::ReceiveMessageSSL<LINE>(clientSocketSSL, FILE);
    unsigned int clientIndex = -1;

    if (clientServerPort.empty())
    {
      SSL_shutdown(clientSocketSSL);
      SSL_free(clientSocketSSL);
      close(clientTcpSocket);
      std::cout << "Client port received empty. Kicked client." << std::endl;
      return;
    }

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
        CleanUp::CleanUpClient(clientIndex, clientTcpSocket, clientSocketSSL);
        return;
      }

      {
        std::lock_guard<std::mutex> lock(clientsMutex);
        ClientResources::clientSocketsTcp.push_back(clientTcpSocket);
        ClientResources::clientSocketsSSL.push_back(clientSocketSSL);
      }

      // find Client index to use for deleting and managing client
      clientIndex = (std::find(ClientResources::clientSocketsTcp.begin(), ClientResources::clientSocketsTcp.end(), clientTcpSocket)) - ClientResources::clientSocketsTcp.begin();

      std::thread(Networking::pingClient, clientSocketSSL, std::ref(clientIndex), clientHashedIp).detach();

      {
        std::lock_guard<std::mutex> lock(clientsMutex);
        ClientResources::passwordVerifiedClients.push_back(0);
      }

      std::cout << "Size of clientHashVerifiedClients vector: " << ClientResources::passwordVerifiedClients.size() << std::endl;
      std::cout << "Password needed: " << ServerSettings::passwordNeeded << std::endl;

      std::cout << "Sending password signal to thread [" << std::this_thread::get_id() << "]" << std::endl;

      const std::string passwordNeededSignal = ServerSettings::passwordNeeded == true ? ServerSetMessage::PreLoadedSignalMessages(SignalType::PASSWORDNEEDED) : ServerSetMessage::PreLoadedSignalMessages(SignalType::PASSWORDNOTNEEDED);

      if (Send::SendMessage<LINE>(clientSocketSSL, passwordNeededSignal, FILE) != 0)
        return;

      if (HandleClient::ClientPasswordVerification(clientSocketSSL, clientIndex, ServerPrivateKeyPath, clientHashedIp, ServerSettings::serverHash) != 0)
        return;

      std::string clientUsername = Receive::ReceiveMessageSSL<LINE>(clientSocketSSL, FILE);

      // first check if their cleaned up and clean if not
      if (clientUsername.empty())
        return;

      if (HandleClient::ClientUsernameValidity(clientSocketSSL, clientIndex, clientUsername) != 0)
        return;

      // send the user an okay signal if their username is validated
      if (Send::SendMessage<LINE>(clientSocketSSL, ServerSetMessage::PreLoadedSignalMessages(SignalType::OKAYSIGNAL), FILE) != 0)
        return;

      {
        std::lock_guard<std::mutex> lock(clientsMutex);
        ServerSettings::totalClientJoins++;
        ClientResources::clientUsernames.push_back(clientUsername);
      }

      std::cout << "Client username added to clientUsernames vector" << std::endl;

      std::cout << "Sending usersactive amount" << std::endl;
      // send the connected users amount
      if (Send::SendMessage<LINE>(clientSocketSSL, std::to_string(ClientResources::clientUsernames.size()), FILE) != 0)
        return;

      std::cout << "Sent usersactive amount: " << ClientResources::clientUsernames.size() << std::endl;

      const std::string userPublicKeyPath = PublicPath(clientUsername);

      // receive the client public key and save it
      std::string encodedUserPublicKey = Receive::ReceiveMessageSSL<LINE>(clientSocketSSL, FILE);

      if (encodedUserPublicKey.empty())
        return;

      // check base 64 here maybe
      std::string decodedUserPublicKey = Decode::Base64Decode(encodedUserPublicKey);
      SaveFile::saveFile(userPublicKeyPath, decodedUserPublicKey, std::ios::binary);

      if (!std::filesystem::is_regular_file(userPublicKeyPath))
        ErrorCatching::CaughtERROR(SignalType::KEYEXISTERR, clientIndex, fmt::format("User [{}] public key file on server does not exist", clientUsername));

      EVP_PKEY *testLoadKey = LoadKey::LoadPublicKey(userPublicKeyPath);

      !testLoadKey ? ErrorCatching::CaughtERROR(SignalType::LOADERR, clientIndex, fmt::format("Cannot load user [{}] public key", clientUsername)) : EVP_PKEY_free(testLoadKey);

      ClientResources::clientsKeyContents.push_back(ReadFile::ReadPemKeyContents(PublicPath(clientUsername)));

      if (Send::SendMessage<LINE>(clientSocketSSL, ServerSetMessage::PreLoadedSignalMessages(SignalType::OKAYSIGNAL), FILE) != 0)
        return;

      if (ServerSettings::totalClientJoins > 2)
      {
        Send::BroadcastMessage(clientSocketSSL, ServerSetMessage::PreLoadedSignalMessages(SignalType::CLIENTREJOIN));
        Send::SendKey(clientSocketSSL, (clientIndex + 1) % ClientResources::clientUsernames.size(), clientIndex);
        // Send::SendKey(clientSocketSSL, clientIndex, );
        // Send::BroadcastKey(clientSocketSSL, clientIndex, 1);
      }

      else if (ClientResources::clientUsernames.size() == 2 && ServerSettings::totalClientJoins <= 2)
        Send::SendKey(clientSocketSSL, 0, clientIndex);
      else
        std::thread(WaitForAnotherClient, clientSocketSSL, std::ref(clientIndex)).join();

      auto NameJoinFormat = [](const std::string name)
      { return fmt::format("{} has joined the chat", name); };

      std::string userJoinMessage = NameJoinFormat(ClientResources::clientUsernames[(clientIndex + 1) % ClientResources::clientUsernames.size()]);

      EVP_PKEY *loadedUserPubKey = LoadKey::LoadPublicKey(PublicPath(clientUsername));

      !loadedUserPubKey ? ErrorCatching::CaughtERROR(SignalType::LOADERR, clientIndex, "Cannot load user key for sending join message") : (void)0;

      // send base 64 encoded and encrypted user join message
      if (Send::SendMessage<LINE>(clientSocketSSL, Encode::Base64Encode(Encrypt::EncryptData(loadedUserPubKey, userJoinMessage)), FILE) != 0)
        return;

      EVP_PKEY_free(loadedUserPubKey);

      std::cout << NameJoinFormat(clientUsername) << std::endl;
      GetUsersConnected();

      bool isConnected = true;

      ServerSettings::handleClientIndexChanges = true;

      while (isConnected)
      {
        std::string exitMsg = fmt::format("{} has left the chat", clientUsername);
        std::string receivedData = Receive::ReceiveMessageSSL<LINE>(clientSocketSSL, FILE);

        if (receivedData.empty() || receivedData.length() > 4096)
        {
          std::cout << exitMsg << std::endl;

          if (receivedData.empty()) // check properly for if they are cleaned up or not
            return;

          ClientResources::cleanUpInPing = false;
          isConnected = false;

          if (ClientResources::clientUsernames.size() > 1)
            Send::BroadcastEncryptedExitMessage(clientIndex, (clientIndex + 1) % ClientResources::clientUsernames.size());

          CleanUp::CleanUpClient(clientIndex);

          if (receivedData.length() > 4096)
            std::cout << "User kicked for invalid message length" << std::endl;

          GetUsersConnected();
          return;
        }

        std::cout << "Received data: " << receivedData << std::endl;
        std::cout << "Ciphertext message length: " << receivedData.length() << std::endl;

        const std::string formattedCiphertext = clientUsername + "|" + GetTime() + "|" + receivedData;

        if (Encode::CheckBase64(receivedData) != 0)
          std::cout << "Ciphertext base 64 received invalid. Not sending" << std::endl;
        else
          Send::BroadcastMessage(clientSocketSSL, formattedCiphertext);
      }

      std::cout << "Exiting handle client for user thread" << std::endl;
      return;
    }
  }
  catch (const std::exception &e)
  {
    ErrorCatching::LOGERROR(ErrorTypes::EXCEPTION, e.what(), FILE, LINE, FUNC);
    raise(SIGINT);
  }
}

int main()
{
  // initialize variables
  SSL_CTX *serverCtx;
  int serverSocket;

  ServerSettings::serverHash = NcursesMenu::StartMenu();

  // setup signal handler
  signal(SIGINT, signalHandleServer);
  shutdownHandler = [&](int signal)
  {
    std::cout << "\b\b\b\b"; // backspace to remove ^C when pressing ctrl+c
    CleanUp::CleanUpServer(serverCtx, serverSocket);
    std::cout << "Server has been shutdown" << std::endl;
    std::cout << fmt::format("Total server pings: {}", ServerSettings::pingCount) << std::endl;
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

  (std::filesystem::is_regular_file(ServerPrivateKeyPath) && std::filesystem::is_regular_file(ServerCertPath)) ? std::cout << fmt::format("Saved server keys in path '{}'", ServerKeysPath) << std::endl : std::cout << "Server keys have not been saved to path they are supposed to be. Exiting." << std::endl;

  EVP_PKEY *serverPrivateKey = LoadKey::LoadPrivateKey(ServerPrivateKeyPath);

  if (!serverPrivateKey)
  {
    std::cout << "Cannot load server's private key. Killing server." << std::endl;
    raise(SIGINT);
  }

  EVP_PKEY_free(serverPrivateKey);
  std::cout << "Server's private key has been loaded" << std::endl;

  LoadKey::extractPubKey(ServerCertPath, ServerPublicKeyPath);

  TlsSetup::LoadSSLAlgs();
  serverCtx = TlsSetup::CreateCtx();

  std::cout << "Configuring server ctx" << std::endl;
  TlsSetup::ConfigureCtx(serverCtx, ServerCertPath, ServerPrivateKeyPath);
  std::cout << "Done configuring server ctx" << std::endl;

  std::cout << "Server is now accepting connections" << std::endl;

  std::thread(startHost).detach();
  std::cout << "Started hosting server cert key" << std::endl;

  signal(SIGPIPE, SIG_IGN);
  ServerSetMessage loadServerMessages;

  while (true)
  {
    // check if its a ping or user connection request
    int clientSocketTCP = Networking::acceptClientConnection(serverSocket);

    std::string getClientConnectionSignal = Receive::ReceiveMessageTcp(clientSocketTCP);

    if (getClientConnectionSignal == ServerSetMessage::PreLoadedSignalMessages(SignalType::CONNECTIONSIGNAL))
    {
      std::cout << "User sent the connection signal. Continuing with connection" << std::endl;
      // get the hashed client ip
      const std::string clientHashedIp = Networking::GetClientIpHash(clientSocketTCP);

      if (HandleClient::isBlackListed(clientHashedIp))
      {
        send(clientSocketTCP, ServerSetMessage::PreLoadedSignalMessages(SignalType::BLACKLISTED).c_str(), ServerSetMessage::PreLoadedSignalMessages(SignalType::BLACKLISTED).length(), 0);
        close(clientSocketTCP);
        continue;
      }

      send(clientSocketTCP, (ServerSetMessage::PreLoadedSignalMessages(SignalType::OKAYSIGNAL)).c_str(), (ServerSetMessage::PreLoadedSignalMessages(SignalType::OKAYSIGNAL)).length(), 0); // send the user an okay signal when connecting and not blacklisted

      SSL *clientSocketSSL = SSL_new(serverCtx);
      SSL_set_fd(clientSocketSSL, clientSocketTCP);

      auto CleanUpUserSocks = [&]()
      {
        SSL_shutdown(clientSocketSSL);
        SSL_free(clientSocketSSL);
        close(clientSocketTCP);
      };

      if (SSL_accept(clientSocketSSL) <= 0)
      {
        ERR_print_errors_fp(stderr);
        CleanUpUserSocks();
        std::cout << "Closed user that failed at SSL/TLS handshake" << std::endl;
        continue;
      }

      if (HandleClient::IncrementUserTries(clientHashedIp) != 0) // client is blacklisted
      {
        const std::string blackListedMessage = ServerSetMessage::PreLoadedSignalMessages(SignalType::BLACKLISTED);
        Send::SendMessage<LINE>(clientSocketSSL, blackListedMessage, FILE);
        CleanUpUserSocks();
        continue;
      }

      std::cout << "Client hashed ip amount of tries: " << ClientResources::amountOfTriesFromIP[clientHashedIp] << std::endl;

      if (CheckClientConnectValidity::CheckUserValidity(clientSocketSSL, clientSocketTCP, clientHashedIp) != 0)
        continue;

      std::thread(handleClient, clientSocketSSL, std::ref(clientSocketTCP), std::ref(clientHashedIp)).detach();
    }

    else if (getClientConnectionSignal == ServerSetMessage::PreLoadedSignalMessages(SignalType::PING))
    {
      const std::string pingBackMessage = ServerSetMessage::PreLoadedSignalMessages(SignalType::PINGBACK);
      send(clientSocketTCP, pingBackMessage.c_str(), pingBackMessage.length(), 0);
      close(clientSocketTCP);
      ServerSettings::pingCount++;

      std::cout << fmt::format("Server has been pinged [{}]", ServerSettings::pingCount) << std::endl;
      std::cout << "\x1b[A" << eraseLine;
    }
  }

  raise(SIGINT);
  return 0;
}