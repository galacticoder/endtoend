// https://github.com/galacticoder
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <fmt/core.h>
#include <netinet/in.h>
#include <cstdlib>
#include <regex>
#include <csignal>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <mutex>
#include <memory>
#include <ncurses.h>
#include <openssl/evp.h>
#include "headers/header-files/Client/SendAndReceive.hpp"
#include "headers/header-files/Client/FileHandling.hpp"
#include "headers/header-files/Client/httpCl.h"
#include "headers/header-files/Client/Clean.hpp"
#include "headers/header-files/Client/Ncurses.hpp"
#include "headers/header-files/Client/SignalHandler.hpp"
#include "headers/header-files/Client/TlsSetup.hpp"
#include "headers/header-files/Client/HandleClient.hpp"
#include "headers/header-files/Client/Encryption.hpp"

long int lineTrack = 0;
short leavePlace;

std::mutex mut;

extern int serverSd;
extern int clientPort;

std::string trimWhitespaces(std::string strIp) // trim whitespaces
{
    strIp.erase(strIp.begin(), find_if(strIp.begin(), strIp.end(), [](unsigned char ch)
                                       { return !isspace(ch); }));
    strIp.erase(find_if(strIp.rbegin(), strIp.rend(), [](unsigned char ch)
                        { return !isspace(ch); })
                    .base(),
                strIp.end());
    return strIp;
}

std::string getTime()
{
    auto now = std::chrono::system_clock::now();
    time_t currentTime = std::chrono::system_clock::to_time_t(now);
    tm *localTime = localtime(&currentTime);

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

    return stringFormatTime;
}

int main()
{
    signal(SIGINT, SignalHandling::signalShutdownHandler);

    WINDOW *messageInputWindow = nullptr;
    WINDOW *messageViewWindow = nullptr;
    WINDOW *subwin = nullptr;

    std::unique_ptr<EVP_PKEY, EVP_CLEANUP> privateKeyUniquePtr(nullptr);

    shutdownHandler = [&](int sig)
    {
        std::lock_guard<std::mutex> lock(mut);
        std::cout << "\b\b\b\b"; // deletes the ^C output after ctrl-c is pressed
        cleanUp::cleanWins(subwin, messageInputWindow, messageViewWindow);
        cleanUp::cleanUpOpenssl(tlsSock, startSock, receivedPublicKey, ctx);
        EVP_cleanup();
        // Delete::DeletePath(KeysReceivedFromServerPath);
        // Delete::DeletePath(YourKeysPath);
        // Delete::DeletePath(TxtDirectoryPath);
        leavePlace == 0 ? std::cout << "You have disconnected from the empty chat." << std::endl : leavePlace == 1 ? std::cout << "You have left the chat" << std::endl
                                                                                                                   : std::cout;
        exit(sig);
    };

    std::string serverIp;
    unsigned int port;

    std::cout << "Enter the server ip to connect to (Leave empty for local ip): ";
    std::getline(std::cin, serverIp);

    if (serverIp.empty())
        serverIp = "127.0.0.1";

    serverIp = trimWhitespaces(serverIp);

    std::cout << "Enter the port to connect to: ";
    std::string tmpPort;
    std::getline(std::cin, tmpPort);
    port = atoi(tmpPort.c_str());

    std::string serverPubKeyPath = fmt::format("{}{}-pubkey.pem", KeysReceivedFromServerPath, "server");
    std::string certPath = fmt::format("{}server-cert.pem", KeysReceivedFromServerPath);

    // create directories
    Create::createDirectory(KeysReceivedFromServerPath);
    Create::createDirectory(TxtDirectoryPath);
    Create::createDirectory(YourKeysPath);

    // start connection to server using tls
    StartTLS(serverIp, certPath, serverPubKeyPath, port);
    // start client server and pinging to the server
    std::thread(http::serverMake).detach();
    std::thread(http::pingServer, serverIp.c_str(), port).detach();

    HandleClient::initCheck(tlsSock);

    std::cout << fmt::format("Connected to server on port {}", port) << std::endl;

    std::string passwordNeeded = Receive::ReceiveMessageSSL(tlsSock);

    HandleClient::handlePassword(serverPubKeyPath, tlsSock, passwordNeeded);

    std::cout << "Enter your username: ";
    std::string user;
    // std::getline(std::cin, user); // username length limit 4-12
    std::cin >> user;

    // send username to server
    Send::SendMessage(tlsSock, user);

    std::string checkErrorsWithUsername = Receive::ReceiveMessageSSL(tlsSock);

    // signal to check if name already exists on server
    SignalType UsernameValiditySignal = SignalHandling::getSignalType(checkErrorsWithUsername);
    SignalHandling::handleSignal(UsernameValiditySignal, checkErrorsWithUsername);

    std::string publicKeyPath = fmt::format("{}{}-pubkey.pem", YourKeysPath, user);
    std::string privateKeyPath = fmt::format("{}{}-privkey.pem", YourKeysPath, user);

    StartTLS::generateKeys(privateKeyPath, publicKeyPath);

    EVP_PKEY *privateKey = LoadKey::LoadPrivateKey(privateKeyPath); // load your private key
    EVP_PKEY *pubkey = LoadKey::LoadPublicKey(publicKeyPath);       // load your public key

    // check if your keys loadedz
    if (!privateKey || !pubkey)
    {
        std::cout << "Your keys cannot be loaded" << std::endl;
        raise(SIGINT);
    }

    EVP_PKEY_free(pubkey);

    // receive and save users active file
    std::string usersActiveAmount = Receive::ReceiveMessageSSL(tlsSock);
    SaveFile::saveFile(usersActivePath, usersActiveAmount);

    if (std::filesystem::is_regular_file(publicKeyPath))
    {
        std::cout << fmt::format("Sending public key ({}) to server", publicKeyPath) << std::endl;
        std::string publicKeyData = ReadFile::readPemKeyContents(publicKeyPath);
        publicKeyData = Encode::Base64Encode(publicKeyData);
        Send::SendMessage(tlsSock, publicKeyData); // send your encoded key data to server
        std::cout << "Public key sent to server" << std::endl;
    }
    else
    {
        std::cout << "Public key does not exist" << std::endl;
        raise(SIGINT);
    }

    int activeUsers = ReadFile::readActiveUsers(usersActivePath);

    receivedPublicKey = HandleClient::receiveKeysAndConnect(tlsSock, receivedPublicKey, user, activeUsers);

    Ncurses::startUserMenu(messageInputWindow, subwin, messageViewWindow, tlsSock, user, receivedPublicKey, privateKey);

    raise(SIGINT);
    return 0;
}
