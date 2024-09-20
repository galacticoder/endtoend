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
short usersConnected;

std::mutex mut;

std::string TrimWhitespaces(std::string strIp) // trim whitespaces
{
    strIp.erase(strIp.begin(), find_if(strIp.begin(), strIp.end(), [](unsigned char ch)
                                       { return !isspace(ch); }));
    strIp.erase(find_if(strIp.rbegin(), strIp.rend(), [](unsigned char ch)
                        { return !isspace(ch); })
                    .base(),
                strIp.end());
    return strIp;
}

std::string GetTime()
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

    shutdownHandler = [&](int sig)
    {
        windowCleaning(sig);
        EVP_PKEY *receivedPublicKey = valuePasser(sig);
        // std::cout << "\b\b\b\b"; // deletes the ^C output after ctrl-c is pressed
        CleanUp::cleanUpOpenssl(clientSocketSSL, startSock, receivedPublicKey, ctx);
        EVP_cleanup();
        Delete::DeletePath(KeysReceivedFromServerPath);
        Delete::DeletePath(YourKeysPath);

        std::cout << "You have disconnected" << std::endl;

        exit(sig);
    };

    windowCleaning = [&](int sig)
    {
        std::cout << "No windows to clean" << std::endl;
    };

    valuePasser = [&](int sig)
    {
        return nullptr;
    };

    std::string serverIp = HandleClient::GetServerIp();
    unsigned int port = HandleClient::GetPort();

    // create directories
    Create::createDirectory(KeysReceivedFromServerPath);
    Create::createDirectory(YourKeysPath);

    // start connection to server using tls
    StartTLS(serverIp, certPath, serverPubKeyPath, port);

    // start client server and pinging to the server
    std::thread(http::serverMake).detach();
    std::thread(http::pingServer, serverIp.c_str(), port).detach();

    Authentication::ServerValidation(clientSocketSSL);

    std::cout << fmt::format("Connected to server on port {}", port) << std::endl;

    std::string passwordNeeded = Receive::ReceiveMessageSSL(clientSocketSSL);

    Authentication::HandlePassword(serverPubKeyPath, clientSocketSSL, passwordNeeded);

    std::cout << "Enter your username: ";
    std::string username;
    std::getline(std::cin, username);

    // send username to server
    if (username.empty())
        raise(SIGINT);

    Send::SendMessage(clientSocketSSL, username);

    std::string checkErrorsWithUsername = Receive::ReceiveMessageSSL(clientSocketSSL);

    // signal to check if name already exists on server
    SignalType usernameValiditySignal = SignalHandling::getSignalType(checkErrorsWithUsername);
    SignalHandling::handleSignal(usernameValiditySignal, checkErrorsWithUsername);

    std::string publicKeyPath = fmt::format("{}{}-pubkey.pem", YourKeysPath, username);
    std::string privateKeyPath = fmt::format("{}{}-privkey.pem", YourKeysPath, username);

    GenerateKeys makeKeys(privateKeyPath, publicKeyPath);

    // check if your keys load
    if (!LoadKey::LoadPrivateKey(privateKeyPath) || !LoadKey::LoadPublicKey(publicKeyPath))
    {
        std::cout << "Your keys couldnt load" << std::endl;
        raise(SIGINT);
    }

    // receive users amount connected
    std::istringstream(Receive::ReceiveMessageSSL(clientSocketSSL)) >> usersConnected;

    std::cout << "Users active: " << usersConnected << std::endl;

    if (std::filesystem::is_regular_file(publicKeyPath))
    {
        std::cout << fmt::format("Sending public key ({}) to server", publicKeyPath) << std::endl;
        std::string publicKeyData = ReadFile::readPemKeyContents(publicKeyPath);
        publicKeyData = Encode::Base64Encode(publicKeyData);
        Send::SendMessage(clientSocketSSL, publicKeyData); // send your encoded key data to server
        std::cout << "Public key sent to server" << std::endl;
    }
    else
    {
        std::cout << "Public key does not exist" << std::endl;
        raise(SIGINT);
    }

    std::thread(Ncurses::startUserMenu, clientSocketSSL, username, privateKeyPath).join();

    return 0;
}
