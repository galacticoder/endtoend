// https://github.com/galacticoder
#include <iostream>
#include <fstream>
#include <sstream>
#include <functional>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <fmt/core.h>
#include <netinet/in.h>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <regex>
#include <csignal>
#include <vector>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <mutex>
#include <ncurses.h>
#include <openssl/evp.h>
#include "headers/header-files/encry.h"
#include "headers/header-files/fileAndDirHandler.h"
#include "headers/header-files/leave.h"
#include "headers/header-files/httpCl.h"
#include "headers/header-files/Clean.hpp"
#include "headers/header-files/Ncurses.hpp"
#include "headers/header-files/SignalHandler.hpp"
#include "headers/header-files/OpenSSL_TLS.hpp"
#include "headers/header-files/HandleClient.hpp"

#define S_KEYS "server-keys/"
#define usersActivePath "txt-files/usersActive.txt"
#define formatPath "keys-from-server/"
#define fpath "your-keys/"

long int track = 0;
short leavePattern;
std::mutex mut;
std::mutex openssl_mutex;

extern int serverSd;
extern int portS;

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
    signal(SIGINT, signalHandling::signalShutdownHandler);

    WINDOW *msg_input_win;
    WINDOW *msg_view_win;
    WINDOW *subwin;

    shutdown_handler = [&](int sig)
    {
        std::lock_guard<std::mutex> lock(mut);
        cleanUp::cleanWins(subwin, msg_input_win, msg_view_win);
        cleanUp::cleanUpOpenssl(tlsSock, startSock, receivedPublicKey, privateKey, ctx);
        leave();
        leaveFile(usersActivePath);
        if (leavePattern == 0)
        {
            std::cout << "You have disconnected from the empty chat." << std::endl;
        }
        else if (leavePattern == 1)
        {
            std::cout << "You have left the chat" << std::endl;
        }
        exit(sig);
    };

    leavePattern = 90;
    char serverIp[30] = "127.0.0.1"; // change to the server ip
    const std::string portPath = "txt-files/PORT.txt";
    std::ifstream file(portPath);
    std::string PORTSTR;
    std::getline(file, PORTSTR);
    unsigned int port;
    std::istringstream(PORTSTR) >> port;

    std::string publicKeyPath = fmt::format("{}{}-pubkey.pem", fpath, "mykey");
    std::string serverPubKeyPath = fmt::format("{}{}-pubkey.pem", formatPath, "server");
    std::string certPath = fmt::format("{}server-cert.pem", formatPath);
    std::string privateKeyPath = fmt::format("{}{}-privkey.pem", fpath, "mykey");
    //
    { // create directories
        createDir(fpath);
        createDir(formatPath);
        createDir(S_KEYS);
    }

    // start connection to server using tls
    TlsStart(serverIp, privateKeyPath, publicKeyPath, certPath, serverPubKeyPath, port);
    // start client server and pinging to the server
    std::thread(http::serverMake).detach();
    std::thread(http::pingServer, serverIp, port).detach();

    handleClient::initCheck(tlsSock);

    std::cout << fmt::format("Connected to server on port {}", port) << std::endl;

    std::string passSig = TlsFunc::receiveMessage(tlsSock);
    handleClient::handlePassword(serverPubKeyPath, tlsSock);

    std::cout << "Enter your username: ";
    std::string user;
    std::cin >> user;

    if (user.length() > 12 || user.length() <= 3)
    {
        std::cout << "Invalid username. Disconnecting from server\n";
        raise(SIGINT);
    }

    // send username to server
    SSL_write(tlsSock, user.c_str(), user.length());

    std::string userStr = TlsFunc::receiveMessage(tlsSock);

    // signal to check if name already exists on server
    SignalType handlerExistingName = signalHandling::getSignalType(userStr);
    signalHandling::handleSignal(handlerExistingName, userStr);

    privateKey = LoadKey::LoadPrvOpenssl(privateKeyPath);      // load your private key
    EVP_PKEY *pubkey = LoadKey::LoadPubOpenssl(publicKeyPath); // load your public key

    // check if your keys loaded
    if (!privateKey || !pubkey)
    {
        std::cout << "Your keys cannot be loaded" << std::endl;
        raise(SIGINT);
    }

    EVP_PKEY_free(pubkey);

    // receive and save users active file
    std::string usersActiveEncodedData = Receive::receiveBase64Data(tlsSock);
    std::string usersActiveDecodedData = Receive::Base64Decode(usersActiveEncodedData);
    Receive::saveFile(usersActivePath, usersActiveDecodedData);

    if (std::filesystem::is_regular_file(publicKeyPath))
    {
        std::cout << fmt::format("Sending public key ({}) to server", publicKeyPath) << std::endl;
        std::string publicKeyData = Receive::read_pem_key(publicKeyPath);
        publicKeyData = Enc::Base64Encode(publicKeyData);
        Send::sendBase64Data(tlsSock, publicKeyData);
        std::cout << "Public key sent to server" << std::endl;
    }
    else
    {
        std::cout << "Public key does not exist" << std::endl;
        raise(SIGINT);
    }

    int activeUsers = readActiveUsers(usersActivePath);

    receivedPublicKey = handleClient::receiveKeysAndConnect(tlsSock, receivedPublicKey, userStr, activeUsers);

    Ncurses::startUserMenu(msg_input_win, subwin, msg_view_win, tlsSock, userStr, receivedPublicKey, privateKey);

    raise(SIGINT);
    return 0;
}
