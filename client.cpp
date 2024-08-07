// https://github.com/galacticoder
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <fmt/core.h>
#include <netinet/in.h>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <arpa/inet.h>
#include <cstdlib>
#include <termios.h>
#include <regex>
#include <filesystem>
#include <bits/stdc++.h>
#include <csignal>
#include <vector>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "headers/header-files/encry.h"
#include "headers/header-files/getch_getline_cl.h"
#include "headers/header-files/fileAndDirHandler.h"
#include "headers/header-files/leave.h"
#include "headers/header-files/linux_conio.h"
#include "headers/header-files/termCmds.h"
#include "headers/header-files/fetchHttp.h"

#define GREEN_TEXT "\033[32m" // green text color
#define RESET_TEXT "\033[0m"  // reset color to default
#define xU "\u02DF"
#define connectionSignal "C"
#define joinSignal "JOINED"
#define S_KEYS "server-keys/"
#define usersActivePath "txt-files/usersActive.txt"

int startSock;
short leavePattern;
short checkMsg = 0;
std::vector<int> clsock;
std::vector<std::string> usersActiveVector;
SSL *tlsSock;
SSL_CTX *pubclctx;
EVP_PKEY *receivedPublicKey;
EVP_PKEY *prkey;

std::string t_w(std::string strIp) // trim whitespaces
{
    strIp.erase(strIp.begin(), find_if(strIp.begin(), strIp.end(), [](unsigned char ch)
                                       { return !isspace(ch); }));
    strIp.erase(find_if(strIp.rbegin(), strIp.rend(), [](unsigned char ch)
                        { return !isspace(ch); })
                    .base(),
                strIp.end());
    return strIp;
}

void signalhandle(int signum)
{
    disable_conio_mode();
    termcmd setdefault;
    setdefault.set_curs_vb();
    setdefault.set_inp();
    if (leavePattern == 0)
    {
        std::cout << "You have disconnected from the empty chat." << std::endl;
        leave();
        leaveFile(usersActivePath);
        if (tlsSock)
        {
            SSL_shutdown(tlsSock);
            SSL_free(tlsSock);
        }
        if (startSock)
        {
            close(startSock);
        }
        if (pubclctx)
        {
            SSL_CTX_free(pubclctx);
        }
        if (prkey)
        {
            EVP_PKEY_free(prkey);
        }
        EVP_cleanup();
        std::cout << eraseLine;
        exit(signum);
    }
    else if (leavePattern == 1)
    {
        std::cout << "You have left the chat" << std::endl;
        leave();
        leaveFile(usersActivePath);
        if (tlsSock)
        {
            SSL_shutdown(tlsSock);
            SSL_free(tlsSock);
        }
        if (startSock)
        {
            close(startSock);
        }
        if (pubclctx)
        {
            SSL_CTX_free(pubclctx);
        }
        if (prkey)
        {
            EVP_PKEY_free(prkey);
        }
        if (receivedPublicKey)
        {
            EVP_PKEY_free(receivedPublicKey);
        }
        EVP_cleanup();
        std::cout << eraseLine;
        exit(signum);
    }
    else if (leavePattern == 90)
    {
        leave();
        leaveFile(usersActivePath);

        if (tlsSock)
        {
            SSL_shutdown(tlsSock);
            SSL_free(tlsSock);
        }
        if (startSock)
        {
            close(startSock);
        }
        if (pubclctx)
        {
            SSL_CTX_free(pubclctx);
        }
        EVP_cleanup();
        std::cout << eraseLine;
        exit(signum);
    }
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

void receiveMessages(SSL *tlsSock, EVP_PKEY *privateKey)
{
    char buffer[4096];
    while (true)
    {
        ssize_t bytesReceived = SSL_read(tlsSock, buffer, sizeof(buffer) - 1);
        if (bytesReceived > 0)
        {
            Dec decoding;
            Dec decrypt;
            buffer[bytesReceived] = '\0';
            std::string receivedMessage(buffer);
            std::string decodedMessage;

            if (receivedMessage.substr(receivedMessage.length() - 2, receivedMessage.length()) == "#N") // not verified message
            {
                leavePattern = 90;
                Dec decNV;
                receivedMessage = receivedMessage.substr(0, receivedMessage.length() - 2);
                decNV.Base64Decode(receivedMessage);
                try
                {
                    std::string decNVS = decrypt.dec(privateKey, decodedMessage);
                    disable_conio_mode();
                    std::cout << decNVS << std::endl;
                    raise(SIGINT);
                }
                catch (const CryptoPP::Exception &e)
                {
                    raise(SIGINT);
                }
            }

            else if (receivedMessage.find('|') == std::string::npos)
            {
                decodedMessage = decoding.Base64Decode(receivedMessage);
                try
                {
                    std::string decryptedMessage = decrypt.dec(privateKey, decodedMessage);
                    passval(decryptedMessage);
                    checkMsg = 1;
                }
                catch (const std::exception &e)
                {
                }
            }

            if (bytesReceived < 500)
            {
                if (receivedMessage.find('|') == std::string::npos)
                {
                    disable_conio_mode();
                    std::cout << receivedMessage << std::endl;
                    enable_conio_mode();
                    continue;
                }
            }

            int firstPipe = receivedMessage.find_first_of("|");
            int secondPipe = receivedMessage.find_last_of("|");
            std::string cipher = receivedMessage.substr(secondPipe + 1);
            std::string time = receivedMessage.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
            std::string user = receivedMessage.substr(0, firstPipe);
            decodedMessage = decoding.Base64Decode(cipher);

            try
            {
                if (receivedMessage.find('|') != std::string::npos) // for messages from client
                {
                    disable_conio_mode();
                    std::string decryptedMessage = decrypt.dec(privateKey, decodedMessage);
                    std::cout << fmt::format("{}: {}\t\t\t\t{}", user, decryptedMessage, time);
                }
                enable_conio_mode();
            }
            catch (const std::exception &e)
            {
            }
        }
    }
}

int main()
{
    leavePattern = 90;
    signal(SIGINT, signalhandle);

    initOpenSSL initializeTls;
    termcmd curs;
    Enc enc;
    Dec dec;
    LoadKey load;
    Send send;
    Recieve receive;

    {
        curs.set_curs_vb(0);
        curs.set_inp(0);
    }
    { // init openssl
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
    }
    { // create directories
        createDir(fpath);
        createDir(formatPath);
        createDir(S_KEYS);
    }

    char serverIp[30] = "127.0.0.1"; // change to the server ip
    const std::string portPath = "txt-files/PORT.txt";
    std::ifstream file(portPath);
    std::string PORTSTR;
    std::getline(file, PORTSTR);
    int PORT;
    std::istringstream(PORTSTR) >> PORT;

    std::string pu = fmt::format("{}{}-pubkey.pem", fpath, "mykey");
    std::string puServer = fmt::format("{}{}-pubkey.pem", formatPath, "server");
    std::string cert = fmt::format("{}server-cert.pem", formatPath);
    std::string pr = fmt::format("{}{}-privkey.pem", fpath, "mykey");

    { // initialize open tlsSock and create ctx
        std::cout << "Initializing OpenSSL" << std::endl;
        initializeTls.InitOpenssl();
        std::cout << "OpenSSL initialized" << std::endl;

        std::cout << "Creating ctx" << std::endl;
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        pubclctx = ctx;
        std::cout << "Ctx Created" << std::endl;
    }

    { // generate your keys
        std::cout << "Generating keys" << std::endl;
        KeysMake genKeys(pr, pu);
        std::cout << "Keys have been generated" << std::endl;
    }

    { // get server cert and exetract public key
        const std::string get = fmt::format("http://{}:{}/", serverIp, 90);
        std::cout << fmt::format("Fetching server cert file from: {}", get) << std::endl;
        if (fetchAndSave(get, cert) == 1)
        {
            std::cout << "Could not fetch server cert" << std::endl;
            raise(SIGINT);
        }
        std::cout << "Extracting server public key from cert" << std::endl;
        load.extractPubKey(cert, puServer);
        std::cout << "Extracted server public key from cert and stored in: " << puServer << std::endl;
        // exit(1);
    }

    { // configure ctx
        std::cout << "Configuring ctx" << std::endl;
        initializeTls.configureContext(pubclctx, cert);
        std::cout << "Context has been configured" << std::endl;
    }

    startSock = socket(AF_INET, SOCK_STREAM, 0);

    { // connect to the server using socket
        sockaddr_in serverAddress;
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(PORT);
        serverAddress.sin_addr.s_addr = inet_addr(serverIp);

        if (inet_pton(AF_INET, serverIp, &serverAddress.sin_addr) <= 0)
        {
            std::cout << "Invalid address / Address not supported\n";
            raise(SIGINT);
        }

        if (connect(startSock, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
        {
            std::cout << "Cannot connect to server\n";
            raise(SIGINT);
        }
    }

    tlsSock = SSL_new(pubclctx);

    { // connect using tlsSock
        if (tlsSock == nullptr)
        {
            std::cerr << "Failed to create tlsSock object\n";
            close(startSock);
            return 1;
        }

        SSL_set_fd(tlsSock, startSock);

        if (SSL_connect(tlsSock) <= 0)
        {
            ERR_print_errors_fp(stderr);
            raise(SIGINT);
        }
    }

    char initbuf[200] = {0};
    ssize_t initbytes = SSL_read(tlsSock, initbuf, sizeof(initbuf) - 1);
    initbuf[initbytes] = '\0';
    std::string initMsg(initbuf);
    // get message to see if you are rate limited or the server is full

    if (initMsg.length() > 10 && initMsg.substr(initMsg.length() - 11, initMsg.length()) == "RATELIMITED")
    {
        std::cout << dec.Base64Decode(initMsg.substr(0, initMsg.length() - 11)) << std::endl;
        raise(SIGINT);
    }
    else if (initMsg.length() > 10 && initMsg.substr(initMsg.length() - 3, initMsg.length()) == "LIM")
    {
        std::cout << dec.Base64Decode(initMsg.substr(0, initMsg.length() - 3)) << std::endl;
        raise(SIGINT);
    }

    std::cout << fmt::format("Found connection to server on port {}", PORT) << std::endl;

    SSL_write(tlsSock, connectionSignal, strlen(connectionSignal));

    char ratelimbuf[200] = {0};
    ssize_t rateb = SSL_read(tlsSock, ratelimbuf, sizeof(ratelimbuf) - 1);
    ratelimbuf[rateb] = '\0';
    std::string rateB(ratelimbuf); // double check to see if your rate limited or joining past the limit

    if (rateB.size() > 10 && rateB.substr(rateB.length() - 11, rateB.length()) == "RATELIMITED")
    {
        std::cout << dec.Base64Decode(rateB.substr(0, rateB.length() - 11)) << std::endl;
        raise(SIGINT);
    }
    else if (rateB.size() > 10 && rateB.substr(rateB.length() - 3, rateB.length()) == "LIM")
    {
        std::cout << dec.Base64Decode(rateB.substr(0, rateB.length() - 3)) << std::endl;
        raise(SIGINT);
    }

    char requestBuf[200] = {0};
    ssize_t requestBytes = SSL_read(tlsSock, requestBuf, sizeof(requestBuf) - 1);
    requestBuf[requestBytes] = '\0';
    std::string requestNeeded(requestBuf); // double check to see if your rate limited or joining past the limit

    if (requestNeeded.size() > 10 && requestNeeded.substr(requestNeeded.length() - 3, requestNeeded.length()) == "REQ")
    {
        std::cout << dec.Base64Decode(requestNeeded.substr(0, requestNeeded.length() - 3)) << std::endl;
        // raise(SIGINT);
    }

    char accBuff[200] = {0};
    ssize_t accBytes = SSL_read(tlsSock, accBuff, sizeof(accBuff) - 1);
    accBuff[accBytes] = '\0';
    std::string acc(accBuff); // double check to see if your rate limited or joining past the limit

    if (acc.size() > 10 && acc.substr(acc.length() - 3, acc.length()) == "ACC")
    {
        std::cout << dec.Base64Decode(acc.substr(0, acc.length() - 3)) << std::endl;
        // raise(SIGINT);
    }
    else if (acc.size() > 10 && acc.substr(acc.length() - 3, acc.length()) == "DEC")
    {
        std::cout << dec.Base64Decode(acc.substr(0, acc.length() - 3)) << std::endl;
        raise(SIGINT);
    }

    EVP_PKEY *serverPublicKey = load.LoadPubOpenssl(puServer);

    if (serverPublicKey)
    {
        std::cout << "Server's public key has been loaded" << std::endl;
    }
    else
    {
        std::cout << "Cannot load server's public key. Exiting." << std::endl;
        raise(SIGINT);
    }

    char passSignal[200] = {0};
    ssize_t bytesPassSig = SSL_read(tlsSock, passSignal, sizeof(passSignal) - 1);
    passSignal[bytesPassSig] = '\0';
    std::string passSig(passSignal);

    if (passSig.back() == '*')
    {
        passSig.pop_back();
        std::cout << passSig << std::endl;
        raise(SIGINT);
    }

    else if (passSig[0] == '1')
    {
        const std::string serverPassMsg = "This server is password protected. Enter the password to join: ";
        Enc encryptServerPass;
        curs.set_curs_vb();
        curs.set_inp();
        std::string password = getinput_getch(MODE_P, "", getTermSizeCols(), serverPassMsg);
        curs.set_curs_vb(0);
        curs.set_inp(0);
        std::cout << eraseLine;
        std::string encryptedPassword = encryptServerPass.enc(serverPublicKey, password);
        EVP_PKEY_free(serverPublicKey);
        encryptedPassword = encryptServerPass.Base64Encode(encryptedPassword);
        //
        SSL_write(tlsSock, encryptedPassword.c_str(), encryptedPassword.length());
        std::cout << eraseLine;

        if (password != "\u2702")
        {
            std::cout << eraseLine;
            std::cout << "Verifying password.." << std::endl;
        }

        char passOp[200] = {0};
        ssize_t bytesOp = SSL_read(tlsSock, passOp, sizeof(passOp) - 1);
        passOp[bytesOp] = '\0';
        std::string verifyRecv(passOp);

        if (verifyRecv.empty())
        {
            std::cout << "Could not verify password" << std::endl;
            raise(SIGINT);
        }
        else if (verifyRecv.substr(verifyRecv.length() - 2, verifyRecv.length()) == "#V")
        {
            std::cout << verifyRecv.substr(0, verifyRecv.length() - 2) << std::endl;
        }
        else if (verifyRecv.substr(verifyRecv.length() - 2, verifyRecv.length()) == "#N")
        {
            std::cout << verifyRecv.substr(0, verifyRecv.length() - 2) << std::endl;
            leavePattern = 90;
            raise(SIGINT);
        }
    }

    curs.set_curs_vb();
    curs.set_inp();
    std::string user = getinput_getch(MODE_N, "/|\\| ", 12, "Enter a username to go by: ");
    curs.set_curs_vb(0);
    curs.set_inp(0);

    std::cout << eraseLine;
    if (user != "\u2702")
    {
        std::cout << "Username: " << boldMode << user << boldModeReset << std::endl;
        if (user.empty() || user.length() > 12 || user.length() <= 3)
        { // set these on top
            disable_conio_mode();
            std::cout << "Invalid username. Disconnecting from server\n";
            raise(SIGINT);
        }
    }

    SSL_write(tlsSock, user.c_str(), sizeof(user));

    char usernameBuffer[200] = {0};
    ssize_t bytesReceived = SSL_read(tlsSock, usernameBuffer, sizeof(usernameBuffer) - 1);
    usernameBuffer[bytesReceived] = '\0';
    std::string userStr(usernameBuffer);

    if (userStr.substr(userStr.length() - 2, userStr.length()) == "#V")
    {
        std::cout << userStr.substr(0, userStr.length() - 2) << std::endl;
        exit(1);
    }
    else if (userStr.back() == '@')
    {
        std::cout << userStr.substr(0, userStr.length() - 1) << std::endl;
        raise(SIGINT);
    }

    clsock.push_back(startSock);

    prkey = load.LoadPrvOpenssl(pr);
    EVP_PKEY *pubkey = load.LoadPubOpenssl(pu);

    if (!prkey)
    {
        std::cout << "Your private key cannot be loaded. Exiting." << std::endl;
        raise(SIGINT);
    }
    else if (!pubkey)
    {
        std::cout << "Your public key cannot be loaded. Exiting." << std::endl;
        raise(SIGINT);
    }
    else
    {
        EVP_PKEY_free(pubkey);
        std::cout << "Your keys have been loaded" << std::endl;
    }

    std::string encodedData = receive.receiveBase64Data(tlsSock);
    std::string decodedData = receive.base64Decode(encodedData);

    // write data
    std::ofstream activef(usersActivePath);

    if (activef.is_open())
    {
        activef << decodedData;
    }

    std::cout << "Users active file has been written to path: " << usersActivePath << std::endl;

    if (std::filesystem::is_regular_file(pu))
    {
        std::cout << fmt::format("Sending public key ({}) to server", pu) << std::endl;
        std::string fi = receive.read_pem_key(pu);
        // std::string fi = "sometextkjhgdshjkfjhgkld.txt";
        fi = enc.Base64Encode(fi);
        send.sendBase64Data(tlsSock, fi);
        std::cout << "Public key sent to server" << std::endl;
    }

    std::ifstream opent(usersActivePath);
    std::string active;
    int activeInt;

    if (opent.is_open())
    {
        std::getline(opent, active);
        std::istringstream(active) >> activeInt;
    }
    else
    {
        std::cout << "Could not open the usersActive.txt file to read" << std::endl;
        raise(SIGINT);
    }

    if (activeInt == 2)
    {
        char oksigbuf[4096] = {0};
        ssize_t bytes = SSL_read(tlsSock, oksigbuf, sizeof(oksigbuf));
        oksigbuf[bytes] = '\0';
        std::string okaysignalornot(oksigbuf);

        if (okaysignalornot.substr(okaysignalornot.length() - 5, okaysignalornot.length()) == "MSGNO")
        {
            std::cout << dec.Base64Decode(okaysignalornot.substr(0, okaysignalornot.length() - 5)) << std::endl;
            raise(SIGINT);
        }
        else if (okaysignalornot.substr(okaysignalornot.length() - 9, okaysignalornot.length()) == "EXISTERR")
        {
            std::cout << dec.Base64Decode(okaysignalornot.substr(0, okaysignalornot.length() - 9)) << std::endl;
            raise(SIGINT);
        }

        char name[4096] = {0};
        ssize_t bt = SSL_read(tlsSock, name, sizeof(name));
        name[bt] = '\0';
        std::string pub(name);

        int indexInt = pub.find_first_of("/") + 1;
        pub = pub.substr(indexInt);
        pub = pub.insert(0, fp, 0, fp.length());
        int firstPipe = pub.find_last_of("/");
        int secondPipe = pub.find_last_of("-");
        std::string pubUser = pub.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);

        std::cout << fmt::format("Recieving {}'s public key", pubUser) << std::endl;
        std::string ec = receive.receiveBase64Data(tlsSock);
        std::string dc = receive.base64Decode(ec);
        receive.saveFilePem(pub, dc);

        if (std::filesystem::is_regular_file(pub))
        {
            std::cout << fmt::format("Recieved {}'s pub key", pubUser) << std::endl;
        }
        else
        {
            std::cout << "Public key file does not exist. Exiting.." << std::endl;
            auto it = std::remove(clsock.begin(), clsock.end(), startSock);
            clsock.erase(it, clsock.end());
            raise(SIGINT);
        }

        std::cout << fmt::format("Attempting to load {}'s public key", pubUser) << std::endl;

        receivedPublicKey = load.LoadPubOpenssl(pub);

        if (receivedPublicKey)
        {
            std::cout << fmt::format("{}'s public key loaded", pubUser) << std::endl;
            if (activeInt > 1)
            {
                std::cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - 1 other user in chat - To quit the chat type '/quit' - \n", userStr, activeInt) << RESET_TEXT;
                leavePattern = 1;
            }
            else
            {
                std::cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - {} users in chat - To quit the chat type '/quit' -\n", userStr, activeInt) << RESET_TEXT;
                leavePattern = 1;
            }
        }
        else
        {

            std::cout << fmt::format("Could not load {}'s public key", pubUser) << std::endl;
            raise(SIGINT);
        }
    }
    else if (activeInt == 1)
    {
        char oksigbuf[4096] = {0};
        ssize_t bytes = SSL_read(tlsSock, oksigbuf, sizeof(oksigbuf));
        oksigbuf[bytes] = '\0';
        std::string okaysignalornot(oksigbuf);

        if (okaysignalornot.substr(okaysignalornot.length() - 5, okaysignalornot.length()) == "MSGNO")
        {
            std::cout << dec.Base64Decode(okaysignalornot.substr(0, okaysignalornot.length() - 5)) << std::endl;
            raise(SIGINT);
        }
        else if (okaysignalornot.substr(okaysignalornot.length() - 9, okaysignalornot.length()) == "EXISTERR")
        {
            std::cout << dec.Base64Decode(okaysignalornot.substr(0, okaysignalornot.length() - 9)) << std::endl;
            raise(SIGINT);
        }

        std::cout << "You have connected to an empty chat. Waiting for another user to connect to start the chat" << std::endl;
        leavePattern = 0;

        while (true)
        {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            activeInt = readActiveUsers(usersActivePath);
            if (activeInt > 1)
            {
                break;
            }
        }

        std::cout << "Another user connected, starting chat.." << std::endl;

        // fix bug happening here----------------
        char sec[4096] = {0};
        ssize_t btSec = SSL_read(tlsSock, sec, sizeof(sec));
        sec[btSec] = '\0';
        std::string secKey(sec); // make this for the path receiving

        std::cout << "seckey: " << secKey << std::endl;

        int firstPipe;
        int secondPipe;
        std::string pubUser;

        // if (secKey.length() > 50)
        // {
        //     std::string s2find = ".pem";
        //     int found = secKey.find(".pem") + s2find.length();
        //     std::cout << "found is: " << found << std::endl;
        //     if (found != std::string::npos)
        //     {
        //         std::string encodedKey = secKey.substr(found);
        //         std::cout << "encoded key: " << encodedKey << std::endl;
        //         secKey = secKey.substr(0, found);
        //         std::cout << "secKey substringed: " << secKey << std::endl;
        //         firstPipe = secKey.find_last_of("/");
        //         secondPipe = secKey.find_last_of("-");
        //         pubUser = secKey.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
        //         std::cout << "pubuser: " << pubUser << std::endl;
        //         std::cout << fmt::format("Recieving {}'s public key", pubUser) << std::endl;
        //         std::string decodedData2 = receive.base64Decode(encodedKey);
        //         receive.saveFilePem(secKey, decodedData2);
        //     }
        //     else
        //     {
        //         std::cout << "Couldnt format sec key" << std::endl;
        //         raise(SIGINT);
        //     }
        // }

        // else if (secKey.length() < 50)
        // {
        std::cout << "else secKey: " << secKey << std::endl;
        firstPipe = secKey.find_last_of("/");
        std::cout << "else secKey: " << secKey << std::endl;
        secondPipe = secKey.find_last_of("-");
        pubUser = secKey.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
        std::cout << "else pubuser: " << pubUser << std::endl;

        std::cout << fmt::format("Recieving {}'s public key", pubUser) << std::endl;
        std::string encodedData2 = receive.receiveBase64Data(tlsSock);
        std::cout << "encoded data: " << encodedData2 << std::endl;
        std::string decodedData2 = receive.base64Decode(encodedData2);
        std::cout << "decoded data: " << decodedData2 << std::endl;
        receive.saveFilePem(secKey, decodedData2);
        // }

        if (std::filesystem::is_regular_file(secKey))
        {
            std::cout << fmt::format("Recieved {}'s pub key", pubUser) << std::endl;
        }
        else
        {
            std::cout << fmt::format("{}'s public key file does not exist", pubUser) << std::endl;
            exit(1);
            std::cout << "You have been disconnected due to not being able to encrypt messages due to public key not being found." << std::endl;
            raise(SIGINT);
        }

        std::cout << fmt::format("Attempting to load {}'s public key", pubUser) << std::endl;
        receivedPublicKey = load.LoadPubOpenssl(secKey);

        if (receivedPublicKey)
        {
            std::cout << fmt::format("{}'s public key loaded", pubUser) << std::endl;
            if (activeInt > 1)
            {
                std::cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - 1 other user in chat - To quit the chat type '/quit' -\n", userStr, activeInt) << RESET_TEXT;
                leavePattern = 1;
            }
            else
            {
                std::cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - {} users in chat - To quit the chat type '/quit' -\n", userStr, activeInt) << RESET_TEXT;
                leavePattern = 1;
            }
        }
        else
        {
            std::cout << fmt::format("Could not load {}'s public key", pubUser) << std::endl;
            raise(SIGINT);
        }
    }

    std::thread receiver(receiveMessages, tlsSock, prkey);
    receiver.detach();

    std::string message;

    curs.set_curs_vb();
    curs.set_inp();

    while (true)
    {
        message = getinput_getch(MODE_N, "", getTermSizeCols());
        std::cout << std::endl;
        std::cout << "\033[A";
        std::cout << "\r";
        std::cout << "\033[K";
        if (t_w(message) == "/quit")
        {
            raise(SIGINT);
        }
        else if (message.empty())
        { // skips empty message
            continue;
        }
        message = t_w(message);

        Enc cipher64;

        std::string cipherText = cipher64.enc(receivedPublicKey, message);
        std::string newenc = cipher64.Base64Encode(cipherText);

        SSL_write(tlsSock, newenc.c_str(), newenc.length());

        std::string stringFormatTime = getTime();

        if (message != "\u2702")
        {
            std::cout << GREEN_TEXT << fmt::format("{}(You): {}", userStr, message) << RESET_TEXT << fmt::format("\t\t\t\t{}", stringFormatTime);
        }
        else
        {
            std::cout << eraseLine;
        }
    }

    return 0;
}
