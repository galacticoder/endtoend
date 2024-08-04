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
#include <cryptopp/base64.h>
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
#define S_KEYS "server-keys/"
#define usersActivePath "txt-files/usersActive.txt"

int startSock;
short leavePattern;
short checkExitMsg = 0;
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
    auto now = chrono::system_clock::now();
    time_t currentTime = chrono::system_clock::to_time_t(now);
    tm *localTime = localtime(&currentTime);

    bool isPM = localTime->tm_hour >= 12;
    string stringFormatTime = asctime(localTime);

    int tHour = (localTime->tm_hour > 12) ? (localTime->tm_hour - 12) : ((localTime->tm_hour == 0) ? 12 : localTime->tm_hour);

    stringstream ss;
    ss << tHour << ":" << (localTime->tm_min < 10 ? "0" : "") << localTime->tm_min << " " << (isPM ? "PM" : "AM");
    string formattedTime = ss.str();

    regex time_pattern(R"(\b\d{2}:\d{2}:\d{2}\b)");
    smatch match;

    if (regex_search(stringFormatTime, match, time_pattern))
    {
        string str = match.str(0);
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
            string receivedMessage(buffer);
            string decodedMessage;

            if (receivedMessage.substr(receivedMessage.length() - 2, receivedMessage.length()) == "#N") // not verified message
            {
                leavePattern = 90;
                Dec decNV;
                receivedMessage = receivedMessage.substr(0, receivedMessage.length() - 2);
                decNV.Base64Decode(receivedMessage);
                try
                {
                    string decNVS = decrypt.dec(privateKey, decodedMessage);
                    disable_conio_mode();
                    cout << decNVS << endl;
                    raise(SIGINT);
                }
                catch (const CryptoPP::Exception &e)
                {
                    raise(SIGINT);
                }
            }

            else if (receivedMessage.find('|') == string::npos)
            {
                decodedMessage = decoding.Base64Decode(receivedMessage);
                try
                {
                    std::string decryptedMessage = decrypt.dec(privateKey, decodedMessage);
                    passval(decryptedMessage);
                    checkExitMsg = 1;
                }
                catch (const exception &e)
                {
                }
            }

            if (bytesReceived < 500)
            {
                if (receivedMessage.find('|') == string::npos)
                {
                    disable_conio_mode();
                    cout << receivedMessage << endl;
                    enable_conio_mode();
                    continue;
                }
            }

            int firstPipe = receivedMessage.find_first_of("|");
            int secondPipe = receivedMessage.find_last_of("|");
            string cipher = receivedMessage.substr(secondPipe + 1);
            string time = receivedMessage.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
            string user = receivedMessage.substr(0, firstPipe);
            decodedMessage = decoding.Base64Decode(cipher);

            try
            {
                if (receivedMessage.find('|') != string::npos) // for messages from client
                {
                    disable_conio_mode();
                    string decryptedMessage = decrypt.dec(privateKey, decodedMessage);
                    cout << fmt::format("{}: {}\t\t\t\t{}", user, decryptedMessage, time);
                }
                enable_conio_mode();
            }
            catch (const exception &e)
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
    const string portPath = "txt-files/PORT.txt";
    ifstream file(portPath);
    string PORTSTR;
    getline(file, PORTSTR);
    int PORT;
    istringstream(PORTSTR) >> PORT;

    std::string pu = fmt::format("{}{}-pubkey.pem", fpath, "mykey");
    std::string puServer = fmt::format("{}{}-pubkey.pem", formatPath, "server");
    std::string cert = fmt::format("{}server-cert.pem", formatPath);
    std::string pr = fmt::format("{}{}-privkey.pem", fpath, "mykey");

    { // initialize open tlsSock and create ctx
        std::cout << "Initializing OpenSSL" << std::endl;
        initializeTls.InitOpenssl();
        std::cout << "OpenSSL initialized" << std::endl;

        cout << "Creating ctx" << endl;
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        pubclctx = ctx;
        cout << "Ctx Created" << endl;
    }

    { // generate your keys
        cout << "Generating keys" << endl;
        KeysMake genKeys(pr, pu);
        cout << "Keys have been generated" << endl;
    }

    { // get server cert and exetract public key
        const std::string get = fmt::format("http://{}:{}/", serverIp, 85);
        std::cout << fmt::format("Fetching server cert file from: {}", get) << std::endl;
        fetchAndSave(get, cert);
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
            cout << "Invalid address / Address not supported\n";
            raise(SIGINT);
        }

        if (connect(startSock, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
        {
            cout << "Cannot connect to server\n";
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
    string initMsg(initbuf);
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

    cout << fmt::format("Found connection to server on port {}", PORT) << endl;

    SSL_write(tlsSock, connectionSignal, strlen(connectionSignal));

    char ratelimbuf[200] = {0};
    ssize_t rateb = SSL_read(tlsSock, ratelimbuf, sizeof(ratelimbuf) - 1);
    ratelimbuf[rateb] = '\0';
    string rateB(ratelimbuf); // double check to see if your rate limited or joining past the limit

    if (rateB.substr(rateB.length() - 11, rateB.length()) == "RATELIMITED")
    {
        std::cout << dec.Base64Decode(rateB.substr(0, rateB.length() - 11)) << std::endl;
        raise(SIGINT);
    }
    else if (rateB.substr(rateB.length() - 3, rateB.length()) == "LIM")
    {
        std::cout << dec.Base64Decode(rateB.substr(0, rateB.length() - 3)) << std::endl;
        raise(SIGINT);
    }

    EVP_PKEY *serverPublicKey = load.LoadPubOpenssl(puServer);

    if (serverPublicKey)
    {
        cout << "Server's public key has been loaded" << endl;
    }
    else
    {
        cout << "Cannot load server's public key. Exiting." << endl;
        raise(SIGINT);
    }

    char passSignal[200] = {0};
    ssize_t bytesPassSig = SSL_read(tlsSock, passSignal, sizeof(passSignal) - 1);
    passSignal[bytesPassSig] = '\0';
    string passSig(passSignal);

    const string serverPassMsg = "This server is password protected. Enter the password to join";

    if (passSig.back() == '*')
    {
        passSig.pop_back();
        cout << passSig << endl;
        raise(SIGINT);
    }

    else if (passSig[0] == '1')
    {
        Enc encryptServerPass;
        cout << serverPassMsg << endl;
        curs.set_curs_vb();
        curs.set_inp();
        string password = getinput_getch(MODE_P, "", getTermSizeCols());
        curs.set_curs_vb(0);
        curs.set_inp(0);
        cout << eraseLine;
        string encryptedPassword = encryptServerPass.enc(serverPublicKey, password);
        EVP_PKEY_free(serverPublicKey);
        encryptedPassword = encryptServerPass.Base64Encode(encryptedPassword);

        SSL_write(tlsSock, encryptedPassword.c_str(), encryptedPassword.length());
        cout << eraseLine;

        if (password != "\u2702")
        {
            cout << eraseLine;
            cout << "Verifying password.." << endl;
        }

        char passOp[200] = {0};
        ssize_t bytesOp = SSL_read(tlsSock, passOp, sizeof(passOp) - 1);
        passOp[bytesOp] = '\0';
        string verifyRecv(passOp);

        if (verifyRecv.empty())
        {
            cout << "Could not verify password" << endl;
            raise(SIGINT);
        }
        else if (verifyRecv.substr(verifyRecv.length() - 2, verifyRecv.length()) == "#V")
        {
            cout << verifyRecv.substr(0, verifyRecv.length() - 2) << endl;
        }
        else if (verifyRecv.substr(verifyRecv.length() - 2, verifyRecv.length()) == "#N")
        {
            cout << verifyRecv.substr(0, verifyRecv.length() - 2) << endl;
            leavePattern = 90;
            raise(SIGINT);
        }
    }

    std::cout << "Enter a username to go by" << std::endl;

    curs.set_curs_vb();
    curs.set_inp();
    std::string user = getinput_getch(MODE_N, "/|\\| ", 12);
    curs.set_curs_vb(0);
    curs.set_inp(0);

    std::cout << eraseLine;
    if (user != "\u2702")
    {
        std::cout << "Username: " << boldMode << user << boldModeReset << std::endl;
        if (user.empty() || user.length() > 12 || user.length() <= 3)
        { // set these on top
            disable_conio_mode();
            cout << "Invalid username. Disconnecting from server\n";
            raise(SIGINT);
        }
    }

    SSL_write(tlsSock, user.c_str(), sizeof(user));

    char usernameBuffer[200] = {0};
    ssize_t bytesReceived = SSL_read(tlsSock, usernameBuffer, sizeof(usernameBuffer) - 1);
    usernameBuffer[bytesReceived] = '\0';
    string userStr(usernameBuffer);

    if (userStr.substr(userStr.length() - 2, userStr.length()) == "#V")
    {
        cout << userStr.substr(0, userStr.length() - 2) << endl;
        exit(1);
    }
    else if (userStr.back() == '@')
    {
        cout << userStr.substr(0, userStr.length() - 1) << endl;
        raise(SIGINT);
    }

    clsock.push_back(startSock);

    prkey = load.LoadPrvOpenssl(pr);
    EVP_PKEY *pubkey = load.LoadPubOpenssl(pu);

    if (!prkey)
    {
        cout << "Your private key cannot be loaded. Exiting." << endl;
        raise(SIGINT);
    }
    else if (!pubkey)
    {
        cout << "Your public key cannot be loaded. Exiting." << endl;
        raise(SIGINT);
    }
    else
    {
        EVP_PKEY_free(pubkey);
        cout << "Your keys have been loaded" << endl;
    }

    string encodedData = receive.receiveBase64Data(tlsSock);
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
        std::string fi = receive.read_pem_key(pu);
        cout << fmt::format("Sending public key ({}) to server", pu) << std::endl;
        fi = enc.Base64Encode(fi);
        send.sendBase64Data(tlsSock, fi);
        std::cout << "Public key sent to server" << std::endl;
    }

    ifstream opent(usersActivePath);
    string active;
    int activeInt;

    if (opent.is_open())
    {
        getline(opent, active);
        istringstream(active) >> activeInt;
    }
    else
    {
        cout << "Could not open the usersActive.txt file to read" << endl;
        auto it = std::remove(clsock.begin(), clsock.end(), startSock);
        clsock.erase(it, clsock.end());
        raise(SIGINT);
    }

    if (activeInt == 2)
    {
        char name[4096] = {0};
        ssize_t bt = SSL_read(tlsSock, name, sizeof(name));
        name[bt] = '\0';
        string pub(name);

        int indexInt = pub.find_first_of("/") + 1;
        pub = pub.substr(indexInt);
        pub = pub.insert(0, fp, 0, fp.length());
        int firstPipe = pub.find_last_of("/");
        int secondPipe = pub.find_last_of("-");
        std::string pubUser = pub.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);

        cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
        std::string ec = receive.receiveBase64Data(tlsSock);
        std::string dc = receive.base64Decode(ec);
        receive.saveFilePem(pub, dc);

        if (std::filesystem::is_regular_file(pub))
        {
            cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
        }
        else
        {
            cout << "Public key file does not exist. Exiting.." << endl;
            auto it = std::remove(clsock.begin(), clsock.end(), startSock);
            clsock.erase(it, clsock.end());
            raise(SIGINT);
        }

        cout << fmt::format("Attempting to load {}'s public key", pubUser) << endl;

        receivedPublicKey = load.LoadPubOpenssl(pub);

        if (receivedPublicKey)
        {
            cout << fmt::format("{}'s public key loaded", pubUser) << endl;
            if (activeInt > 1)
            {
                cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - 1 other user in chat - To quit the chat type '/quit' - \n", userStr, activeInt) << RESET_TEXT;
                leavePattern = 1;
            }
            else
            {
                cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - {} users in chat - To quit the chat type '/quit' -\n", userStr, activeInt) << RESET_TEXT;
                leavePattern = 1;
            }
        }
        else
        {

            cout << fmt::format("Could not load {}'s public key", pubUser) << endl;
            raise(SIGINT);
        }
    }
    else if (activeInt == 1)
    {
        cout << "You have connected to an empty chat. Waiting for another user to connect to start the chat" << endl;
        leavePattern = 0;
        termcmd termcmdProgress;
        int *ac = &activeInt;

        while (true)
        {
            this_thread::sleep_for(chrono::seconds(2));
            activeInt = readActiveUsers(usersActivePath);
            if (activeInt > 1)
            {
                break;
            }
        }

        std::cout << "Another user connected, starting chat.." << std::endl;
        char sec[4096] = {0};
        ssize_t btSec = SSL_read(tlsSock, sec, sizeof(sec));
        sec[btSec] = '\0';
        std::string secKey(sec);

        int firstPipe;
        int secondPipe;
        std::string pubUser;

        if (secKey.length() > 50)
        {
            static string s2find = ".pem";
            int found = secKey.find(".pem") + s2find.length();
            if (found != string::npos)
            {
                string encodedKey = secKey.substr(found);
                secKey = secKey.substr(0, found);
                firstPipe = secKey.find_last_of("/");
                secondPipe = secKey.find_last_of("-");
                pubUser = secKey.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
                cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
                std::string decodedData2 = receive.base64Decode(encodedKey);
                receive.saveFilePem(secKey, decodedData2);
            }
            else
            {
                cout << "Couldnt format sec key" << endl;
                auto it = std::remove(clsock.begin(), clsock.end(), startSock);
                clsock.erase(it, clsock.end());
                raise(SIGINT);
            }
        }

        else if (secKey.length() < 50)
        {
            firstPipe = secKey.find_last_of("/");
            secondPipe = secKey.find_last_of("-");
            pubUser = secKey.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);

            if (secKey.length() < 50)
            {
                cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
                string encodedData2 = receive.receiveBase64Data(tlsSock);
                std::string decodedData2 = receive.base64Decode(encodedData2);
                receive.saveFilePem(secKey, decodedData2);
            }
        }

        if (std::filesystem::is_regular_file(secKey))
        {
            cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
        }
        else
        {
            cout << fmt::format("{}'s public key file does not exist", pubUser) << endl;
            cout << "You have been disconnected due to not being able to encrypt messages due to public key not being found." << endl;
            raise(SIGINT);
        }

        cout << fmt::format("Attempting to load {}'s public key", pubUser) << endl;
        receivedPublicKey = load.LoadPubOpenssl(secKey);

        if (receivedPublicKey)
        {
            cout << fmt::format("{}'s public key loaded", pubUser) << endl;
            if (activeInt > 1)
            {
                cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - 1 other user in chat - To quit the chat type '/quit' -\n", userStr, activeInt) << RESET_TEXT;
                leavePattern = 1;
            }
            else
            {
                cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - {} users in chat - To quit the chat type '/quit' -\n", userStr, activeInt) << RESET_TEXT;
                leavePattern = 1;
            }
        }
        else
        {
            cout << fmt::format("Could not load {}'s public key", pubUser) << endl;
            raise(SIGINT);
        }
    }

    thread receiver(receiveMessages, tlsSock, prkey);
    receiver.detach();

    string message;

    curs.set_curs_vb();
    curs.set_inp();

    while (true)
    {
        message = getinput_getch(MODE_N, "", getTermSizeCols());
        cout << endl;
        cout << "\033[A";
        cout << "\r";
        cout << "\033[K";
        if (t_w(message) == "/quit")
        {
            cout << "You have left the chat\n";
            auto it = std::remove(clsock.begin(), clsock.end(), startSock);
            clsock.erase(it, clsock.end());
            raise(SIGINT);
        }
        else if (message.empty())
        { // skips empty message
            continue;
        }
        message = t_w(message);

        Enc cipher64;

        string cipherText = cipher64.enc(receivedPublicKey, message);
        string newenc = cipher64.Base64Encode(cipherText);

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
