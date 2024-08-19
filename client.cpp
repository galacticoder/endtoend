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
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <cstdlib>
#include <termios.h>
#include <regex>
#include <filesystem>
#include <bits/stdc++.h>
#include <csignal>
#include <vector>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <mutex>
#include <ncurses.h>
#include <openssl/evp.h>
#include "headers/header-files/encry.h"
#include "headers/header-files/linux_conio.h"
// #include "headers/header-files/getch_getline_cl.h"
#include "headers/header-files/fileAndDirHandler.h"
#include "headers/header-files/leave.h"
// #include "headers/header-files/linux_conio.h"
// #include "headers/header-files/termCmds.h"
#include "headers/header-files/fetchHttp.h"

#define GREEN_TEXT "\033[32m" // green text color
#define RESET_TEXT "\033[0m"  // reset color to default
#define connectionSignal "C"
#define S_KEYS "server-keys/"
#define usersActivePath "txt-files/usersActive.txt"
// #define S_PATH "server-recieved-client-keys"
#define formatPath "keys-from-server/"
#define fpath "your-keys/"
// #define PING_BYTE 0x01

int startSock;
long int track = 0;
short leavePattern;
std::vector<int> clsock;
// std::vector<std::string> usersActiveVector;
SSL *tlsSock;
SSL_CTX *pubclctx;
EVP_PKEY *receivedPublicKey;
EVP_PKEY *prkey;
std::mutex mut;
std::mutex openssl_mutex;
std::atomic<bool> pingingrunning{true};

WINDOW *subaddr;
WINDOW *inputaddr;
WINDOW *viewaddr;

// int heightGlobal = LINES;
// int widthGlobal = COLS;

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

void cleanWins()
{
    std::cout << "here" << std::endl;
    if (subaddr)
    {
        std::cout << "trying Del subaddr" << std::endl;
        delwin(subaddr);
        std::cout << "Del subaddr" << std::endl;
    }
    if (inputaddr)
    {
        std::cout << "trying Del inputaddr" << std::endl;
        delwin(inputaddr);
        std::cout << "Del inputaddr" << std::endl;
    }
    if (viewaddr)
    {
        std::cout << "trying viewaddr" << std::endl;
        delwin(viewaddr);
        std::cout << "Del viewaddr" << std::endl;
    }
    curs_set(1);
    endwin();
    std::cout << "done" << std::endl;
}

void cleanUpOpenssl()
{
    std::lock_guard<std::mutex> lock(openssl_mutex); // Lock the mutex
    // std::lock_guard<std::mutex> lock(mut);
    std::cout << "clean ssl" << std::endl;
    std::cout << "prkey test to see if seg fault happens from it: " << prkey << std::endl;
    if (tlsSock)
    {
        std::cout << "cleaning sock ssl" << std::endl;
        SSL_shutdown(tlsSock);
        SSL_free(tlsSock);
        tlsSock = nullptr;
        std::cout << "done sock" << std::endl;
    }
    if (startSock)
    {
        std::cout << "closing sock" << std::endl;
        close(startSock);
        startSock = 0;
        std::cout << "closed sock" << std::endl;
    }
    if (receivedPublicKey)
    {
        std::cout << "freeing rcpk" << std::endl;
        EVP_PKEY_free(receivedPublicKey);
        receivedPublicKey = nullptr;
        std::cout << "freed" << std::endl;
    }

    if (prkey)
    {
        std::cout << "freeing prkey" << std::endl;
        EVP_PKEY_free(prkey);
        prkey = nullptr;
        std::cout << "freed prkey" << std::endl;
    }

    if (pubclctx)
    {
        std::cout << "freeing ctx" << std::endl;
        SSL_CTX_free(pubclctx);
        pubclctx = nullptr;
        std::cout << "freed ctx" << std::endl;
    }
    std::cout << "done" << std::endl;

    EVP_cleanup();
}

void signalhandle(int signum)
{
    {
        std::lock_guard<std::mutex> lock(mut);
        pingingrunning = false;
    }
    { // clean up memory used
        std::cout << "starting clean of ncurses" << std::endl;
        cleanWins();
        std::cout << "clean of ncurses done" << std::endl;
        std::cout << "starting clean of openssl" << std::endl;
        cleanUpOpenssl();
        std::cout << "clean of openssl done" << std::endl;
    }

    if (leavePattern == 0)
    {
        std::cout << "You have disconnected from the empty chat." << std::endl;
    }
    else if (leavePattern == 1)
    {
        std::cout << "You have left the chat" << std::endl;
    }

    // clean up
    { // del files and dir
        leave();
        leaveFile(usersActivePath);
    }
    // std::cout << "\n";
    std::cout << eraseLine;
    exit(signum);
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

void receiveMessages(SSL *tlsSock, WINDOW *subwin)
{
    Recieve receive;
    LoadKey load;
    char buffer[4096];
    while (true)
    {
        ssize_t bytesReceived = SSL_read(tlsSock, buffer, sizeof(buffer) - 1);
        if (bytesReceived > 0)
        {
            track++;
            Dec decrypt;
            buffer[bytesReceived] = '\0';
            std::string receivedMessage(buffer);
            std::string decodedMessage;

            if (receivedMessage.substr(receivedMessage.length() - 2, receivedMessage.length()) == "#N") // not verified message
            {
                leavePattern = 90;
                receivedMessage = receivedMessage.substr(0, receivedMessage.length() - 2);
                decrypt.Base64Decode(receivedMessage);
                try
                {
                    std::string decNVS = decrypt.dec(prkey, decodedMessage);
                    curs_set(0);

                    wmove(subwin, track, 0);
                    decNVS += "\n";
                    wprintw(subwin, decNVS.c_str(), track);
                    wrefresh(subwin);
                    curs_set(1);
                }
                catch (const std::exception &e)
                {
                    raise(SIGINT);
                }
            }

            else if (receivedMessage.substr(receivedMessage.length() - 3, receivedMessage.length()) == "PSE")
            {
                char sec2Buff[4096] = {0};
                ssize_t btcl2 = SSL_read(tlsSock, sec2Buff, sizeof(sec2Buff));
                sec2Buff[btcl2] = '\0';
                std::string cl2recv(sec2Buff); // for file path to save to and extract username from

                int firstPipe;
                int secondPipe;
                std::string pubUser;

                firstPipe = cl2recv.find_last_of("/");
                secondPipe = cl2recv.find_last_of("-");
                pubUser = cl2recv.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);

                // std::cout << fmt::format("Recieving {}'s public key", pubUser) << std::endl;
                std::string encodedData2 = receive.receiveBase64Data(tlsSock);
                std::string decodedData2 = receive.base64Decode(encodedData2);
                receive.saveFilePem(cl2recv, decodedData2);

                // std::cout << fmt::format("Attempting to load {}'s public key", pubUser) << std::endl;
                receivedPublicKey = load.LoadPubOpenssl(cl2recv, 0);

                if (!receivedPublicKey)
                {
                    // std::cout << fmt::format("{}'s public key cannot be loaded", pubUser) << std::endl;
                    raise(SIGINT);
                }
            }

            else if (receivedMessage.find('|') == std::string::npos)
            {
                decodedMessage = decrypt.Base64Decode(receivedMessage);
                try
                {
                    std::string decryptedMessage = decrypt.dec(prkey, decodedMessage);
                    curs_set(0);

                    wmove(subwin, track, 0);
                    decryptedMessage += "\n";
                    wprintw(subwin, decryptedMessage.c_str(), track);
                    wrefresh(subwin);

                    curs_set(1);
                }
                catch (const std::exception &e)
                {
                    continue;
                }
            }

            if (bytesReceived < 500)
            {
                if (receivedMessage.find('|') == std::string::npos && receivedMessage.substr(receivedMessage.length() - 3, receivedMessage.length()) != "PSE")
                {
                    try
                    {
                        curs_set(0);

                        std::string decryptedDec = decrypt.Base64Decode(decrypt.dec(prkey, receivedMessage));

                        wmove(subwin, track, 0);
                        decryptedDec += "\n";
                        wprintw(subwin, decryptedDec.c_str(), track);
                        wrefresh(subwin);

                        curs_set(1);
                        // track++;
                        // resetPos(subwin);

                        continue;
                    }
                    catch (const std::exception &e)
                    {
                        continue;
                    }
                }
            }

            int firstPipe = receivedMessage.find_first_of("|");
            int secondPipe = receivedMessage.find_last_of("|");
            std::string cipher = receivedMessage.substr(secondPipe + 1);
            std::string time = receivedMessage.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
            std::string user = receivedMessage.substr(0, firstPipe);
            decodedMessage = decrypt.Base64Decode(cipher);

            try
            {
                if (receivedMessage.find('|') != std::string::npos) // for messages from client
                {
                    std::string decryptedMessage = decrypt.dec(prkey, decodedMessage);
                    std::string passmsg = fmt::format("{}: {}", user, decryptedMessage);
                    curs_set(0);

                    wmove(subwin, track, 0);
                    passmsg += "\n";
                    wprintw(subwin, passmsg.c_str(), track);
                    wrefresh(subwin);

                    curs_set(1);
                }
            }
            catch (const std::exception &e)
            {
                continue;
            }
        }
    }
}

void handleResize()
{
    int y, x;
    getmaxyx(stdscr, y, x);

    wresize(viewaddr, y - 3, x);
    wresize(inputaddr, 3, x);
    mvwin(inputaddr, y - 3, 0);

    werase(viewaddr);
    werase(inputaddr);
    wrefresh(viewaddr);
    wrefresh(inputaddr);

    refresh();
    doupdate();
}

void typing(const std::string &userStr)
{
    std::string message;

    Enc cipher64;
    int ch;

    while (true)
    {
        ch = wgetch(inputaddr);
        if (ch == 13)
        {
            if (t_w(message) == "/quit")
            {
                // cleanWins();
                raise(SIGINT);
            }
            else if (!message.empty() && t_w(message) != "/quit")
            {
                // check if message is length and if it reaches the width of the subwin if so track++
                track++;
                curs_set(0);

                wmove(subaddr, track, 0);

                message += "\n";
                // send msg
                std::string stringFormatTime = getTime();
                // print the time later
                std::string form = fmt::format("{}(You): {}", userStr, message);
                message = t_w(message);
                std::string cipherText = cipher64.enc(receivedPublicKey, message);
                std::string newenc = cipher64.Base64Encode(cipherText);
                SSL_write(tlsSock, newenc.c_str(), newenc.length());
                //-----------------
                wprintw(subaddr, form.c_str(), track);
                wrefresh(subaddr);
                // print time
                // wmove(subwin, track, width - 5 - stringFormatTime.length());
                // wprintw(subwin, stringFormatTime.c_str(), track);

                wclear(inputaddr);
                box(inputaddr, 0, 0);
                wrefresh(inputaddr);
                message.clear();
                wmove(inputaddr, 1, 1);
                curs_set(1);
            }
            else
            {
                continue;
            }
        }
        else if (ch == KEY_RESIZE)
        {
            std::lock_guard<std::mutex> lock(mut);
            handleResize();
        }

        else
        {
            message += ch;
            wprintw(inputaddr, "%c", ch);
            wrefresh(inputaddr);
        }
    }
}
int main()
{
    signal(SIGINT, signalhandle);

    leavePattern = 90;
    char serverIp[30] = "127.0.0.1"; // change to the server i
    const std::string portPath = "txt-files/PORT.txt";
    std::ifstream file(portPath);
    std::string PORTSTR;
    std::getline(file, PORTSTR);
    unsigned int PORT;
    std::istringstream(PORTSTR) >> PORT;

    initOpenSSL initializeTls;
    Enc enc;
    Dec dec;
    LoadKey load;
    Send sendssl;
    Recieve receive;

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

    // while (pingingrunning != false)
    // {
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
            std::cout << "Cannot connect to server. Check server port\n";
            raise(SIGINT);
        }

        send(startSock, connectionSignal, strlen(connectionSignal), 0);

        char oksig[200] = {0};
        ssize_t okbytes = read(startSock, oksig, sizeof(oksig) - 1);
        oksig[okbytes] = '\0';
        std::string okayStr(oksig);

        if (okayStr != "OKAYSIGNAL")
        {
            std::cout << "Server sent unknown signal. Leaving for security." << std::endl;
            raise(SIGINT);
        }

        // std::thread(send_ping, startSock).detach();
    }
    const unsigned int ui = 1;
    std::thread pingingServer(pingServer, serverIp, PORT, std::ref(pingingrunning), ui);
    pingingServer.detach();

    tlsSock = SSL_new(pubclctx);

    { // connect using tlsSock
        if (tlsSock == nullptr)
        {
            std::cerr << "Failed to create tlsSock object\n";
            raise(SIGINT);
        }

        SSL_set_fd(tlsSock, startSock);

        if (SSL_connect(tlsSock) <= 0)
        {
            ERR_print_errors_fp(stderr);
            raise(SIGINT);
        }
    }

    // exit(1);
    char initbuf[200] = {0};
    ssize_t initbytes = SSL_read(tlsSock, initbuf, sizeof(initbuf) - 1);
    initbuf[initbytes] = '\0';
    std::string initMsg(initbuf);
    // get message to see if you are rate limited or the server is full

    // exit(1)
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

    // exit(1);
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

    // std::cout << "here" << std::endl;
    // close(startSock);
    // exit(1);
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
        std::string password; /*= getinput_getch(MODE_P, "", getTermSizeCols(), serverPassMsg, serverIp, PORT);*/
        std::getline(std::cin, password);
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

    std::string user; /* = getinput_getch(MODE_N, "/|\\| ", 12, "Enter a username to go by: ", serverIp, PORT);*/
    // std::getline(std::cin, user);
    std::cin >> user;

    std::cout << eraseLine;
    // if (user != "\u2702")
    // {
    std::cout << "Username: " << user << std::endl;
    if (user.empty() || user.length() > 12 || user.length() <= 3)
    { // set these on top
        // disable_conio_mode();
        std::cout << "Invalid username. Disconnecting from server\n";
        raise(SIGINT);
    }
    // }

    SSL_write(tlsSock, user.c_str(), user.length());

    char usernameBuffer[200] = {0};
    ssize_t bytesReceived = SSL_read(tlsSock, usernameBuffer, sizeof(usernameBuffer) - 1);
    usernameBuffer[bytesReceived] = '\0';
    std::string userStr(usernameBuffer);

    if (userStr.substr(userStr.length() - 2, userStr.length()) == "#V")
    {
        std::cout << userStr.substr(0, userStr.length() - 2) << std::endl;
        // exit(1);
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
        sendssl.sendBase64Data(tlsSock, fi);
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

        // std::cout << "seckey: " << secKey << std::endl;

        int firstPipe;
        int secondPipe;
        std::string pubUser;

        firstPipe = secKey.find_last_of("/");
        secondPipe = secKey.find_last_of("-");
        pubUser = secKey.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);

        std::cout << fmt::format("Recieving {}'s public key", pubUser) << std::endl;
        std::string encodedData2 = receive.receiveBase64Data(tlsSock);
        std::string decodedData2 = receive.base64Decode(encodedData2);
        receive.saveFilePem(secKey, decodedData2);
        // }

        if (std::filesystem::is_regular_file(secKey))
        {
            std::cout << fmt::format("Recieved {}'s pub key", pubUser) << std::endl;
        }
        else
        {
            std::cout << fmt::format("{}'s public key file does not exist", pubUser) << std::endl;
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
                // start chat window here
                std::cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - 1 other user in chat - To quit the chat type '/quit' -\n", userStr, activeInt) << RESET_TEXT;
                leavePattern = 1;
            }
            else
            {
                // start chat window here
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

    // start windows for user msg viewing and inputting
    initscr();
    cbreak();
    nonl();
    noecho();
    keypad(stdscr, TRUE);

    int height = LINES;
    int width = COLS;

    int msg_view_h = height - 3;
    int msg_input_h = 3;

    WINDOW *msg_input_win = newwin(msg_input_h, width, msg_view_h, 0);
    box(msg_input_win, 0, 0);

    WINDOW *msg_view_win = newwin(msg_view_h - 1, width - 2, 1, 1);
    box(msg_view_win, 0, 0);

    wrefresh(msg_view_win);
    wrefresh(msg_input_win);

    mvwprintw(msg_view_win, 0, 4, "Chat");
    wrefresh(msg_view_win);

    WINDOW *subwin = derwin(msg_view_win, height - 6, width - 4, 1, 1);
    scrollok(subwin, TRUE);
    idlok(subwin, TRUE);

    wmove(msg_input_win, 1, 1);

    subaddr = subwin;
    inputaddr = msg_input_win;
    viewaddr = msg_view_win;

    std::thread(receiveMessages, tlsSock, subwin).detach();
    std::thread(typing, std::ref(userStr)).detach();

    while (1)
    {
    }
    //--------------------------

    // }
    // std::cout << "Server has been shutdown" << std::endl;
    raise(SIGINT);
    return 0;
}
