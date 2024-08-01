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
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <netinet/ip_icmp.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <netinet/in.h>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <arpa/inet.h>
#include <boost/asio.hpp>
#include <cstdlib>
#include <termios.h>
#include "headers/header-files/rsa.h"
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/queue.h>
#include <regex>
#include <filesystem>
#include <bits/stdc++.h>
#include <csignal>
#include <vector>
#include <atomic>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "headers/header-files/encry.h"
#include "headers/header-files/getch_getline.h" // including my own getline function i made for better user input allows arrow keys and stuff
#include "headers/header-files/leave.h"
#include "headers/header-files/termCmds.h"
// #include <ncurses.h>

// find a way to send the port file if possible

// try addig file sending whewn the client starts the message off with /sendfile {filepath} and let client 2 get a mesage this user is trying to send you a file would you like to recieve it or not? if not then dont recieve is yes then recieve it also maybe add a file view feature where you can open the file to see whats in it and you can accept the file later on with /acceptfile {thefilename that was given} if no args provided then accept the last file sent

// To run: g++ -o client client.cpp -lcryptopp -lfmt

#define GREEN_TEXT "\033[32m" // green text color
// #define erasebeg "\033[2K\r" //erase from beggining
#define clearsrc "\033[2J\r" // clears screen and return cursor
#define left1 "\033[1D"      // move the cursor back to the left once
#define right1 "\033[1C"     // move the cursor back to the right once
#define RESET_TEXT "\033[0m" // reset color to default
#define xU "\u02DF"
#define connectionSignal "C"

#define S_KEYS "server-keys/"
#define usersActivePath "txt-files/usersActive.txt"

using namespace std;
// using namespace CryptoPP;
using boost::asio::ip::tcp;
using namespace filesystem;

int clsockC = 0;

vector<int> clsock;
vector<std::string> usersActiveVector;
vector<SSL *> tlsSock;
vector<SSL_CTX *> sslStore;
uint8_t leavePattern;
int con = 0;
// bool isPav(const string& address, int port) {
//     try {
//         boost::system::error_code ecCheck;
//         boost::asio::ip::address::from_string(address, ecCheck);
//         if (ecCheck) {
//             cout << "invalid ip address: " << address << endl;
//             // return false;
//         }
//         boost::asio::io_service io_service;
//         tcp::socket socket(io_service);
//         tcp::endpoint endpoint(boost::asio::ip::address::from_string(address), port);
//         socket.connect(endpoint);

//         return true;
//     }
//     catch (const exception& e) {
//         modeP.clear();
//         cout << "Server has been shutdown" << endl;
//         leave();
//         cout << "exception: " << e.what() << endl;
//         return false;
//     }
//     return false; // not reachable
// }

string t_w(string strIp)
{
    strIp.erase(strIp.begin(), find_if(strIp.begin(), strIp.end(), [](unsigned char ch)
                                       { return !isspace(ch); }));
    strIp.erase(find_if(strIp.rbegin(), strIp.rend(), [](unsigned char ch)
                        { return !isspace(ch); })
                    .base(),
                strIp.end());
    return strIp;
}

bool containsOnlyASCII(const string &stringS)
{
    for (auto c : stringS)
    {
        if (static_cast<unsigned char>(c) > 127)
        {
            return false;
        }
    }
    return true;
}

void signalhandle(int signum)
{
    termcmd setdefault;
    setdefault.set_curs_vb();
    setdefault.set_inp();
    if (con == 1)
    {
        int indexClientOut = 0;
        SSL_shutdown(tlsSock[indexClientOut]);
        SSL_free(tlsSock[indexClientOut]);
        close(clsockC);
        SSL_CTX_free(sslStore[0]);
        EVP_cleanup();
        cout << eraseLine;
    }
    if (leavePattern == 0)
    {
        cout << "You have disconnected from the empty chat." << endl;
        leave();
        leaveFile(usersActivePath);
        exit(signum);
    }
    else if (leavePattern == 1)
    {
        cout << "You have left the chat" << endl;
        leave();
        leaveFile(usersActivePath);
        exit(signum);
    }
    else if (leavePattern == 90)
    {
        leave();
        leaveFile(usersActivePath);
        exit(signum);
    }
}

// void readUsersActiveFile(const string usersActivePath, std::atomic<bool>& running, unsigned int update_secs) {
//     const auto wait_duration = chrono::seconds(update_secs);
//     ifstream openFile(usersActivePath);
//     string active;
//     while (true) {
//         try {
//             if (openFile.is_open()) {
//                 getline(openFile, active);
//             }
//             if (active == "2!") {
//                 running = false;
//             }
//             this_thread::sleep_for(wait_duration);
//         }
//         catch (const exception& e) {
//             running = false;
//         }
//     }
// }

void receiveUsersActiveFile(SSL *ssl)
{
    Recieve recieveActiveFile;
    while (true)
    {
        std::string encodedData = recieveActiveFile.receiveBase64Data(ssl);
        std::string decodedData = recieveActiveFile.base64Decode(encodedData);
        recieveActiveFile.saveFile(usersActivePath, decodedData);
    }
}

void receiveMessages(SSL *ssl, EVP_PKEY *privateKey) /*change to the openssl one*/
{

    // check if characters are in encoded version not in actual message and decode from server first to see if decodable and then send it to the client
    char buffer[4096];
    while (true)
    {
        ssize_t bytesReceived = SSL_read(ssl, buffer, sizeof(buffer) - 1);
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

            else if (receivedMessage.find('|') == string::npos) // mainly for messages server related kind of. like users leaving and stuff
            {
                decodedMessage = decoding.Base64Decode(receivedMessage);
                try
                {
                    std::string decryptedMessage = decrypt.dec(privateKey, decodedMessage);
                    passval(decryptedMessage);
                }
                catch (const exception &e)
                {
                }
            }

            if (bytesReceived < 500)
            {
                if (receivedMessage.find('|') == string::npos) // it not found
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

bool createDir(const string &dirName)
{
    if (!create_directories(dirName))
    {
        if (exists(dirName))
        {
            return true;
        }
        else
        {
            cout << fmt::format("Couldnt create directory: {}", dirName) << endl;
            return false;
        }
    }
    return true;
}

void sendPem(const std::string &pempath, BIO *bio)
{
    if (BIO_write(bio, pempath.c_str(), pempath.size()) <= 0)
    {
        std::cout << "Could not send '" << pempath << "' to server" << endl;
        BIO_free_all(bio);
        raise(SIGINT);
    }
    std::cout << fmt::format("File ({}) has been sent to server", pempath) << std::endl;
}

int main()
{
    signal(SIGINT, signalhandle);
    termcmd curs;
    curs.set_curs_vb(0);
    curs.set_inp(0);
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    leavePattern = 90;
    createDir(S_KEYS);
    char serverIp[30] = "127.0.0.1"; // change to the server ip //192.168.0.205
    const string portPath = "txt-files/PORT.txt";
    ifstream file(portPath);
    string PORTSTR;
    getline(file, PORTSTR);
    int PORT;
    istringstream(PORTSTR) >> PORT;
    std::cout << "Starting client" << std::endl;
    createDir(fpath);
    createDir(formatPath);
    // generate keys here and load them into the context config
    std::string pu = fmt::format("{}{}-pubkey.pem", fpath, "mykey");
    std::string puserver = fmt::format("{}{}-pubkey.pem", formatPath, "server");
    std::string cert = fmt::format("{}server-cert.pem", formatPath);
    std::string pr = fmt::format("{}{}-privkey.pem", fpath, "mykey");
    std::cout << "Initialized paths" << std::endl;
    initOpenSSL initializeTls;
    std::cout << "Initializing OpenSSL" << std::endl;
    initializeTls.InitOpenssl();
    std::cout << "OpenSSL initialized" << std::endl;
    cout << "Creating ctx" << endl;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    sslStore.push_back(ctx);
    cout << "Ctx Created" << endl;
    cout << "Generating keys" << endl;
    KeysMake genKeys(pr, pu);
    cout << "Keys have been generated" << endl;
    std::cout << "Fetching server cert file" << std::endl;
    // fetch_and_save_certificate(serverIp, "80", cert);
    const std::string get = fmt::format("curl -o {} http://{}:{}/ > /dev/null 2>&1", cert, serverIp, 80);
    int result = system(get.c_str());
    // cout << "Result: " << result << endl;
    if (result != 0)
    {
        std::cout << "Could not get server cert file for secure tls connection" << std::endl;
        raise(SIGINT);
    }
    cout << "Configuring ctx" << endl;
    initializeTls.configureContext(ctx, cert);
    cout << "Context has been configured" << endl;
    std::cout << "Extracting server public key from cert" << std::endl;
    LoadKey load;
    load.extractPubKey(cert, puserver);
    std::cout << "Extracted server public key from cert and stored in: " << puserver << std::endl;
    // std::filesystem::rename(cert, fmt::format("{}server-cert.pem", formatPath));

    string user;
    int startSock = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = inet_addr(serverIp);

    if (inet_pton(AF_INET, serverIp, &serverAddress.sin_addr) <= 0)
    {
        cout << "Invalid address / Address not supported\n";
        return 1;
    }

    if (connect(startSock, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        // fprintf(stderr, "connect: %s\n", strerror(errno));
        cout << "Cannot connect to server\n";
        close(startSock);
        return 1;
    }

    SSL *ssl = SSL_new(ctx);

    if (ssl == nullptr)
    {
        std::cerr << "Failed to create SSL object\n";
        close(startSock);
        return 1;
    }

    SSL_set_fd(ssl, startSock);

    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        raise(SIGINT);
    }

    clsockC += startSock;
    con = 1;
    tlsSock.push_back(ssl);
    cout << fmt::format("Found connection to server on port {}", PORT) << endl;
    // std::cout << "Connected with " << SSL_get_cipher(ssl) << " encryption" << std::endl;

    SSL_write(ssl, connectionSignal, strlen(connectionSignal));
    const string formatpath = "keys-from-server/";
    static const string fPath = "your-keys/";

    // check if directories exist if they dont then create them

    // recieve server pub key
    LoadKey loads;
    std::string serverPubPath = fmt::format("{}server-pubkey.pem", formatPath);
    Recieve recieveServerKey;
    std::string serverPubKeyBuff = recieveServerKey.getPemKey(ssl, serverPubPath);
    EVP_PKEY *rsaKey = loads.loadPemEVP(serverPubKeyBuff);
    // cout << "Serverkeybuf: " << serverPubKeyBuff << endl;
    // std::string decodedDataServerPub = recieveServerKey.base64Decode(severPubKeyBuff);

    // recieveServerKey.saveFile(serverPubPath, serverPubKeyBuff);

    LoadKey loadServerKey;
    EVP_PKEY *serverPublicKey = loadServerKey.LoadPubOpenssl(serverPubPath); //
    // std::filesystem::rename(serverPubPath, fmt::format("{}server-pubkey.pem", formatPath));

    if (serverPublicKey) /*if server key is loaded*/
    {
        cout << "Server's public key has been loaded" << endl;
    }
    else
    {
        cout << "Cannot load server's public key. Exiting." << endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(startSock);
        SSL_CTX_free(ctx);
        EVP_cleanup();
        leave();
        exit(1);
    }
    //-----------
    char passSignal[200] = {0};
    ssize_t bytesPassSig = SSL_read(ssl, passSignal, sizeof(passSignal) - 1);
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
        string password = getinput_getch(CLIENT_S, MODE_P, cert, ctx, startSock, ssl, "", getTermSizeCols(), serverIp, PORT);
        curs.set_curs_vb(0);
        curs.set_inp(0);
        cout << eraseLine;
        string encryptedPassword = encryptServerPass.enc(serverPublicKey, password);
        encryptedPassword = encryptServerPass.Base64Encode(encryptedPassword);

        SSL_write(ssl, encryptedPassword.c_str(), encryptedPassword.length());
        cout << eraseLine;
        if (password != "\u2702")
        {
            cout << eraseLine;
            cout << "Verifying password.." << endl;
        }
        // sleep(1);
        char passOp[200] = {0};
        ssize_t bytesOp = SSL_read(ssl, passOp, sizeof(passOp) - 1);
        passOp[bytesOp] = '\0';
        string verifyRecv(passOp); // works properly

        if (verifyRecv.empty())
        {
            cout << "Could not verify password" << endl;
            // exit(1);
            leavePattern = 90;
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
            // exit(1);
        }
    }
    else if (passSig == "2")
    {
    }

    for (int i = 0; i < 5; i++)
    {
        cout << xU;
    }
    ///
    cout << " Enter a username to go by ";
    for (int i = 0; i < 5; i++)
    {
        cout << xU;
    }
    cout << endl;
    curs.set_curs_vb();
    curs.set_inp();
    user = getinput_getch(CLIENT_S, MODE_N, cert, ctx, startSock, ssl, "/|\\| ", 12, serverIp, PORT); // seperate chars by '|'delimeter
    curs.set_curs_vb(0);
    curs.set_inp(0);

    cout << eraseLine;
    if (user != "\u2702")
    {
        cout << "Username: " << boldMode << user << boldModeReset << endl;
        if (user.empty() || user.length() > 12 || user.length() <= 3)
        { // set these on top
            disable_conio_mode();
            cout << "Invalid username. Disconnecting from server\n"; // username cant be less than 3 or morew tjhan 12
            raise(SIGINT);
        }
    }
    SSL_write(ssl, user.c_str(), sizeof(user));

    char usernameBuffer[200] = {0};
    ssize_t bytesReceived = SSL_read(ssl, usernameBuffer, sizeof(usernameBuffer) - 1);
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
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(startSock);
        SSL_CTX_free(ctx);
        EVP_cleanup();
        exit(1);
    }

    clsock.push_back(startSock);

    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey publicKey;

    LoadKey keyLoader;

    EVP_PKEY *prkey = keyLoader.LoadPrvOpenssl(pr);
    EVP_PKEY *pubkey = keyLoader.LoadPubOpenssl(pu);

    if (!prkey || !pubkey)
    {
        cout << "Your keys cannot be loaded. Exiting." << endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(startSock);
        SSL_CTX_free(ctx);
        EVP_cleanup();
        leave();
        exit(1);
    }
    else
    {
        cout << "Your keys have been loaded" << endl;
    }

    // recv active file
    Recieve recvActive;
    string encodedData = recvActive.receiveBase64Data(ssl);
    std::string decodedData = recvActive.base64Decode(encodedData);
    // recvActive.saveFile(usersActivePath, decodedData);

    std::ofstream activef(usersActivePath);

    if (activef.is_open())
    {
        // std::cout << "path: " << std::filesystem::current_path() << std::endl;
        activef << decodedData;
        if (is_regular_file(usersActivePath))
        {
            std::cout << "Users active file has been written to path: " << usersActivePath << std::endl;
        }
    }

    std::cout << "Users active file has been written to path: " << usersActivePath << std::endl;

    // sendFile(pu);
    Send sendtoserver;
    Recieve readpem;
    Enc be;
    if (is_regular_file(pu))
    {
        // sendPem(pu);
        std::string fi = readpem.read_pem_key(pu); // file path is a string to the file pat
        cout << fmt::format("Sending public key ({}) to server", pu) << endl;
        fi = be.Base64Encode(fi);
        sendtoserver.sendBase64Data(ssl, fi); // send encoded key
        cout << "Public key sent to server" << endl;
    }

    // read the active users
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

    //-------

    LoadKey loadp;
    EVP_PKEY *receivedPublicKey;

    // Send sendtoserver;
    Recieve recievePub;
    Dec decoding;
    Dec decrypt;
    string nameRecv = "";

    if (activeInt == 2)
    {
        char name[4096] = {0};
        ssize_t bt = SSL_read(ssl, name, sizeof(name));
        name[bt] = '\0';
        string pub(name);

        int indexInt = pub.find_first_of("/") + 1;
        pub = pub.substr(indexInt);
        pub = pub.insert(0, formatpath, 0, formatpath.length());
        int firstPipe = pub.find_last_of("/");
        int secondPipe = pub.find_last_of("-");
        std::string pubUser = pub.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
        nameRecv += pubUser;

        cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
        // recvServer(pub);
        std::string ec = recievePub.receiveBase64Data(ssl);
        std::string dc = recievePub.base64Decode(ec);
        recievePub.saveFilePem(pub, dc);

        if (is_regular_file(pub))
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

        receivedPublicKey = loadp.LoadPubOpenssl(pub);

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
            auto it = std::remove(clsock.begin(), clsock.end(), startSock);
            clsock.erase(it, clsock.end());
            raise(SIGINT);
        }
    }
    else if (activeInt == 1)
    {
        cout << "You have connected to an empty chat. Waiting for another user to connect to start the chat" << endl;
        leavePattern = 0;
        termcmd termcmdProgress;
        int *ac = &activeInt;
        // thread(call_pgbar, ac, activeInt).detach();
        while (true)
        {
            this_thread::sleep_for(chrono::seconds(2));
            signal(SIGINT, signalhandle);
            activeInt = readActiveUsers(usersActivePath);
            if (activeInt > 1)
            {
                break;
            }
        }
        cout << "Another user connected, starting chat.." << endl;
        char sec[4096] = {0};
        ssize_t btSec = SSL_read(ssl, sec, sizeof(sec));
        sec[btSec] = '\0';
        string secKey(sec);

        int firstPipe;
        int secondPipe;
        string pubUser;
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
                std::string decodedData2 = recievePub.base64Decode(encodedKey);
                recievePub.saveFilePem(secKey, decodedData2);
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
                string encodedData2 = recievePub.receiveBase64Data(ssl);
                std::string decodedData2 = recievePub.base64Decode(encodedData2);
                recievePub.saveFilePem(secKey, decodedData2);
            }
        }

        if (is_regular_file(secKey))
        {
            cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
        }
        else
        {
            cout << fmt::format("{}'s public key file does not exist", pubUser) << endl;
            auto it = std::remove(clsock.begin(), clsock.end(), startSock);
            clsock.erase(it, clsock.end());
            cout << "You have been disconnected due to not being able to encrypt messages due to public key not being found." << endl;
            raise(SIGINT);
            // exit(1);
        }

        cout << fmt::format("Attempting to load {}'s public key", pubUser) << endl;
        nameRecv += pubUser;
        receivedPublicKey = loadp.LoadPubOpenssl(secKey);

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
            auto it = std::remove(clsock.begin(), clsock.end(), startSock);
            clsock.erase(it, clsock.end());
            raise(SIGINT);
        }
    }

    thread receiver(receiveMessages, ssl, prkey);
    receiver.detach();

    string message;

    curs.set_curs_vb();
    curs.set_inp();

    // send join code

    while (true)
    {
        message = getinput_getch(CLIENT_S, MODE_N, cert, ctx, startSock, ssl, "", getTermSizeCols(), serverIp, PORT);
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

        // cout << "encrypting" << endl;
        string cipherText = cipher64.enc(receivedPublicKey, message);
        // cout << "encrypted" << endl;
        string newenc = cipher64.Base64Encode(cipherText);

        SSL_write(ssl, newenc.c_str(), newenc.length());
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
        if (message != "\u2702")
        {
            cout << GREEN_TEXT << fmt::format("{}(You): {}", userStr, message) << RESET_TEXT << fmt::format("\t\t\t\t{}", stringFormatTime);
        }
        else
        {
            cout << eraseLine;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(startSock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
