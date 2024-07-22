//https://github.com/galacticoder
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
#include "headers/encry.h"
#include <cstdio>
#include <ctime>
#include <arpa/inet.h>
#include <boost/asio.hpp>
#include <cstdlib>
#include <termios.h>
#include "headers/rsa.h"
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/queue.h>
#include <regex>
#include <filesystem>
#include <bits/stdc++.h>
#include <csignal>
#include <vector>
#include "headers/getch_getline.h" // including my own getline function i made for better user input allows arrow keys and stuff
// #include <ncurses.h>

//find a way to send the port file if possible

//try addig file sending whewn the client starts the message off with /sendfile {filepath} and let client 2 get a mesage this user is trying to send you a file would you like to recieve it or not? if not then dont recieve is yes then recieve it also maybe add a file view feature where you can open the file to see whats in it and you can accept the file later on with /acceptfile {thefilename that was given} if no args provided then accept the last file sent

//To run: g++ -o client client.cpp -lcryptopp -lfmt

#define formatPath "keys-from-server/"
#define fpath "your-keys/"
#define GREEN_TEXT "\033[32m" //green text color
// #define erasebeg "\033[2K\r" //erase from beggining
#define clearsrc "\033[2J\r" //clears screen and return cursor
#define left1 "\033[1D" //move the cursor back to the left once
#define right1 "\033[1C" //move the cursor back to the right once
#define RESET_TEXT "\033[0m" //reset color to default
#define xU "\u02DF"

using namespace std;
using namespace CryptoPP;
using boost::asio::ip::tcp;
using namespace filesystem;

vector <int> clsock;

uint8_t leavePattern;
static const string formatpath = "keys-from-server/";
static const string fPath = "your-keys/";


string getTime() {
    auto now = chrono::system_clock::now();
    time_t currentTime = chrono::system_clock::to_time_t(now);
    tm* localTime = localtime(&currentTime);

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

bool isPortOpen(const string& address, int port) {
    try {
        boost::asio::io_service io_service;
        tcp::socket socket(io_service);
        tcp::endpoint endpoint(boost::asio::ip::address::from_string(address), port);
        socket.connect(endpoint);
        return true;
    }
    catch (exception& e) {
        return false;
    }
}


void sendM(string& local, int& PORT, const string msg, const string& userStr, const int clientSocket) {
    bool serverReachable = isPortOpen(local, PORT);
    if (serverReachable != true) { //check if server is reachable before attempting to send a message
        cout << "Server has been shutdown" << endl;
        close(clientSocket);
        exit(true);
    }
    else {
        send(clientSocket, msg.c_str(), msg.length(), 0);
        // send(clientSocket, publicKey.c_str(), publicKey.length(), 0);
        cout << GREEN_TEXT << fmt::format("{}(You): {}", userStr, msg) << RESET_TEXT << endl; //print the message you sent without it doubkin g tho
    }
}

string t_w(string strIp) {
    strIp.erase(strIp.begin(), find_if(strIp.begin(), strIp.end(), [](unsigned char ch) {
        return !isspace(ch);
        }));
    strIp.erase(find_if(strIp.rbegin(), strIp.rend(), [](unsigned char ch) {
        return !isspace(ch);
        }).base(), strIp.end());
    return strIp;
}

bool containsOnlyASCII(const string& stringS) {
    for (auto c : stringS) {
        if (static_cast<unsigned char>(c) > 127) {
            return false;
        }
    }
    return true;
}

void clientThreeKeyRecv(const string& pathname, int clientSocket) {
    try {
        string active;
        int activeInt;
        while (true) {
            ifstream opent(pathname);
            getline(opent, active);
            istringstream(active) >> activeInt;
            if (activeInt == 3) {
                Recieve recieveClientPubKey3;
                char name[4096] = { 0 };
                ssize_t bt = recv(clientSocket, name, sizeof(name), 0);
                name[bt] = '\0';
                string pub(name);

                int indexInt = pub.find_first_of("/") + 1;
                pub = pub.substr(indexInt);
                pub = pub.insert(0, formatpath, 0, formatpath.length());
                int firstPipe = pub.find_last_of("/");
                int secondPipe = pub.find_last_of("-");
                string pubUser = pub.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);

                cout << fmt::format("Recieving {}'s public key", pubUser) << endl;

                string ec = recieveClientPubKey3.receiveBase64Data(clientSocket);
                vector<uint8_t> dc = recieveClientPubKey3.base64Decode(ec);
                recieveClientPubKey3.saveFile(pub, dc);

                if (is_regular_file(pub)) {
                    cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
                }
                else {
                    cout << "Public key file does not exist. Exiting.." << endl;
                    close(clientSocket);
                    leave();
                }
                LoadKey loadp;
                RSA::PublicKey receivedPublicKey;
                if (loadp.loadPub(pub, receivedPublicKey) == true) {
                    cout << fmt::format("{}'s public key has been loaded", pubUser) << endl;
                    ofstream rewrite(pathname);
                    if (rewrite.is_open()) {
                        rewrite << "#RD";
                    }
                }
                else {
                    cout << fmt::format("Could not load {}'s public key. Exiting..", pubUser) << endl;
                    close(clientSocket);
                    leave();
                }
            }
            else if (active == "#RD") {
                break;
            }
            else {
                break;
            }
        }
    }
    catch (const Exception& e) {
    }
}

// static void d/elIt(const string& formatpath) {
//     int del1 = 0;
//     auto del2 = filesystem::directory_iterator(formatpath);
//     int counter = 0;
//     for (auto& del1 : del2) {
//         if (del1.is_regular_file()) {
//             filesystem::remove(del1);
//             counter++;
//         }
//     }

//     if (counter == 0) {
//         cout << fmt::format("There was nothing to delete from path '{}'", formatpath) << endl;
//     }
//     if (counter == 1) {
//         cout << fmt::format("{} key in filepath ({}) have been deleted", counter, formatpath) << endl;
//     }
//     else if (counter > 1) {
//         cout << fmt::format("{} keys in filepath ({}) have been deleted", counter, formatpath) << endl;
//     }
// }

// void leave(int clientSocket = clsock[0], const string& formatpath = formatPath, const string& fPath = fpath) {
//     close(clientSocket);
//     delIt(formatpath);
//     delIt(fPath);
//     exit(true);
// }1

void signalhandle(int signum) {
    cout << eraseLine;
    // cout << erasefromc;
    // switch (leavePattern) {
    // case 0:
    //     cout << "You have disconnected from the empty chat." << endl;
    // case 1:
    //     cout << "You have left the chat" << endl;
    // default:
    //     cout << "You have been kicked for having an existing username";
    // }

    leavePattern == 0 ? cout << "You have disconnected from the empty chat." << endl : cout << "You have left the chat" << endl;
    leave();
    // cout << "you left" << endl;
    exit(signum);
}

void receiveMessages(int clientSocket, RSA::PrivateKey privateKey) {
    char buffer[4096];
    while (true) {
        ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            Dec decoding;
            Dec decrypt;
            buffer[bytesReceived] = '\0';
            string receivedMessage(buffer);
            string decodedMessage;

            if (receivedMessage.find('|') == string::npos) {
                decodedMessage = decoding.Base64Decode(receivedMessage);
                try {
                    string decryptedMessage = decrypt.dec(privateKey, decodedMessage);
                    disable_conio_mode();
                    cout << decryptedMessage << endl;
                    enable_conio_mode();
                }
                catch (const CryptoPP::Exception& e) {
                    // If decryption fails, it may not be an encrypted message
                    // cout << "Failed to decrypt server message: " << e.what() << endl; //for d
                    // cout << decodedMessage << endl;
                }
            }

            if (bytesReceived < 500) {
                if (receivedMessage.find('|') != string::npos) {
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

            try {
                if (receivedMessage.find('|') != string::npos) { //if found
                    disable_conio_mode();
                    string decryptedMessage = decrypt.dec(privateKey, decodedMessage);
                    cout << fmt::format("{}: {}\t\t\t\t{}", user, decryptedMessage, time);
                    enable_conio_mode();
                }
            }
            catch (const CryptoPP::Exception& e) {
            }
        }
    }
}

static bool createDir(const string& dirName)
{
    if (!create_directories(dirName))
    {
        if (exists(dirName))
        {
            // cout << fmt::format("The directory ({}) already exists", dirName) << endl;
            return true;
        }
        else {
            cout << fmt::format("Couldnt create directory: {}", dirName) << endl;
            return false;
        }
    }
    return true;

}


int main() {
    // cout << clearsrc << endl;
    // leavePattern == 
    char serverIp[30] = "192.168.0.205"; //change to the server ip
    ifstream file("PORT.txt");
    string PORTSTR;
    getline(file, PORTSTR);
    int PORT;
    istringstream(PORTSTR) >> PORT;

    string user;
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = inet_addr(serverIp);

    if (inet_pton(AF_INET, serverIp, &serverAddress.sin_addr) <= 0) {
        cout << "Invalid address / Address not supported\n";
        return 1;
    }
    // cout << serverIp;


    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        cout << "Cannot connect to server\n";
        close(clientSocket);
        return 1;
    }

    cout << fmt::format("Found connection to server on port {}", PORT) << endl;

    // cout << "\u02F9\t\t\u02FA";
    for (int i = 0; i < 5;i++) {
        cout << xU;
    }
    ///
    cout << " Enter a username to go by ";
    // cout << "\u02FA";
    for (int i = 0; i < 5;i++) {
        cout << xU;
    }
    cout << endl;
    //get username input
    // getline(cin, user);

    user = getinput_getch("/|\\| ", 12); //seperate chars by '|' delimeter


    cout << eraseLine;
    cout << "Username: " << boldMode << user << boldModeReset << endl;

    // string* user;
    // getstr(&string); //append from vector to string and return from function back to string and save it in the string provided in arg



    //-------------

    if (user.empty() || user.length() > 12 || user.length() <= 3) { //set these on top
        cout << "Invalid username. Disconnecting from server\n"; //username cant be less than 3 or morew tjhan 12
        close(clientSocket);
        exit(1);
    }

    send(clientSocket, user.c_str(), sizeof(user), 0);


    //to recieve new client username if usrname had spaces or limit or same name
    char usernameBuffer[200] = { 0 };
    ssize_t bytesReceived = recv(clientSocket, usernameBuffer, sizeof(usernameBuffer) - 1, 0);
    usernameBuffer[bytesReceived] = '\0';
    string userStr(usernameBuffer);


    // cout << "\nUserstr is: " << userStr << endl;
    //check if userstr is equal to the client has the same name exiting message from server then it exits 
    if (userStr.back() == '*') {
        userStr.pop_back();
        cout << userStr << endl;
        close(clientSocket);
        exit(1);
    }

    else if (userStr.back() == '@') {
        cout << userStr.substr(0, userStr.length() - 1) << endl;
        close(clientSocket);
        exit(1);
    }

    clsock.push_back(clientSocket);
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    //check if directories exist if they dont then create them
    createDir(fpath);
    createDir(formatPath);

    static string pu = fmt::format("{}{}-pubkey.der", fpath, user);
    static string pr = fmt::format("{}{}-privkey.der", fpath, user);
    KeysMake keys(pr, pu); //generates our keys
    //load generated keys to make sure they can be accessed
    LoadKey keyLoader;
    if (!keyLoader.loadPrv(pr, privateKey) || !keyLoader.loadPub(pu, publicKey)) {
        cout << "Your keys cannot be loaded. Exiting." << endl;
        close(clientSocket);
        leave();
    }

    Recieve recvActive;
    static const string usersActivePath = "headers/usersActive.txt";//
    string encodedData = recvActive.receiveBase64Data(clientSocket);
    vector<uint8_t> decodedData = recvActive.base64Decode(encodedData);
    recvActive.saveFile(usersActivePath, decodedData);

    // sendFile(pu);
    Send sendtoserver;
    if (is_regular_file(pu)) {
        vector<uint8_t> fi = sendtoserver.readFile(pu); //file path is a string to the file path
        string ed4 = sendtoserver.b64EF(fi);
        cout << fmt::format("Sending public key ({}) to server: {}", pu, ed4) << endl;
        // cout << "Encoded data sending is: " << encodedData << endl;
        sendtoserver.sendBase64Data(clientSocket, ed4); //send encoded key
        cout << "Public key sent to server" << endl;
    }


    // ssize_t pubname = recv(clientSocket, name, sizeof(name), 0);


    //send this file from the server
    ifstream opent(usersActivePath);
    string active;
    int activeInt;

    if (opent.is_open()) {
        getline(opent, active);
        istringstream(active) >> activeInt;
    }
    else {
        cout << "Could not open the usersActive.txt file to read" << endl;
        close(clientSocket);
        leave();
    }

    // int last = (pub.find_last_of("-p")) - 2;
    // int lastS = (pub.find_last_of("/")) + 1;
    // string userSent = pub.substr(lastS, last);


    RSA::PublicKey receivedPublicKey;
    RSA::PublicKey receivedPublicKey2;

    // Send sendtoserver;
    LoadKey loadp;
    Recieve recievePub;
    Recieve recievePub2;
    Dec decoding;
    Dec decrypt;
    string nameRecv = "";


    //-----------------

    if (activeInt == 3) {
        //for user 1
        char name[4096] = { 0 };
        ssize_t bt = recv(clientSocket, name, sizeof(name), 0);
        name[bt] = '\0';
        string pub(name);

        int indexInt = pub.find_first_of("/") + 1;
        pub = pub.substr(indexInt);
        pub = pub.insert(0, formatpath, 0, formatpath.length());
        int firstPipe = pub.find_last_of("/");
        int secondPipe = pub.find_last_of("-");
        string pubUser = pub.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
        nameRecv += pubUser;

        cout << fmt::format("Recieving {}'s public key", pubUser) << endl;

        string ec = recievePub.receiveBase64Data(clientSocket);
        vector<uint8_t> dc = recievePub.base64Decode(ec);
        recievePub.saveFile(pub, dc);

        if (is_regular_file(pub)) {
            cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
        }
        else {
            cout << "Public key file does not exist. Exiting.." << endl;
            close(clientSocket);
            leave();
        }
        //---------------
        char name2[4096] = { 0 };
        ssize_t bt2 = recv(clientSocket, name2, sizeof(name2), 0);
        name2[bt2] = '\0';
        string pub2(name2);

        int indexInt2 = pub2.find_first_of("/") + 1;
        pub2 = pub2.substr(indexInt2);
        pub2 = pub2.insert(0, formatpath, 0, formatpath.length());
        int firstPipe2 = pub2.find_last_of("/");
        int secondPipe2 = pub2.find_last_of("-");
        string pubUser2 = pub2.substr(firstPipe2 + 1, (secondPipe2 - firstPipe2) - 1);
        nameRecv += pubUser2;

        cout << fmt::format("Recieving {}'s public key", pubUser2) << endl;

        string ec2 = recievePub.receiveBase64Data(clientSocket);
        vector<uint8_t> dc2 = recievePub.base64Decode(ec2);
        recievePub.saveFile(pub2, dc2);

        if (is_regular_file(pub2)) {
            cout << fmt::format("Recieved {}'s pub key", pubUser2) << endl;
        }
        else {
            cout << "Public key file does not exist. Exiting.." << endl;
            close(clientSocket);
            leave();
        }
        //----------

        cout << fmt::format("Attempting to load {}'s public key & {}'s public key..", pubUser2, pubUser) << endl;

        if (loadp.loadPub(pub, receivedPublicKey) == true && loadp.loadPub(pub2, receivedPublicKey2)) {
            cout << fmt::format("{}'s & {}'s public keys have been loaded", pubUser, pubUser2) << endl;
            if (activeInt > 1) {
                cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - 1 other user in chat - To quit the chat type '/quit' - \n", userStr, activeInt) << RESET_TEXT;
                leavePattern = 1;
            }
            else {
                cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - {} users in chat - To quit the chat type '/quit' -\n", userStr, activeInt) << RESET_TEXT;
                leavePattern = 1;
            }
        }
        else {
            cout << "Could not load required public keys. Exiting.." << endl;
            close(clientSocket);
            leave();
        }
    }

    else if (activeInt == 2) {
        char name[4096] = { 0 };
        ssize_t bt = recv(clientSocket, name, sizeof(name), 0);
        name[bt] = '\0';
        string pub(name);

        int indexInt = pub.find_first_of("/") + 1;
        pub = pub.substr(indexInt);
        pub = pub.insert(0, formatpath, 0, formatpath.length());
        int firstPipe = pub.find_last_of("/");
        int secondPipe = pub.find_last_of("-");
        string pubUser = pub.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
        nameRecv += pubUser;

        cout << fmt::format("Recieving {}'s public key", pubUser) << endl;

        string ec = recievePub.receiveBase64Data(clientSocket);
        vector<uint8_t> dc = recievePub.base64Decode(ec);
        recievePub.saveFile(pub, dc);

        if (is_regular_file(pub)) {
            cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
        }
        else {
            cout << "Public key file does not exist. Exiting.." << endl;
            close(clientSocket);
            leave();
        }

        cout << fmt::format("Attempting to load {}'s public key", pubUser) << endl;

        if (loadp.loadPub(pub, receivedPublicKey) == true) {
            cout << fmt::format("{}'s public key loaded", pubUser) << endl;
            if (activeInt > 1) {
                cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - 1 other user in chat - To quit the chat type '/quit' - \n", userStr, activeInt) << RESET_TEXT;
                leavePattern = 1;
            }
            else {
                cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - {} users in chat - To quit the chat type '/quit' -\n", userStr, activeInt) << RESET_TEXT;
                leavePattern = 1;
            }
        }
        else {
            cout << fmt::format("Could not load {}'s public key", pubUser) << endl;
            close(clientSocket);
            exit(1);
        }
    }
    else if (activeInt == 1) {
        cout << "You have connected to an empty chat. Waiting for another user to connect to start the chat" << endl;
        leavePattern = 0;
        while (true) {
            this_thread::sleep_for(chrono::seconds(2));
            signal(SIGINT, signalhandle);
            activeInt = readActiveUsers(usersActivePath);
            if (activeInt > 1) {
                break;
            }
        }

        cout << "Another user connected, starting chat.." << endl;

        if (activeInt == 2) {
            char sec[4096] = { 0 };
            ssize_t btSec = recv(clientSocket, sec, sizeof(sec), 0);
            sec[btSec] = '\0';
            string secKey(sec);

            int firstPipe;
            int secondPipe;
            string pubUser;
            if (secKey.length() > 50) {
                static string s2find = ".der";
                int found = secKey.find(".der") + s2find.length();
                if (found != string::npos) {
                    string encodedKey = secKey.substr(found);
                    secKey = secKey.substr(0, found);
                    firstPipe = secKey.find_last_of("/");
                    secondPipe = secKey.find_last_of("-");
                    pubUser = secKey.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
                    cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
                    vector<uint8_t> decodedData2 = recievePub2.base64Decode(encodedKey);
                    recievePub2.saveFile(secKey, decodedData2);
                }
                else {
                    cout << "Couldnt format sec key" << endl;
                    close(clientSocket);
                    leave();
                }
            }

            else if (secKey.length() < 50) {
                firstPipe = secKey.find_last_of("/");
                secondPipe = secKey.find_last_of("-");
                pubUser = secKey.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);

                if (secKey.length() < 50) {
                    cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
                    string encodedData2 = recievePub2.receiveBase64Data(clientSocket);
                    vector<uint8_t> decodedData2 = recievePub2.base64Decode(encodedData2);
                    recievePub2.saveFile(secKey, decodedData2);
                }
            }
            if (is_regular_file(secKey)) {
                cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
            }
            else {
                cout << fmt::format("{}'s public key file does not exist", pubUser) << endl;
                close(clientSocket);
                cout << "You have been disconnected due to not being able to encrypt messages due to public key not being found." << endl;
                leave();
            }
            cout << fmt::format("Attempting to load {}'s public key", pubUser) << endl;

            nameRecv += pubUser;
            if (loadp.loadPub(secKey, receivedPublicKey) == true) {
                cout << fmt::format("{}'s public key loaded", pubUser) << endl;
                if (activeInt > 1) {
                    cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - 1 other user in chat - To quit the chat type '/quit' -\n", userStr, activeInt) << RESET_TEXT;
                    leavePattern = 1;
                }
                else {
                    //for grammar
                    cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - {} users in chat - To quit the chat type '/quit' -\n", userStr, activeInt) << RESET_TEXT;
                    leavePattern = 1;
                }
            }
            else {
                cout << fmt::format("Could not load {}'s public key", pubUser) << endl;
                close(clientSocket);
                exit(1);
            }
        }
        else if (activeInt == 3) {
            char sec[4096] = { 0 };
            ssize_t btSec = recv(clientSocket, sec, sizeof(sec), 0);
            sec[btSec] = '\0';
            string secKey(sec);

            int firstPipe;
            int secondPipe;
            string pubUser;
            if (secKey.length() > 50) {
                static string s2find = ".der";
                int found = secKey.find(".der") + s2find.length();
                if (found != string::npos) {
                    string encodedKey = secKey.substr(found);
                    secKey = secKey.substr(0, found);
                    firstPipe = secKey.find_last_of("/");
                    secondPipe = secKey.find_last_of("-");
                    pubUser = secKey.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
                    cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
                    vector<uint8_t> decodedData2 = recievePub2.base64Decode(encodedKey);
                    recievePub2.saveFile(secKey, decodedData2);
                }
                else {
                    cout << "Couldnt format sec key" << endl;
                    close(clientSocket);
                    leave();
                }
            }

            else if (secKey.length() < 50) {
                firstPipe = secKey.find_last_of("/");
                secondPipe = secKey.find_last_of("-");
                pubUser = secKey.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);

                if (secKey.length() < 50) {
                    cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
                    string encodedData2 = recievePub2.receiveBase64Data(clientSocket);
                    vector<uint8_t> decodedData2 = recievePub2.base64Decode(encodedData2);
                    recievePub2.saveFile(secKey, decodedData2);
                }
            }
            if (is_regular_file(secKey)) {
                cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
            }
            else {
                cout << fmt::format("{}'s public key file does not exist", pubUser) << endl;
                close(clientSocket);
                cout << "You have been disconnected due to not being able to encrypt messages due to public key not being found." << endl;
                leave();
            }

            //----------------------
            char sec2[4096] = { 0 };
            ssize_t btSec2 = recv(clientSocket, sec2, sizeof(sec2), 0);
            sec2[btSec2] = '\0';
            string secKey2(sec2);

            int firstPipe2;
            int secondPipe2;
            string pubUser2;
            if (secKey2.length() > 50) {
                static string s2find2 = ".der";
                int found2 = secKey2.find(".der") + s2find2.length();
                if (found2 != string::npos) {
                    string encodedKey2 = secKey2.substr(found2);
                    secKey2 = secKey2.substr(0, found2);
                    firstPipe2 = secKey2.find_last_of("/");
                    secondPipe2 = secKey2.find_last_of("-");
                    pubUser2 = secKey2.substr(firstPipe2 + 1, (secondPipe2 - firstPipe2) - 1);
                    cout << fmt::format("Recieving {}'s public key", pubUser2) << endl;
                    vector<uint8_t> decodedData22 = recievePub2.base64Decode(encodedKey2);
                    recievePub2.saveFile(secKey2, decodedData22);
                }
                else {
                    cout << "Couldnt format sec key" << endl;
                    close(clientSocket);
                    leave();
                }
            }

            else if (secKey2.length() < 50) {
                firstPipe2 = secKey2.find_last_of("/");
                secondPipe2 = secKey2.find_last_of("-");
                pubUser2 = secKey2.substr(firstPipe2 + 1, (secondPipe2 - firstPipe2) - 1);

                cout << fmt::format("Recieving {}'s public key", pubUser2) << endl;
                string encodedData22 = recievePub2.receiveBase64Data(clientSocket);
                vector<uint8_t> decodedData22 = recievePub2.base64Decode(encodedData22);
                recievePub2.saveFile(secKey2, decodedData22);
            }
            if (is_regular_file(secKey2)) {
                cout << fmt::format("Recieved {}'s pub key", pubUser2) << endl;
            }
            else {
                cout << fmt::format("{}'s public key file does not exist", pubUser) << endl;
                close(clientSocket);
                cout << "You have been disconnected due to not being able to encrypt messages due to public key not being found." << endl;
                leave();
            }
            //---------------------

            cout << fmt::format("Attempting to load {}'s public key & {}'s public key", pubUser, pubUser2) << endl;

            nameRecv += pubUser;
            if (loadp.loadPub(secKey, receivedPublicKey) == true) {
                cout << fmt::format("{}'s & {}'s public keys have been loaded", pubUser, pubUser2) << endl;
                if (activeInt == 2) {
                    cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - 1 other user in chat - To quit the chat type '/quit' -\n", userStr, activeInt) << RESET_TEXT;
                    leavePattern = 1;
                }
                else {
                    //for grammar
                    cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - {} users in chat - To quit the chat type '/quit' -\n", userStr, activeInt) << RESET_TEXT;
                    leavePattern = 1;
                }
            }
            else {
                cout << "Could not load required public keys. Exiting.." << endl;
                close(clientSocket);
                leave();
            }
        }
    }
    //-----------------

    thread receiver(receiveMessages, clientSocket, privateKey);
    receiver.detach();
    thread checkIf(clientThreeKeyRecv, usersActivePath, clientSocket);
    checkIf.detach();

    string message;
    signal(SIGINT, signalhandle);

    //this while loop runs once after every message
    while (true) {
        // clientThreeKeyRecv(usersActivePath, clientSocket);
        // ch = getch();
        // getline(cin, message); /<--> none
        message = getinput_getch();
        cout << endl;
        //clear input start 
        cout << "\033[A"; //up
        cout << "\r"; //delete
        cout << "\033[K"; //from start mixed up on line 128
        //end
        if (t_w(message) == "/quit") { //CHECK IF USERS IS EQUAL TO 0 THEN DELETE KEYS // ALSO RECIEVE UPDATED USERSACTIVE TXT FILE WHEN USER QUITS
            cout << "You have left the chat\n";
            close(clientSocket);
            leave();
            break;
        }
        //use t_w first before sending the message
        else if (message.empty()) {
            continue; //skip empty messages
        }
        message = t_w(message);
        // cout << "substringed is: " << message.substr(0, 8 + 1) << endl;
        // if (message == "quit") {
        //     //delete pub files directory after leaving the chat 

        //     //when this code is in file cannot run client locally
        //     exit(true);
        // }

        Enc cipher64;

        //CHANGE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        string cipherText = cipher64.enc(receivedPublicKey, message); //wrong not supposed to encrypt using user pub key only using recipient public key //2nd clients key
        string newenc = cipher64.Base64Encode(cipherText); //for 2nd client

        // cout << "encoded: " << newenc << endl;
        // cout << "encrypted text: \t" << cipherText << endl;
        // cout << "ciphertext length on client: " << cipherText.length();

        //need to send key, iv, and message with a pipe delimeter all at once because of data loss
        bool serverReachable = isPortOpen(serverIp, PORT);
        if (serverReachable != true) { //check if server is reachable before attempting to send a message
            cout << "Server has been shutdown" << endl; //put in function
            close(clientSocket);
            leave();
        }
        else {
            if (activeInt > 2) { //implying its 3 because thats the limit of users allowed in one chat room
                string cipherTextCl1 = cipher64.enc(receivedPublicKey2, message); //wrong not supposed to encrypt using user pub key only using recipient public key // 1st clients key
                string newenc1 = cipher64.Base64Encode(cipherTextCl1);

                // RSA::PublicKey load3rdclkey;
                // LoadKey loadpubkey;
                // string thirdKeyFile = formatPath + ;
                // loadpubkey.loadPub(load3rdclkey);

                // string cipherTextCl3 = cipher64.enc(load3rdclkey, message); //wrong not supposed to encrypt using user pub key only using recipient public key // 1st clients key
                // string newenc3 = cipher64.Base64Encode(cipherTextCl1);

                newenc += "2";
                newenc1 += "1"; //clientUsernames[0]// recievdMEssage.back() if == 1
                // newenc3 += "3"; //clientUsernames[0]// recievdMEssage.back() if == 1
                send(clientSocket, newenc.c_str(), newenc.length(), 0);
                send(clientSocket, newenc1.c_str(), newenc1.length(), 0);
                // send(clientSocket, newenc3.c_str(), newenc3.length(), 0);

                string stringFormatTime = getTime();
                cout << GREEN_TEXT << fmt::format("{}(You): {}", userStr, message) << RESET_TEXT << fmt::format("\t\t\t\t{}", stringFormatTime);
            }
            else if (activeInt <= 2) {
                send(clientSocket, newenc.c_str(), newenc.length(), 0);
                string stringFormatTime = getTime();
                cout << GREEN_TEXT << fmt::format("{}(You): {}", userStr, message) << RESET_TEXT << fmt::format("\t\t\t\t{}", stringFormatTime);
            }
        }
    }

    close(clientSocket);
    leave();
    return 0;
}
