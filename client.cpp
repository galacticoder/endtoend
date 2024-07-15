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
#include "encry.h"
#include <cstdio>
#include <ctime>
#include <arpa/inet.h>
#include <boost/asio.hpp>
#include <cstdlib>
#include <termios.h>
#include "rsa.h"
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
// #include <ncurses.h>

//find a way to send the port file if possible

//try addig file sending whewn the client starts the message off with /sendfile {filepath} and let client 2 get a mesage this user is trying to send you a file would you like to recieve it or not? if not then dont recieve is yes then recieve it also maybe add a file view feature where you can open the file to see whats in it and you can accept the file later on with /acceptfile {thefilename that was given} if no args provided then accept the last file sent

//To run: g++ -o client client.cpp -lcryptopp -lfmt

#define formatPath "keys-from-server/"
#define fpath "your-keys/"

#define GREEN_TEXT "\033[32m" //green text color
#define erasebeg "\033[2K\r" //erase from beggining
#define left1 "\033[1D" //move the cursor back to the left once
#define right1 "\033[1C" //move the cursor back to the right once
#define RESET_TEXT "\033[0m" //reset color to default

using namespace std;
using namespace CryptoPP;
using boost::asio::ip::tcp;
using namespace filesystem;

vector <int> clsock;

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

static void delIt(const string& formatpath) {
    int del1 = 0;
    auto del2 = filesystem::directory_iterator(formatpath);
    int counter = 0;
    for (auto& del1 : del2) {
        if (del1.is_regular_file()) {
            filesystem::remove(del1);
            counter++;
        }
    }

    if (counter == 0) {
        cout << fmt::format("There was nothing to delete from path '{}'", formatpath) << endl;
    }
    if (counter == 1) {
        cout << fmt::format("{} key in filepath ({}) have been deleted", counter, formatpath) << endl;
    }
    else if (counter > 1) {
        cout << fmt::format("{} keys in filepath ({}) have been deleted", counter, formatpath) << endl;
    }
}

void leave(int clientSocket = clsock[0], const string& formatpath = formatPath, const string& fPath = fpath) {
    close(clientSocket);
    delIt(formatpath);
    delIt(fPath);
    exit(true);
}

void signalhandle(int signum) {
    cout << erasebeg;
    // cout << erasefromc;
    cout << "You have left the chat" << endl;
    leave();
    // cout << "you left" << endl;
    exit(signum);
}

void receiveMessages(int clientSocket, RSA::PrivateKey privateKey, string userstr) {
    char buffer[4096];
    while (true) {
        ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            Dec decoding;
            Dec decrypt;
            buffer[bytesReceived] = '\0';
            string receivedMessage(buffer);
            string decodedMessage;

            if (receivedMessage.find('|') == string::npos) { //if not found
                // cout << "msg from server: " << receivedMessage << endl;
                decodedMessage = decoding.Base64Decode(receivedMessage);
                try {
                    string decryptedMessage = decrypt.dec(privateKey, decodedMessage);
                    cout << decryptedMessage << endl;
                }
                catch (const CryptoPP::Exception& e) {
                    // If decryption fails, it may not be an encrypted message
                    // cout << "Failed to decrypt server message: " << e.what() << endl; //for d
                    // cout << decodedMessage << endl;
                }
            }

            if (bytesReceived < 500) {
                if (receivedMessage.find('|') != string::npos) {
                    cout << receivedMessage << endl;
                    continue;
                }
            }
            // cout << "quit is : " << receivedMessage.find_last_of("quit") << endl;
            // cout << "len is: " << receivedMessage.length() - 1 << endl;
            // if (receivedMessage.find_last_of("quit") == receivedMessage.length() - 1) {
                // continue;
            // }

            int firstPipe = receivedMessage.find_first_of("|");
            int secondPipe = receivedMessage.find_last_of("|");
            string cipher = receivedMessage.substr(secondPipe + 1);
            string time = receivedMessage.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
            string user = receivedMessage.substr(0, firstPipe);

            // cout << "encoded recieved: " << receivedMessage << endl;
            // cout << "cipher recieved: " << cipher << endl;
            // decodedMessage = Base64Decode(receivedMessage);
            decodedMessage = decoding.Base64Decode(cipher);
            // cout << "decoded Base64" << endl;
            // cout << "base 64 decode: " << decodedMessage << endl;
            // if (containsOnlyASCII(decodedMessage) == true) {
            //     cout << receivedMessage << endl;
            //     continue;
            // }

            try {
                if (receivedMessage.find('|') != string::npos) {
                    string decryptedMessage = decrypt.dec(privateKey, decodedMessage);
                    cout << fmt::format("{}: {}\t\t\t\t{}", user, decryptedMessage, time);
                }
            }
            catch (const CryptoPP::Exception& e) {
                // If decryption fails, it may not be an encrypted message
                // cout << "Failed to decrypt message: " << e.what() << endl;
                // cout << decodedMessage << endl;
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
            cout << fmt::format("The directory ({}) already exists", dirName) << endl;
            return true;
        }
        cout << fmt::format("couldnt make directory: {}", dirName) << endl;
        return false;
    }
    return true;
}

int readActiveUsers(const string& filepath) {
    ifstream opent(filepath);
    string active;
    getline(opent, active);
    int activeInt;
    istringstream(active) >> activeInt;
    return activeInt;
}

int main() {//MKA
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
        printw("Invalid address / Address not supported\n");
        return 1;
    }
    // cout << serverIp;

    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        cout << "Cannot connect to server\n";
        close(clientSocket);
        return 1;
    }

    cout << fmt::format("Found connection to server on port {}", PORT) << endl;
    cout << "Enter a username to go by: ";
    getline(cin, user);

    if (user.empty() || user.length() > 12 || user.length() <= 3) { //set these on top
        cout << "Invalid username. Disconnecting from server\n"; //username cant be less than 3 or morew tjhan 12
        close(clientSocket);
        exit(1);
    }

    send(clientSocket, user.c_str(), sizeof(user), 0);


    //to recieve new client username if usrname had spaces
    char buffer[4096] = { 0 };
    ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    buffer[bytesReceived] = '\0';
    string userStr(buffer);

    clsock.push_back(clientSocket);
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    static const string formatpath = "keys-from-server/";
    static const string fPath = "your-keys/";

    //check if directories exist if they dont then create them
    if (!exists(formatPath)) {
        createDir(formatPath);
    }
    // else {
    //     delIt(formatPath);
    // }
    if (!exists(fpath)) {
        createDir(fpath);
    }
    // else {
    //     delIt(fpath);
    // }

    static string pu = fmt::format("{}{}-pubkey.der", fpath, user);
    static string pr = fmt::format("{}{}-privkey.der", fpath, user);
    KeysMake keys(pr, pu); //generates our keys
    //load generated keys to make sure they can be accessed
    LoadKey keyLoader;
    if (!keyLoader.loadPrv(pr, privateKey) || !keyLoader.loadPub(pu, publicKey)) {
        cout << "Your keys cannot be loaded. Exiting." << endl;
        leave(clientSocket);
        exit(1);
    }

    Recieve recvActive;
    static const string usersActivePath = "usersActive.txt";
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
        exit(1);
    }

    // int last = (pub.find_last_of("-p")) - 2;
    // int lastS = (pub.find_last_of("/")) + 1;
    // string userSent = pub.substr(lastS, last);


    RSA::PublicKey receivedPublicKey;


    // Send sendtoserver;
    LoadKey loadp;
    Recieve recievePub;
    Recieve recievePub2;
    Dec decoding;
    Dec decrypt;

    if (activeInt == 2) {
        // cout << "Users more than 1 executing 1st" << endl;
        char name[4096] = { 0 };
        ssize_t bt = recv(clientSocket, name, sizeof(name), 0);
        name[bt] = '\0';
        string pub(name);

        int indexInt = pub.find_first_of("/") + 1;
        pub = pub.substr(indexInt);
        pub = pub.insert(0, formatpath, 0, formatpath.length());
        // cout << fmt::format("Formatted 1 pub: {}", pub) << endl;
        int firstPipe = pub.find_last_of("/");
        int secondPipe = pub.find_last_of("-");
        string pubUser = pub.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);

        cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
        // recvServer(pub);
        string ec = recievePub.receiveBase64Data(clientSocket);
        vector<uint8_t> dc = recievePub.base64Decode(ec);
        recievePub.saveFile(pub, dc);

        //change to recieve 
        // cout << fmt::format("recieved filename: {}", pub) << endl;
        ifstream file(pub, ios::binary);
        if (file.is_open()) {
            cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
            file.close();
        }
        else {
            cout << "Public key file recieved cannot be opened or does not exist" << endl;
        }

        cout << fmt::format("Attempting to load {}'s public key", pubUser) << endl;
        // string some = "user-keys/pub/someone-pubkey.der";
        // loadp.loadPub(some, receivedPublicKey);
        if (loadp.loadPub(pub, receivedPublicKey) == true) {
            cout << fmt::format("{}'s public key loaded", pubUser) << endl;
            if (activeInt > 1) {
                cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - 1 other user in chat - To quit the chat properly type 'quit' - \n", user, activeInt) << RESET_TEXT;
            }
            else {
                cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - {} users in chat - To quit the chat properly type 'quit' -\n", user, activeInt) << RESET_TEXT;
            }

            // const string conn = "1";
            // send(clientSocket, conn.c_str(), conn.length(), 0);
        }
        else {

            cout << fmt::format("Could not load {}'s public key", pubUser) << endl;
            close(clientSocket);
            exit(1);

            // const string err = "0";
            // send(clientSocket, err.c_str(), err.length(), 0);
        }
    }
    else if (activeInt == 1) {
        cout << "You have connected to an empty chat. Waiting for another user to connect to start the chat" << endl;
        while (true) {
            this_thread::sleep_for(chrono::seconds(2));
            activeInt = readActiveUsers(usersActivePath);
            if (activeInt > 1) {
                break;
            }
        }
        cout << "Another user connected, starting chat.." << endl;
        char sec[4096] = { 0 };
        ssize_t btSec = recv(clientSocket, sec, sizeof(sec), 0);
        sec[btSec] = '\0';
        string secKey(sec);
        // cout << "ORIGINAL SEC KEY: " << secKey << endl;

        // // cout << "seckey bytes: " << sizeof(secKey) << endl;
        // if (sizeof(secKey) < 100) { //change this to adapt to the bottom code
        //     int indexInt = secKey.find_first_of("/") + 1;
        //     secKey = secKey.substr(indexInt);
        //     secKey = secKey.insert(0, formatPath, 0, formatPath.length());
        //     // cout << fmt::format("Formatted 1 secKey: {}", secKey) << endl;
        // }

            //keys-from-server/someone-pubkeyfromserver.der
        int firstPipe;
        int secondPipe;
        string pubUser;
        if (secKey.length() > 50) {
            // cout << GREEN_TEXT << "CHARS OVER 5000000000000000000" << RESET_TEXT << endl;
            static string s2find = ".der";
            int found = secKey.find(".der") + s2find.length();
            if (found != string::npos) {
                string encodedKey = secKey.substr(found);
                secKey = secKey.substr(0, found);
                // cout << "new secKey: " << secKey << endl;
                // cout << "encoded key is: " << encodedKey << endl;
                firstPipe = secKey.find_last_of("/");
                secondPipe = secKey.find_last_of("-");
                pubUser = secKey.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
                cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
                vector<uint8_t> decodedData2 = recievePub2.base64Decode(encodedKey);
                // cout << "decoded key gonna save" << endl;
                recievePub2.saveFile(secKey, decodedData2);
                // cout << "saved file" << endl;
            }
            else {
                cout << "Couldnt format sec key" << endl;
                leave(clientSocket);
            }
        }

        else if (secKey.length() < 50) {
            firstPipe = secKey.find_last_of("/");
            secondPipe = secKey.find_last_of("-");
            pubUser = secKey.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);

            if (secKey.length() < 50) {
                cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
                string encodedData2 = recievePub2.receiveBase64Data(clientSocket);
                // cout << "encd2: " << encodedData2 << endl;
                vector<uint8_t> decodedData2 = recievePub2.base64Decode(encodedData2);
                recievePub2.saveFile(secKey, decodedData2);
            }
        }
        // cout << "now seckey: " << secKey << endl;
        // }

        // if (pubUser.length() > 12 || pubUser.length() < 3) {
        //     //SO WHEN IT PRINTS OUT SECKEY AND YOU CAN SEE WHATS GOING ON SPLIT THE KEY DATA WITH THE USERNAME AND PATH IF THEY CAME TOGETHER.
        //     cout << "Pub user could not format properly" << endl;
        //     close(clientSocket);
        //     delIt(formatPath);
        //     delIt(fpath);
        //     exit(1);
        // }
        // cout << encodedData2 << endl;
        // cout << "stage 1 complete" << endl;
        // cout << "stage 2 complete" << endl;
        // cout << "stage 3 complete" << endl;

        // ifstream file(secKey, ios::binary);
        if (is_regular_file(secKey)) {
            cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
            // file.close();
        }
        else {
            cout << "Public key file does not exist" << endl;
        }


        // cout << fmt::format("recieved filename: {}", pub) << endl;
        // ifstream pubkeyrecv(secKey, ios::binary);
        // if (pubkeyrecv.is_open()) {
        //     cout << "success" << endl;
        //     pubkeyrecv.close();
        // }
        // else {
        //     cout << "file recieved cannot be open";
        // }
        cout << fmt::format("Attempting to load {}'s public key", pubUser) << endl;
        // string some = "user-keys/pub/someone-pubkey.der";
        // loadp.loadPub(some, receivedPublicKey);
        if (loadp.loadPub(secKey, receivedPublicKey) == true) {
            cout << fmt::format("{}'s public key loaded", pubUser) << endl;
            if (activeInt > 1) {
                cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - 1 other user in chat -  To quit the chat properly type 'quit' -\n", user, activeInt) << RESET_TEXT;
            }
            else {
                cout << GREEN_TEXT << fmt::format("-- You have joined the chat as {} - {} users in chat - To quit the chat properly type 'quit' -\n", user, activeInt) << RESET_TEXT;
            }
            // const string conn = "1";
            // send(clientSocket, conn.c_str(), conn.length(), 0);
        }
        else {

            cout << fmt::format("Could not load {}'s public key", pubUser) << endl;
            close(clientSocket);
            exit(1);
            // const string err = "0";
            // send(clientSocket, err.c_str(), err.length(), 0);
        }
    }

    thread receiver(receiveMessages, clientSocket, privateKey, userStr);
    receiver.detach();

    string message;
    signal(SIGINT, signalhandle);

    // int ch;
    // // while (true) {
    // initscr(); //start ncurses
    // // }./
    // raw(); //no line buffer enabled 
    // keypad(stdscr, TRUE); //enable special key detection like arrow keys and function keys


    while (true) {
        // ch = getch();
        getline(cin, message); //^<--> none
        //clear input start 
        cout << "\033[A"; //up
        cout << "\r"; //delete
        cout << "\033[K"; //from start mixed up on line 128
        //end
        if (t_w(message) == "quit") { //CHECK IF USERS IS EQUAL TO 0 THEN DELETE KEYS // ALSO RECIEVE UPDATED USERSACTIVE TXT FILE WHEN USER QUITS
            cout << "You have left the chat\n";
            leave(clientSocket);
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
        string cipherText = cipher64.enc(receivedPublicKey, message); //wrong not supposed to encrypt using user pub key only using recipient public key
        string newenc = cipher64.Base64Encode(cipherText);
        // cout << "encoded: " << newenc << endl;
        // cout << "encrypted text: \t" << cipherText << endl;
        // cout << "ciphertext length on client: " << cipherText.length();

        //need to send key, iv, and message with a pipe delimeter all at once because of data loss
        bool serverReachable = isPortOpen(serverIp, PORT);
        if (serverReachable != true) { //check if server is reachable before attempting to send a message
            cout << "Server has been shutdown" << endl; //put in function
            endwin();
            leave(clientSocket);
        }
        else {
            send(clientSocket, newenc.c_str(), newenc.length(), 0);
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
            // send(clientSocket, publicKey.c_str(), publicKey.length(), 0);
            cout << GREEN_TEXT << fmt::format("{}(You): {}", userStr, message) << RESET_TEXT << fmt::format("\t\t\t\t{}", stringFormatTime); //print the message you sent without it doubkin g tho
            // printw("%s(You): %s\t\t\t\t%s", userStr.c_str(), message.c_str(), stringFormatTime.c_str()); //print the message you sent without it doubkin g tho
        }
        // cout << cipherText << endl;

        //bathroom break

    }
    close(clientSocket);
    endwin();
    return 0;
}
