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
#define PING "ping"
#define PONG "pong"
#define connectionSignal "C"

using namespace std;
using namespace CryptoPP;
using boost::asio::ip::tcp;
using namespace filesystem;

vector <int> clsock;
uint8_t leavePattern;

bool isPav(const string& address, int port) {
    try {
        boost::system::error_code ecCheck;
        boost::asio::ip::address::from_string(address, ecCheck);
        if (ecCheck) {
            cout << "invalid ip address: " << address << endl;
            // return false;
        }
        boost::asio::io_service io_service;
        tcp::socket socket(io_service);
        tcp::endpoint endpoint(boost::asio::ip::address::from_string(address), port);
        socket.connect(endpoint);

        return true;
    }
    catch (const exception& e) {
        modeP.clear();
        cout << "Server has been shutdown" << endl;
        leave();
        cout << "exception: " << e.what() << endl;
        return false;
    }
    return false; // not reachable
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

void signalhandle(int signum) {
    cout << eraseLine;
    leavePattern == 0 ? cout << "You have disconnected from the empty chat." << endl : cout << "You have left the chat" << endl;
    leave();
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

            if (receivedMessage == PING) {
                send(clientSocket, PONG, strlen(PONG), 0);
                continue;
            }

            if (receivedMessage.find('|') == string::npos) {
                if (receivedMessage != PING) {
                    decodedMessage = decoding.Base64Decode(receivedMessage);
                    try {
                        string decryptedMessage = decrypt.dec(privateKey, decodedMessage);
                        disable_conio_mode();
                        cout << decryptedMessage << endl;
                        enable_conio_mode();
                    }
                    catch (const CryptoPP::Exception& e) {
                    }
                }
            }

            if (bytesReceived < 500) {
                // disable_conio_mode();
                // cout << "b is a: " << bytesReceived << 
                // enable_conio_mode();

                if (receivedMessage.find('|') != string::npos || receivedMessage != PING) { //if '|' not found
                    // if (receivedMessage.empty()) {
                    //     disable_conio_mode();
                    //     cout << "recieved message is empty" << endl;
                    //     enable_conio_mode();
                    // }
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

            // cout << "encoded recieved: " << receivedMessage << endl
            // cout << "cipher recieved: " << cipher << endl;
            // decodedMessage = Base64Decode(receivedMessage);
            decodedMessage = decoding.Base64Decode(cipher);
            // cout << "decoded Base64" << endl;
            // cout << "base 64 decode: " << decodedMessage << endl;
            // if (containsOnlyASCII(decodedMessage) == true) {
            //     cout << receivedMessage << endl;
            //     continue;
            // }

            // cout << "decoded: " << decodedMessage << endl;

            try {
                if (receivedMessage.find('|') != string::npos) { //if found
                    disable_conio_mode();
                    string decryptedMessage = decrypt.dec(privateKey, decodedMessage);
                    cout << fmt::format("{}: {}\t\t\t\t{}", user, decryptedMessage, time);
                    enable_conio_mode();
                }
            }
            catch (const CryptoPP::Exception& e) {
                // If decryption failsit may not be an encrypted message
                // cout << "Failed to decryptge: " << e.what() << endl;
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
            // cout << fmt::format("The directory ({}) already exists";
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
    // cout << clearsrc << en
    // leavePattern == 
    char serverIp[30] = "127.0.0.1"; //change to the server ip //192.168.0.205
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

    send(clientSocket, connectionSignal, strlen(connectionSignal), 0);//

    // std::atomic<bool> running{ true };
    // const unsigned int update_interval = 2; // update after every 50 milliseconds
    // std::thread pingingServerClientSide(isPortOpen, serverIp, PORT, std::ref(running), update_interval);
    // pingingServerClientSide.detach();

    char passSignal[200] = { 0 };
    ssize_t bytesPassSig = recv(clientSocket, passSignal, sizeof(passSignal) - 1, 0);
    passSignal[bytesPassSig] = '\0';
    string passSig(passSignal);

    if (passSig.back() == '*') {
        passSig.pop_back();
        cout << passSig << endl;
        close(clientSocket); //client Socket is already being closed by servero noneed to shutdown 
        exit(1);
    }

    else if (passSig[0] == '1') {
        cout << "This server is password protected. Enter the password to join: " << endl;
        string password = getinput_getch(CLIENT_S, MODE_P, serverIp, PORT);
        send(clientSocket, password.c_str(), password.length(), 0);
        // cout << "\x1b[A";
        cout << eraseLine;
        if (password != "\u2702") {
            // cout << "some";
            cout << eraseLine;
            cout << "Verifying password.." << endl;
        }
        sleep(1);
        char passOp[200] = { 0 };
        ssize_t bytesOp = recv(clientSocket, passOp, sizeof(passOp) - 1, 0);
        passOp[bytesOp] = '\0';
        string verifyRecv(passOp); //works properly now

        if (verifyRecv.empty()) {
            cout << "Could not verify password" << endl;
            exit(1);
        }
        else if (verifyRecv.substr(verifyRecv.length() - 2, verifyRecv.length()) == "#V") {
            cout << verifyRecv.substr(0, verifyRecv.length() - 2) << endl;
        }
        else if (verifyRecv.substr(verifyRecv.length() - 2, verifyRecv.length()) == "#N") {
            cout << verifyRecv.substr(0, verifyRecv.length() - 2) << endl;
            exit(1);
        }
    }
    else if (passSig == "2") {
    }

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
    //get username in
    // getline(cin, user);

    user = getinput_getch(CLIENT_S, MODE_N, serverIp, PORT, "/|\\| ", 12); //seperate chars by '|' delimeter


    cout << eraseLine;
    cout << "Username: " << boldMode << user << boldModeReset << endl;

    // string* user;
    // getstr(&string); //append from vectoro string and return from function back to string and save it in the string provided in arg



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
    if (userStr.substr(userStr.length() - 2, userStr.length()) == "#V") {
        cout << userStr.substr(0, userStr.length() - 2) << endl;
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
    static const string formatpath = "keys-from-server/";
    static const string fPath = "your-keys/";

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
        leave();
    }


    RSA::PublicKey receivedPublicKey;


    // Send sendtoserver;
    LoadKey loadp;
    Recieve recievePub;
    Recieve recievePub2;
    Dec decoding;
    Dec decrypt;
    string nameRecv = "";

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
        nameRecv += pubUser;

        cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
        // recvServer(pub);
        string ec = recievePub.receiveBase64Data(clientSocket);
        vector<uint8_t> dc = recievePub.base64Decode(ec);
        recievePub.saveFile(pub, dc);

        //change to recieve 
        // cout << fmt::format("recieved filename: {}", pub) << endl;
        if (is_regular_file(pub)) {
            cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
        }
        else {
            cout << "Public key file does not exist. Exiting.." << endl;
            close(clientSocket);
            leave();
        }

        cout << fmt::format("Attempting to load {}'s public key", pubUser) << endl;
        // string some = "user-keys/pub/someone-pubkey.der";
        // loadp.loadPub(some, receivedPublicKey);

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
        leavePattern = 0;
        while (true) {
            this_thread::sleep_for(chrono::seconds(2));
            // thread(isPortOpen, serverAddress, PORT).detach();
            signal(SIGINT, signalhandle);
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
                close(clientSocket);
                leave();
                // exit(1);
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

        if (is_regular_file(secKey)) {
            cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
            // file.close();
        }
        else {
            cout << fmt::format("{}'s public key file does not exist", pubUser) << endl;
            close(clientSocket);
            cout << "You have been disconnected due to not being able to encrypt messages due to public key not being found." << endl;
            leave();
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

    thread receiver(receiveMessages, clientSocket, privateKey);
    receiver.detach();

    string message;
    signal(SIGINT, signalhandle);

    // int ch;
    // // while (true) {
    // initscr(); //start ncurses
    // // }.//
    // raw(); //no line buffer enabled 
    // keypad(stdscr, TRUE); //enable special key detection like arrow keys and function keys


    while (true) {
        // ch = getch();
        // getline(cin, message); //<--> none
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
        string cipherText = cipher64.enc(receivedPublicKey, message); //wrong not supposed to encrypt using user pub key only using recipient public key
        string newenc = cipher64.Base64Encode(cipherText);
        // cout << "encoded: " << newenc << endl;
        // cout << "encrypted text: \t" << cipherText << endl;
        // cout << "ciphertext length on client: " << cipherText.length();

        //need to send key, iv, and message with a pipe delimeter all at once because of data loss
        bool serverReachable = isPav(serverIp, PORT);
        if (serverReachable != true) { //check if server is reachable before attempting to send a message
            cout << "Server has been shutdown" << endl; //put in function
            close(clientSocket);
            leave();
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
    return 0;
}
