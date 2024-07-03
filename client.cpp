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

//find a way to send the port file if possible

//try addig file sending whewn the client starts the message off with /sendfile {filepath} and let client 2 get a mesage this user is trying to send you a file would you like to recieve it or not? if not then dont recieve is yes then recieve it also maybe add a file view feature where you can open the file to see whats in it and you can accept the file later on with /acceptfile {thefilename that was given} if no args provided then accept the last file sent

//To run: g++ -o client client.cpp -lcryptopp -lfmt

#define GREEN_TEXT "\033[32m" //green text color
#define RESET_TEXT "\033[0m" //reset color to default

using namespace std;
using namespace CryptoPP;
using boost::asio::ip::tcp;
using namespace filesystem;


bool isPortOpen(const std::string& address, int port) {
    try {
        boost::asio::io_service io_service;
        tcp::socket socket(io_service);
        tcp::endpoint endpoint(boost::asio::ip::address::from_string(address), port);
        socket.connect(endpoint);
        return true;
    }
    catch (std::exception& e) {
        return false;
    }
}

void sendM(string& local, int& PORT, const string msg, const string& userStr, const int clientSocket) {
    bool serverReachable = isPortOpen(local, PORT);
    if (serverReachable != true) { //check if server is reachable before attempting to send a message
        std::cout << "Server has been shutdown" << endl;
        close(clientSocket);
        exit(true);
    }
    else {
        send(clientSocket, msg.c_str(), msg.length(), 0);
        // send(clientSocket, publicKey.c_str(), publicKey.length(), 0);
        std::cout << GREEN_TEXT << fmt::format("{}(You): {}", userStr, msg) << RESET_TEXT << endl; //print the message you sent without it doubkin g tho
    }
}

std::string t_w(std::string strIp) {
    strIp.erase(strIp.begin(), std::find_if(strIp.begin(), strIp.end(), [](unsigned char ch) {
        return !std::isspace(ch);
        }));
    strIp.erase(std::find_if(strIp.rbegin(), strIp.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
        }).base(), strIp.end());
    return strIp;
}

bool containsOnlyASCII(const std::string& stringS) {
    for (auto c : stringS) {
        if (static_cast<unsigned char>(c) > 127) {
            return false;
        }
    }
    return true;
}

static void delIt(const string& formatPath) {
    int del1 = 0;
    auto del2 = std::filesystem::directory_iterator(formatPath);
    int counter = 0;
    for (auto& del1 : del2) {
        if (del1.is_regular_file()) {
            std::filesystem::remove(del1);
            counter++;
        }
    }

    if (counter == 0) {
        cout << fmt::format("There was nothing to delete from path '{}'", formatPath) << endl;
    }
    if (counter == 1) {
        cout << fmt::format("{} key in filepath ({}) have been deleted", counter, formatPath) << endl;
    }
    else if (counter > 1) {
        cout << fmt::format("{} keys in filepath ({}) have been deleted", counter, formatPath) << endl;
    }
}

void receiveMessages(int clientSocket, RSA::PrivateKey privateKey) {
    char buffer[4096];
    while (true) {
        ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            string receivedMessage(buffer);
            // if (typing.load()) {
            //     std::cout << "\r\033[K" << std::flush; //clear line
            //     std::cout << "\r\033[K" << "Another user is typing..." << std::flush;
            // }
            if (receivedMessage[0] == '|') { //were going to treat this as a file accept reply message
                receivedMessage = receivedMessage.substr(1, receivedMessage.length() - 1);
                cout << receivedMessage;
                string reply;
                getline(cin, reply);
                // cout << "reply is: " << reply << endl;
                send(clientSocket, reply.data(), reply.length(), 0); //sending back the reply
                if (reply == "y") {
                    static string filepathSave = "usersentfile.txt";
                    Recieve recvFile;
                    std::string encodedData = recvFile.receiveBase64Data(clientSocket);
                    std::vector<uint8_t> decodedData = recvFile.base64Decode(encodedData);
                    recvFile.saveFile(filepathSave, decodedData);
                    if (is_regular_file(filepathSave)) { //if file exists
                        cout << "You have saved the file username has sent" << endl;
                    }
                    else {
                        cout << "File could not be saved" << endl;
                    }
                }
            }

            string decodedMessage;
            if (bytesReceived < 500) {
                cout << receivedMessage << endl;
                continue;
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
            Dec decoding;
            decodedMessage = decoding.Base64Decode(cipher);
            // cout << "decoded Base64" << endl;
            // cout << "base 64 decode: " << decodedMessage << endl;
            // if (containsOnlyASCII(decodedMessage) == true) {
            //     cout << receivedMessage << endl;
            //     continue;
            // }

            try {
                Dec decrypt;
                string decryptedMessage = decrypt.dec(privateKey, decodedMessage);
                cout << fmt::format("{}: {}\t\t\t\t{}", user, decryptedMessage, time);
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

int readActiveUsers() {
    ifstream opent("usersActive.txt");
    string active;
    getline(opent, active);
    int activeInt;
    istringstream(active) >> activeInt;
    return activeInt;
}

int main() {
    char serverIp[30] = "192.168.0.38"; //if server is being served locally change to your loopback address
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
        std::cerr << "Invalid address / Address not supported" << std::endl;
        return 1;
    }
    // cout << serverIp;

    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cout << "Cannot connect to server\n";
        close(clientSocket);
        return 1;
    }

    std::cout << fmt::format("Found connection to server on port {}", PORT) << endl;
    std::cout << "Enter a username to go by: ";
    getline(cin, user);

    if (user.empty() || user.length() > 12 || user.length() <= 3) {
        std::cout << "Invalid username. Disconnecting from server\n"; //username cant be less than 3 or morew tjhan 12
        close(clientSocket);
        exit(1);
    }

    send(clientSocket, user.c_str(), sizeof(user), 0);


    //to recieve new client username if usrname had spaces
    char buffer[4096] = { 0 };
    ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    buffer[bytesReceived] = '\0';
    std::string userStr(buffer);

    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    static const string formatPath = "keys-from-server/";
    static const string fpath = "your-keys/";

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

    string pu = fmt::format("{}{}-pubkey.der", fpath, user);
    string pr = fmt::format("{}{}-privkey.der", fpath, user);
    KeysMake keys(pr, pu); //generates our keys
    //load generated keys to make sure they can be accessed
    LoadKey keyLoader;
    keyLoader.loadPrv(pr, privateKey);
    keyLoader.loadPub(pu, publicKey);

    Recieve recvActive;
    std::string encodedData = recvActive.receiveBase64Data(clientSocket);
    std::vector<uint8_t> decodedData = recvActive.base64Decode(encodedData);
    recvActive.saveFile("usersActive.txt", decodedData);

    // sendFile(pu);
    Send sendtoserver;
    if (is_regular_file(pu)) {
        std::vector<uint8_t> fi = sendtoserver.readFile(pu); //file path is a string to the file path
        std::string ed4 = sendtoserver.b64EF(fi);
        cout << fmt::format("Sending public key ({}) to server: {}", pu, ed4) << endl;
        // cout << "Encoded data sending is: " << encodedData << endl;
        sendtoserver.sendBase64Data(clientSocket, ed4); //send encoded key
        cout << "Public key sent to server" << endl;
    }


    // ssize_t pubname = recv(clientSocket, name, sizeof(name), 0);


    //send this file from the server
    ifstream opent("usersActive.txt");
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

    if (activeInt == 2) {
        // cout << "Users more than 1 executing 1st" << endl;
        char name[4096] = { 0 };
        ssize_t bt = recv(clientSocket, name, sizeof(name), 0);
        name[bt] = '\0';
        std::string pub(name);
        int indexInt = pub.find_first_of("/") + 1;
        pub = pub.substr(indexInt);
        pub = pub.insert(0, formatPath, 0, formatPath.length());
        // cout << fmt::format("Formatted 1 pub: {}", pub) << endl;
        int firstPipe = pub.find_last_of("/");
        int secondPipe = pub.find_last_of("-");
        string pubUser = pub.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);

        cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
        // recvServer(pub);
        std::string ec = recievePub.receiveBase64Data(clientSocket);
        std::vector<uint8_t> dc = recievePub.base64Decode(ec);
        recievePub.saveFile(pub, dc);

        //change to recieve 
        // cout << fmt::format("recieved filename: {}", pub) << endl;
        std::ifstream file(pub, std::ios::binary);
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
            std::this_thread::sleep_for(std::chrono::seconds(2));
            activeInt = readActiveUsers();
            if (activeInt > 1) {
                break;
            }
        }
        cout << "Another user connected, starting chat.." << endl;
        char sec[4096] = { 0 };
        ssize_t btSec = recv(clientSocket, sec, sizeof(sec), 0);
        sec[btSec] = '\0';
        std::string secKey(sec);

        // cout << "seckey bytes: " << sizeof(secKey) << endl;
        if (sizeof(secKey) < 100) {
            int indexInt = secKey.find_first_of("/") + 1;
            secKey = secKey.substr(indexInt);
            secKey = secKey.insert(0, formatPath, 0, formatPath.length());
            // cout << fmt::format("Formatted 1 secKey: {}", secKey) << endl;
        }
        int firstPipe = secKey.find_last_of("/");
        int secondPipe = secKey.find_last_of("-");
        string pubUser = secKey.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);



        cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
        std::string encodedData2 = recievePub2.receiveBase64Data(clientSocket);
        std::vector<uint8_t> decodedData2 = recievePub2.base64Decode(encodedData2);
        recievePub2.saveFile(secKey, decodedData2);
        // cout << encodedData2 << endl;
        // cout << "stage 1 complete" << endl;
        // cout << "stage 2 complete" << endl;
        // cout << "stage 3 complete" << endl;

        // std::ifstream file(secKey, std::ios::binary);
        if (is_regular_file(secKey)) {
            cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
            // file.close();
        }
        else {
            cout << "Public key file does not exist" << endl;
        }


        // cout << fmt::format("recieved filename: {}", pub) << endl;
        // std::ifstream pubkeyrecv(secKey, std::ios::binary);
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

    thread receiver(receiveMessages, clientSocket, privateKey);
    receiver.detach();

    string message;
    while (true) {
        getline(cin, message); //^<--> none
        //clear input start 
        std::cout << "\033[A"; //up
        std::cout << "\r"; //delete
        std::cout << "\033[K"; //from start mixed up on line 128
        //end
        if (t_w(message) == "quit") { //CHECK IF USERS IS EQUAL TO 0 THEN DELETE KEYS // ALSO RECIEVE UPDATED USERSACTIVE TXT FILE WHEN USER QUITS
            cout << "You have left the chat" << endl;
            close(clientSocket);
            delIt(formatPath);
            delIt(fpath);
            break;
        }
        //use t_w first before sending the message
        else if (message.empty()) {
            continue; //skip empty messages
        }
        message = t_w(message);
        // cout << "substringed is: " << message.substr(0, 8 + 1) << endl;
        if (message.substr(0, 8 + 1) == "/sendfile") { //if this true then encrypt the file before sending it and let the server send it back to the other client
            if (is_regular_file(message.substr(8 + 2, message.length() - 1))) { //add encryption to the file before sending
                cout << "Sending file waiting for user to reply" << endl;
                send(clientSocket, message.c_str(), message.length(), 0); //send the file too
                Send sendfile;
                std::vector<uint8_t> buffer = sendfile.readFile(message.substr(8 + 2, message.length() - 1)); //file path is a string to the file path
                std::string encodedData = sendfile.b64EF(buffer);
                sendfile.sendBase64Data(clientSocket, encodedData);
            }
            else {
                cout << "This file does not exist cannot send" << endl;
            }
        }

        // if (message == "quit") {
        //     //delete pub files directory after leaving the chat 

        //     //when this code is in file cannot run client locally
        //     exit(true);
        // }

        Enc cipher64;

        //CHANGE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        std::string cipherText = cipher64.enc(receivedPublicKey, message); //wrong not supposed to encrypt using user pub key only using recipient public key
        string newenc = cipher64.Base64Encode(cipherText);
        // cout << "encoded: " << newenc << endl;
        // cout << "encrypted text: \t" << cipherText << endl;
        // cout << "ciphertext length on client: " << cipherText.length();

        //need to send key, iv, and message with a pipe delimeter all at once because of data loss
        bool serverReachable = isPortOpen(serverIp, PORT);
        if (serverReachable != true) { //check if server is reachable before attempting to send a message
            std::cout << "Server has been shutdown" << endl; //put in function
            close(clientSocket);
            delIt(formatPath);
            delIt(fpath);
            exit(true);
        }
        else {
            if (message.substr(0, 8 + 1) != "/sendfile") {
                send(clientSocket, newenc.c_str(), newenc.length(), 0);
                auto now = std::chrono::system_clock::now();
                std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
                std::tm* localTime = std::localtime(&currentTime);

                bool isPM = localTime->tm_hour >= 12;
                string stringFormatTime = asctime(localTime);

                int tHour = (localTime->tm_hour > 12) ? (localTime->tm_hour - 12) : ((localTime->tm_hour == 0) ? 12 : localTime->tm_hour);

                stringstream ss;
                ss << tHour << ":" << (localTime->tm_min < 10 ? "0" : "") << localTime->tm_min << " " << (isPM ? "PM" : "AM");
                string formattedTime = ss.str();

                std::regex time_pattern(R"(\b\d{2}:\d{2}:\d{2}\b)");
                std::smatch match;
                if (regex_search(stringFormatTime, match, time_pattern))
                {
                    string str = match.str(0);
                    size_t pos = stringFormatTime.find(str);
                    stringFormatTime.replace(pos, str.length(), formattedTime);
                }
                // send(clientSocket, publicKey.c_str(), publicKey.length(), 0);
                std::cout << GREEN_TEXT << fmt::format("{}(You): {}", userStr, message) << RESET_TEXT << fmt::format("\t\t\t\t{}", stringFormatTime); //print the message you sent without it doubkin g tho
            }
            // cout << cipherText << endl;
        }
    }

    close(clientSocket);
    return 0;
}
