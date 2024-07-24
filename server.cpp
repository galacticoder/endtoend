// https://github.com/galacticoder
#include <iostream>
#include <vector>
#include <thread>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <fstream>
#include <cstring>
#include <mutex>
#include <fmt/core.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <sstream>
#include <boost/asio.hpp>
#include <ctime>
#include <chrono>
#include <regex>
#include <stdlib.h>
#include <unistd.h>
#include <filesystem>
#include <ncurses.h>
#include "headers/serverSendRecv.h"

// add certain length of username allow only

// To run: g++ -std=c++20 -o server server.cpp -lcryptopp -lfmt

//std::vector<std::vector<int>> userandclsocket

// map<string, int> userAndClSocket;

// // Insert some values into the map
// mp["one"] = 1;
// mp["two"] = 2;
// mp["three"] = 3;

// // Get an iterator pointing to the first element in the
// // map
// map<string, int>::iterator it = mp.begin();

// // Iterate through the map and print the elements
// while (it != mp.end()) {
//     cout << "Key: " << it->first
//          << ", Value: " << it->second << endl;
//     ++it;
// }
#define PASS_N 1
#define PASS_O 2

using boost::asio::ip::tcp;

using namespace std;
using namespace CryptoPP;
using namespace std::chrono;
using namespace filesystem;


vector<int> connectedClients;
vector<int> uids;
vector<string> clientUsernames;
mutex clientsMutex;
// const stringlenOfUser;

//std::string encodedData = receiveBase64Data(clientSocket);
//std::vector<uint8_t> decodedData = base64Decode(encodedData);
//saveFile(filePath, decodedData);
// using namespace std::chrono_literals;

bool isPav(int port)
{
    int pavtempsock;
    struct sockaddr_in addr;
    bool available = false;

    pavtempsock = socket(AF_INET, SOCK_STREAM, 0);

    if (pavtempsock < 0)
    {
        std::cerr << "Cannot create socket to test port availability" << std::endl;
        return false;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(pavtempsock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        available = false;
    }
    else
    {
        available = true;
    }

    close(pavtempsock);
    return available;
}

void signalHandleServer(int signum) {
    cout << eraseLine;
    cout << "Server has been shutdown" << endl;
    delIt("server-recieved-client-keys");
    // cout << "you left" << endl;
    exit(signum);
}

static bool createDir(const string& dirName)
{
    if (!create_directories(dirName))
    {
        if (exists(dirName))
        {
            return true;
        }
        cout << fmt::format("Couldnt make directory: {}", dirName) << endl;
        return false;
    }
    return true;
}

void broadcastMessage(const string& message, int senderSocket = -1)
{
    lock_guard<mutex> lock(clientsMutex);
    for (int clientSocket : connectedClients)
    {
        if (clientSocket != senderSocket)
        {
            send(clientSocket, message.c_str(), message.length(), 0);
        }
    }
}

// void broadcastFile(string& filename, int senderSocket = -1)
// {
// {
// lock_guard<mutex> lock(clientsMutex);
// for (int clientSocket : connectedClients)
// {
// if (clientSocket == senderSocket) {
// continue;
// }
// else if (clientSocket != senderSocket)
// {
// //send file to all clients but the sender
// sendFile(filename);
// }
// }
// }
// }

void updatePort(int PORT) {
    string portfile = "FILEPORT.TXT";
    std::ofstream file(portfile);
    if (file.is_open())
    {
        file << PORT;
        file.close();
    }
    else
    {
        cout << "Cannot write file server port to file" << endl;
        return;
    }
}

// void EncAndB64enc(string plaintext, string userStr, string lenOfUser) {
//     LoadKey loadkeyandsend;
//     if (clientUsernames[0] == userStr) {
//         int index = 0 + 1;
//         string pathpub = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[index]);
//         string op64 = loadkeyandsend.loadPubAndEncrypt(pathpub, plaintext);
//         cout << "UPDATED OP64: " << op64 << endl;
//         if (lenOfUser.length() == userStr.length() && lenOfUser == userStr && op64 != "err") {
//             send(connectedClients[index], op64.c_str(), op64.length(), 0);
//         }
//     }

//     else if (clientUsernames[1] == userStr) {
//         int index2 = 1 - 1;
//         string pathpub2 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[index2]);
//         string op642 = loadkeyandsend.loadPubAndEncrypt(pathpub2, plaintext);
//         cout << "UPDATED OP642: " << op642 << endl;
//         if (lenOfUser.length() == userStr.length() && lenOfUser == userStr && op642 != "err") {
//             // send(connectedClients[index2], op642.c_str(), op642.length(), 0);
//             send(connectedClients[index2], op642.c_str(), op642.length(), 0);
//         }
//     }
// }

string countUsernames(string& clientsNamesStr)
{ // make the func erase the previous string and make it empty to add all users
    clientsNamesStr.clear();
    if (clientsNamesStr.empty())
    {
        for (int i = 0; i < clientUsernames.size(); ++i)
        {
            if (clientUsernames.size() >= 2)
            {
                // for the last index dont print a comma
                clientsNamesStr.append(clientUsernames[i] + ","); // find the userbname and the before start pos and after end pos should be a comma
            }
            else
            {
                clientsNamesStr.append(clientUsernames[i]);
            }
        }
    }
    if (clientUsernames.size() >= 2)
    {
        clientsNamesStr.pop_back(); // to pop extra comma in the end
    }

    return clientsNamesStr;
}

// int showfp() {
// int PORT;
// string portfile = "FILEPORT.TXT";
// ifstream fileport(portfile);
// if (!fileport.is_open()) {
// cerr << "Could not open port file" << endl;
// return 0;
// }
// string PORTSTR;
// getline(fileport, PORTSTR);
// istringstream(PORTSTR) >> PORT;
// return PORT;
// }

void updateActiveFile(auto data) {
    std::ofstream file("usersActive.txt");
    file.open("usersActive.txt", std::ofstream::out | std::ofstream::trunc);
    file.close();

    ofstream fp("usersActive.txt");

    if (fp.is_open())
    {
        fp << data;
        fp.close();
    }
}

void handleClient(int clientSocket, int serverSocket, unordered_map<int, string> serverHash, const string notVerified, string passGetArg) {
    //check user hash given in order to continue in the chat
    string clientsNamesStr = "";
    {
        lock_guard<mutex> lock(clientsMutex);
        connectedClients.push_back(clientSocket);
    }

    char buffer[4096] = { 0 };
    ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    buffer[bytesReceived] = '\0';
    std::string userStr(buffer);

    if (bcrypt::validatePassword(passGetArg, serverHash[1]) != 1) {
        send(clientSocket, notVerified.c_str(), notVerified.length(), 0);
        sleep(1); //so they recieve it before closing their socket
        close(clientSocket);
        userStr.clear();
        auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
        connectedClients.erase(it, connectedClients.end());
        cout << "disconnected not verified user" << endl;
    }

    int index = userStr.find("|");
    string pubkeyseri = userStr.substr(index + 1);
    userStr = userStr.substr(0, index);

    uint8_t limOfUsers = 2;

    //end = * == user attempted to join the chat past the limit allowed
    //end = @ == user attempted to join the chat with an already existing username in the chat

    const string limReached = "The limit of users has been reached for this chat. Exiting..*";

    if (clientUsernames.size() == limOfUsers) {
        send(clientSocket, limReached.c_str(), limReached.length(), 0);
        cout << fmt::format("client attempted to join past the required limit of users({})", limOfUsers) << endl;

        auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
        connectedClients.erase(it, connectedClients.end());
        cout << "removed client socket of user that attempted to join past limit from vector" << endl;
        cout << "connectedClients vector size: " << connectedClients.size() << endl;

        userStr.clear();

        close(clientSocket);
    }

    // clientsNamesStr = countUsernames(clientsNamesStr); //something is being added making the vecotr 2
    // cout << "Connected clients: (";// (sopsijs,SOMEONE,ssjss,)
    else if (clientUsernames.size() > 0 && clientUsernames.size() != limOfUsers) {
        const string exists = "Username already exists. You are have been kicked.@"; //detects if username already exists
        for (uint8_t i = 0; i < clientUsernames.size();i++) {
            if (clientUsernames[i] == userStr) {
                cout << "client with the same username detected. kicking.." << endl;
                send(clientSocket, exists.c_str(), exists.length(), 0);

                auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
                connectedClients.erase(it, connectedClients.end());
                cout << "removed client with the same username socket from vector" << endl;
                cout << "connectedClients vector size: " << connectedClients.size() << endl;

                close(clientSocket);
                userStr.clear();
                // sleep(1);
            }
        }
    }
    // cout << clientsNamesStr;
    // cout << ")" << endl;
    if (userStr.find(' ')) {
        for (int i = 0; i < userStr.length(); i++)
        {
            if (userStr[i] == ' ')
            {
                userStr[i] = '_';
            } //also check for slashes
        }
        send(clientSocket, userStr.c_str(), userStr.length(), 0);
    }


    // set a username length max and detect if user already exists
    // if (clientUsernames.size() != 1 || clientUsernames.size() != 0)
    // {
    //     if (clientUsernames.size() > 0)
    //     {
    //         if (std::find(clientUsernames.begin(), clientUsernames.end(), userStr) != clientUsernames.end())
    //         {
    //             std::cout << "2 clients of the same username detected" << endl;
    //             std::cout << "Client Username vector size: " << clientUsernames.size() << endl;
    //             std::cout << "New user entered name that already exists. Kicking..." << endl;
    //             send(clientSocket, exists.data(), sizeof(exists), 0);
    //             std::lock_guard<std::mutex> lock(clientsMutex);
    //             std::cout << "Starting deletion of user socket" << endl;
    //             auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
    //             connectedClients.erase(it, connectedClients.end());
    //             std::cout << "Removed client socket from vector" << endl; // probnably getting a segmentation fault because of deletion of client socket before userename making it non accessable
    //             // std::lock_guard<std::mutex> lock(clientsMutex);

    //             // for(int i=clientsNamesStr.length();i<0;i--){
    //             // if(clientsNamesStr.find())
    //             // }

    //             close(clientSocket);
    //         }
    //     }
    // }

    // cout << "Connected clients: (";// (sopsijs,SOMEONE,ssjss,)
    // cout << clientsNamesStr;
    // cout << ")" << endl;

    if (userStr.empty()) {
        close(clientSocket);
        cout << "Closed client username empty" << endl;
    }

    else {
        clientUsernames.push_back(userStr); //first user index is 0 and the size is going to be 1 right here
        // clientUsernames.push_back(userStr);
        cout << "username added to client vector usernames" << endl;
        // cout << connectedClients[0] << endl;
        //send pub key
        updateActiveFile(clientUsernames.size());
        // userAndClSocket[userStr + to_string(clientUsernames.size() - 1)] = clientSocket; //clientUsernames.size() - 1 should give us the index of the user that just joined the index for user 1 would be 0
        cout << "client SIZE: " << clientUsernames.size() << endl;

        Send usersactive;
        //send the active users txt file to client
        std::vector<uint8_t> activeBuf = usersactive.readFile("usersActive.txt"); //file path is a string to the file path
        std::string ed = usersactive.b64EF(activeBuf);
        //encrypt the file using the public key of client socket 
        usersactive.sendBase64Data(clientSocket, ed);

        std::string joinMsg = fmt::format("{} has joined the chat", userStr);
        string lenOfUser;
        std::string userJoinMsg = fmt::format("You have joined the chat as {}\n", userStr); // limit of string?????

        const string only = "\nYou are the only user in this chat you cannot send messages until another user joins";

        string pub = fmt::format("keys-server/{}-pubkeyserver.der", userStr);

        // recvServer(pub);
        //recieve the pub key file from the client and save it
        Recieve pubrecvserver;

        static string serverRecv;

        if (clientUsernames.size() == 1) {
            serverRecv = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", userStr);
        }
        else if (clientUsernames.size() > 1) {
            serverRecv = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[1]);
        }
        // cout << "starting encoded data" << endl;
        // cout << "done encoded data" << endl;
        // cout << "SERVERECV PATH: " << serverRecv << endl;
        // cout << "gonna save file" << endl;
        // cout << "decoded writing: " << decodedData.data() << endl;
        // std::ofstream pubcheck(serverRecv, std::ios::binary);
        std::string encodedData = pubrecvserver.receiveBase64Data(clientSocket);
        std::vector<uint8_t> decodedData = pubrecvserver.base64Decode(encodedData);
        pubrecvserver.saveFile(serverRecv, decodedData);

        static const string messagetouseraboutpub = "Public key that you sent to server cannot be loaded on server";
        if (is_regular_file(serverRecv)) {
            cout << "public key exists" << endl;
            LoadKey loadpub;
            if (!loadpub.loadPub(serverRecv)) {
                cout << "CANNOT LOAD USER PUB KEY. KICKING" << endl;
                send(clientSocket, messagetouseraboutpub.data(), messagetouseraboutpub.length(), 0);
                close(clientSocket);
            } //test load the key
        }
        else {
            cout << "PUBLIC KEY FILE DOES NOT EXIST" << endl;
            send(clientSocket, messagetouseraboutpub.data(), messagetouseraboutpub.length(), 0);
            close(clientSocket);
        }
        // if (!pubcheck.is_open())
        // {
        // throw std::runtime_error("Could not open file to write");
        // }
        // else{
        // cout << "KEY FILE RECIEVED OPENED" << endl;
        // pubcheck.close();
        // }

        cout << "recv" << endl;
        cout << "Encoded key: " << encodedData << endl;


        //file paths
        string sendToClient2 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[0]); //this path is to send the pub key of client 1 to the client that connects 
        string clientSavePathAs = fmt::format("keys-from-server/{}-pubkeyfromserver.der", clientUsernames[0]);
        // string sendToClient1 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[1]); //file path of client 2 pub key | segmentation fault 
        // string client1toSavePathAs;

        // string fir = fmt::format("keys-server/{}-pubkeyserver.der", clientUsernames[0]);
        // string sec = fmt::format("keys-server/{}-pubkeyserver.der", userStr); //change userstr to new user without segmentation fault

        // string firSend = fmt::format("keys-server/{}-pubkeyserverfromser.der", clientUsernames[0]);

        //send file name to client
        Send sendtoclient;

        const string con = fmt::format("\nUsers connected: {}\n", clientUsernames.size());
        if (clientUsernames.size() == 2) {
            std::cout << fmt::format("sending {} from user {} to user {}", sendToClient2, clientUsernames[0], userStr) << endl;
            //send the file path to save as on client side
            send(clientSocket, clientSavePathAs.data(), clientSavePathAs.length(), 0);
            cout << "sleeping 1 sec" << endl;
            // sleep(1); //dont gotta wait a sec no more
            // sendFile(fir);//this works for the second user only so make it also work for user 1
            std::vector<uint8_t> fi = sendtoclient.readFile(sendToClient2); //file path is a string to the file path
            std::string encodedData = sendtoclient.b64EF(fi);
            sendtoclient.sendBase64Data(clientSocket, encodedData); //send encoded key

            // char buf1[8] = { 0 };
            // ssize_t bt = recv(clientSocket, buf1, sizeof(buf1) - 1, 0);
            // buf1[bt] = '\0';
            // std::string ms1(buf1);
            // cout << "client 2 ms is: " << ms1 << endl;
        }
        else if (clientUsernames.size() == 1) {
            // send(clientSocket, con.c_str(), con.length(), 0);
            // send(clientSocket, only.c_str(), only.length(), 0);
            cout << "waiting for another client to connect to continue" << endl;
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                if (connectedClients[0] != clientSocket) {
                    cout << "Client one left. Killing server." << endl;
                    close(serverSocket);
                    exit(1); //not working cuz the client socket is still in the vector when they leave the chat init
                }
                else if (clientUsernames.size() > 1 && connectedClients[0] == clientSocket) {
                    cout << "Another user connected, proceeding..." << endl;
                    break;
                }
            }
            // string sec = fmt::format("keys-server/{}-pubkeyserver.der", clientUsernames[1]); //change userstr to new user without segmentation fault | fixed //second client sending the pub key to the first client
            if (clientUsernames.size() == 2) {
                string client1toSavePathAs = fmt::format("keys-from-server/{}-pubkeyfromserver.der", clientUsernames[1]); //file path client 1 needs to save as

                cout << fmt::format("sending to user 1: {}", client1toSavePathAs) << endl;
                //sending the file name to save as for client side
                send(clientSocket, client1toSavePathAs.data(), client1toSavePathAs.length(), 0);
            }
            cout << "SENDING TO CLIENT 1" << endl;
            sleep(1); //gets connection error if dont sleep for 1s because server not ready yet
            // sendFile(sec);
            string sendToClient1 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[1]);
            std::vector<uint8_t> fi2 = sendtoclient.readFile(sendToClient1); //file path is a string to the file path //error when reading the file
            std::string encodedDataClient = sendtoclient.b64EF(fi2);
            sendtoclient.sendBase64Data(clientSocket, encodedDataClient); //send encoded key
            cout << "file to CLIENT 1 SENT" << endl;
            // char buf2[8] = { 0 };
            // ssize_t bt2 = recv(clientSocket, buf2, sizeof(buf2) - 1, 0);
            // buf2[bt2] = '\0';
            // std::string ms2(buf2);
            // cout << "client 1 ms is: " << ms2 << endl;
            // send(clientSocket, userJoinMsg.data(), userJoinMsg.length(), 0);
            // broadcastMessage(joinMsg, clientSocket);
        }
        // send(clientSocket, userJoinMsg.data(), userJoinMsg.length(), 0);
        // broadcastMessage(joinMsg, clientSocket);

        // string newSecSend = fmt::format("keys-server/{}-pubkeyserver.der", clientUsernames[1]);
        // //check if port file server was on is still on if so send the file to it
        // int PORT; 
        std::cout << "for join" << endl;
        for (int i = 0; i < clientUsernames.size(); i++)
        {
            if (clientUsernames[i] == userStr)
            {
                std::cout << "i: " << clientUsernames[i] << endl;
                lenOfUser.append(clientUsernames[i]);
            }
        }
        std::cout << "LENGTH OF USER: " << lenOfUser.length() << endl;
        std::cout << "LENGTH OF USERSTR: " << userStr.length() << endl;
        std::cout << "------------" << endl;

        // update clients to print
        clientsNamesStr = countUsernames(clientsNamesStr);

        std::cout << "Connected clients: ("; // (sopsijs,SOMEONE,ssjss,)
        std::cout << clientsNamesStr;
        std::cout << ")" << endl;


        std::cout << "Client Username vector size: " << clientUsernames.size() << endl;
        std::cout << "------------" << endl;

        bool isConnected = true;

        // if (clientUsernames.size() > 1) {
        // string ms = "";

        //add join messages somewhere
        //also send the username and time of the message attached to the message by delimeters | done

        while (isConnected) {
            //gonna iterate in infinitly

            // if (clientUsernames.size() > 1) {
            // send(clientSocket, only.c_str(), only.length(), 0);

            // }
            bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (bytesReceived <= 0 || strcmp(buffer, "quit") == 0) { //the quit word is useless because the quit message doesnt get sent to the user
                isConnected = false;
                {
                    std::lock_guard<std::mutex> lock(clientsMutex);
                    std::cout << fmt::format("User client socket deletion: BEFORE: {}", connectedClients.size()) << endl;
                    auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
                    connectedClients.erase(it, connectedClients.end());
                    std::cout << fmt::format("User client socket deleted: AFTER: {}", connectedClients.size()) << endl;
                    std::cout << "------------" << endl;
                    std::cout << fmt::format("{} has left the chat", userStr) << endl;
                    // erase username
                }

                std::string exitMsg = fmt::format("{} has left the chat", userStr);
                LoadKey loadkeyandsend;
                if (clientUsernames[0] == userStr) {
                    int index = 0 + 1;
                    string pathpub = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[index]);
                    string op64 = loadkeyandsend.loadPubAndEncrypt(pathpub, exitMsg);
                    cout << "UPDATED OP64: " << op64 << endl;
                    if (lenOfUser.length() == userStr.length() && lenOfUser == userStr && op64 != "err") {
                        broadcastMessage(op64, clientSocket);
                    }
                }

                else if (clientUsernames[1] == userStr) {
                    int index2 = 1 - 1;
                    string pathpub2 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[index2]);
                    string op642 = loadkeyandsend.loadPubAndEncrypt(pathpub2, exitMsg);
                    cout << "UPDATED OP642: " << op642 << endl;
                    if (lenOfUser.length() == userStr.length() && lenOfUser == userStr && op642 != "err") {
                        // send(connectedClients[index2], op642.c_str(), op642.length(), 0);
                        broadcastMessage(op642, clientSocket);
                    }
                }
                // std::cout << exitMsg << std::endl;
                std::cout << "------------" << endl;
                // add if statment if useerrname of user isnt in vector twice
                auto user = find(clientUsernames.rbegin(), clientUsernames.rend(), userStr);
                if (user != clientUsernames.rend()) {
                    clientUsernames.erase((user + 1).base());
                }
                updateActiveFile(clientUsernames.size());
                std::cout << "Clients connected: (" << countUsernames(clientsNamesStr) << ")" << endl;
                std::cout << fmt::format("Clients in chat: {} ", clientUsernames.size()) << endl;
                cout << "Deleting user pubkey" << endl;
                string pubfiletodel = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", userStr);

                remove(pubfiletodel);
                if (!is_regular_file(pubfiletodel)) { // if pub file doesnt exist
                    cout << fmt::format("client pubkey file ({}) has been deleted", pubfiletodel) << endl;
                }
                else if (is_regular_file(pubfiletodel)) {
                    cout << "client pub key file could not be deleted" << endl;
                }

                // string lenOfUser;
                if (clientUsernames.size() < 1) {
                    close(serverSocket);
                    delIt("server-recieved-client-keys");
                    exit(1);
                }

                // else {
                //     // cout << fmt::format("Clients connected: ({})", clientsNamesStr) << endl;
                //     std::cout << "Disconnected client with same username" << endl;
                //     close(clientSocket);
                // }
                lenOfUser.clear();
                // last execution of username exists
            }

            else {
                buffer[bytesReceived] = '\0';
                std::string receivedData(buffer);
                // cout << "______________________________" << endl;
                std::cout << "Received data: " << receivedData << std::endl;
                // cout << "______________________________" << endl;
                cout << "ciphertext length on server: " << receivedData.length() << endl;
                std::string cipherText = receivedData; //fix server shutdown

                // string newenc = benc(newdec);
                // cout << "mem addr of recieveddata: " << &receivedData << endl;

                if (!cipherText.empty() && cipherText.length() > 30) { //when sneing somehow losig data when sending | fixed //this may be a problem to why the message is being sent like weirdly
                    // cout << "cipher: " << cipherText << endl;;
                    //time
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
                    string formattedCipher = userStr + "|" + stringFormatTime + "|" + cipherText;
                    broadcastMessage(formattedCipher, clientSocket);
                }
            }
        }
    }
}

int main() {
    // int* pn = 0;
    static const string path = "server-recieved-client-keys";
    signal(SIGINT, signalHandleServer);
    unordered_map <int, string> serverHash;
    initMenu startMenu;
    const string hash = startMenu.initmenu(serverHash);
    if (!hash.empty()) { //if hash isnt empty
        serverHash[1] = hash;
    }

    string pnStr;
    int pnInt;
    ifstream pn("pn.txt");
    getline(pn, pnStr);
    istringstream(pnStr) >> pnInt;

    cout << "pnInt is: " << pnInt << endl;

    // createDir(path);

    unsigned short PORT = 8080; //defualt port is set at 8080

    thread t1([&]()
        {
            if (isPav(PORT) == false) {
                cout << fmt::format("Port {} is not usable searching for port to use..", PORT) << endl;
                for (unsigned short i = 49152; i <= 65535; i++) {
                    if (isPav(i) != false) {
                        PORT = i;
                        break;
                    }
                }
            }
        }
    );

    t1.join();

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (serverSocket < 0)
    {
        std::cerr << "Error opening server socket" << std::endl;
        return 1;
    }

    sockaddr_in serverAddress;
    int opt = 1;

    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0)
    {
        cout << "Chosen port isn't available. Killing server" << endl;
        close(serverSocket);
        exit(true);
    }

    listen(serverSocket, 5);
    std::cout << fmt::format("Server listening on port {}", PORT) << "\n";
    uint8_t clientHashi = 0;

    while (true)
    {
        sockaddr_in clientAddress;
        socklen_t clientLen = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientLen);


        string pnS = "1";
        string pnO = "2";
        const string passwordGet = "This server is password protected. Enter the password to join: ";
        const string notVerified = "Wrong password. You have been kicked.#N";
        const string verified = "You have joined the server#V";
        string passGetArg = "";

        if (pnInt == 1) {
            cout << "sending pass verify" << endl;
            send(clientSocket, pnS.c_str(), pnS.length(), 0);
            send(clientSocket, passwordGet.c_str(), passwordGet.length(), 0);

            char passBuf[200] = { 0 };
            ssize_t passBytes = recv(clientSocket, passBuf, sizeof(passBuf) - 1, 0);
            passBuf[passBytes] = '\0';
            std::string passGet(passBuf);
            passGetArg += passGet;
            //compare the password the user entered to the hash of the server password
            cout << "userp: " << bcrypt::generateHash(passGet) << endl;
            cout << "serverp: " << serverHash[1] << endl;
            if (bcrypt::validatePassword(passGet, serverHash[1]) == 1) { //bcrypt::validatePassword(passGet, serverHash[1]) == 1
                send(clientSocket, verified.c_str(), verified.length(), 0);
                // cout << "stored client hash in clienthash umap" << endl;
                cout << "user verified" << endl;
            }
            else {
                send(clientSocket, notVerified.c_str(), notVerified.length(), 0);
                sleep(1);
                close(clientSocket);
                cout << "user not verified. kicked." << endl;
            }
        }
        else if (pnInt == 2) {
            send(clientSocket, pnO.c_str(), pnO.length(), 0);
        }

        thread(handleClient, clientSocket, serverSocket, serverHash, notVerified, passGetArg).detach();
    }

    close(serverSocket);
    return 0;
}
