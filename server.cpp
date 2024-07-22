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
// #include "headers/core.h"
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

#define RED_TEXT "\033[31m" // red text color
#define GREEN_TEXT "\033[32m" // green text color
#define BRIGHT_BLUE_TEXT "\033[94m" // bright blue text color
#define RESET_TEXT "\033[0m" // reset color to default

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

int itVec(const string& username, vector <string>& vec) {
    int i = 0;
    for (auto& it : vec) {
        i++;
        if (it == username) {
            return i - 1;
        }
    }
    return -1;
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

void handleClient(int clientSocket, int serverSocket) {
    string clientsNamesStr = "";
    {
        lock_guard<mutex> lock(clientsMutex);
        connectedClients.push_back(clientSocket);
    }

    char buffer[4096] = { 0 };
    ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    buffer[bytesReceived] = '\0';
    std::string userStr(buffer);

    int index = userStr.find("|");
    string pubkeyseri = userStr.substr(index + 1);
    userStr = userStr.substr(0, index);

    uint8_t limOfUsers = 3;

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

    if (userStr.empty()) {
        close(clientSocket);
        cout << "Closed client username empty" << endl;
    }

    else {
        clientUsernames.push_back(userStr); //first user index is 0 and the size is going to be 1 right here
        cout << "username added to client vector usernames" << endl;
        updateActiveFile(clientUsernames.size());
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

        // static ;

        // string nametosave = "";

        string serverRecv = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", userStr); //the name to save the pub key file as should be the username of the user
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

        cout << "recv" << endl;
        cout << "Encoded key: " << encodedData << endl;


        //send file name to client
        Send sendtoclient;
        string sendToClient2 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[0]); //this path is to send the pub key of client 1 to the client that connects 
        string clientSavePathAs = fmt::format("keys-from-server/{}-pubkeyfromserver.der", clientUsernames[0]);

        const string con = fmt::format("\nUsers connected: {}\n", clientUsernames.size());
        if (clientUsernames.size() > 1) {
            if (clientUsernames.size() == 3) {
                string sendToClient3 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[1]);
                string clientSavePathAs3 = fmt::format("keys-from-server/{}-pubkeyfromserver.der", clientUsernames[1]);
                std::cout << fmt::format("sending {} from user {} to user {}", sendToClient3, clientUsernames[1], userStr) << endl;
                send(clientSocket, clientSavePathAs3.data(), clientSavePathAs3.length(), 0);
                std::vector<uint8_t> fi3 = sendtoclient.readFile(sendToClient3); //file path is a string to the file path
                std::string encodedData3 = sendtoclient.b64EF(fi3);
                sendtoclient.sendBase64Data(clientSocket, encodedData3); //send encoded key

                sleep(1);
                //---------

                string sendToClient4 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[0]);
                string clientSavePathAs4 = fmt::format("keys-from-server/{}-pubkeyfromserver.der", clientUsernames[0]);
                std::cout << fmt::format("sending {} from user {} to user {}", sendToClient2, clientUsernames[0], userStr) << endl;
                send(clientSocket, clientSavePathAs4.data(), clientSavePathAs4.length(), 0);

                std::vector<uint8_t> fi4 = sendtoclient.readFile(sendToClient2);
                std::string encodedData2 = sendtoclient.b64EF(fi4);
                sendtoclient.sendBase64Data(clientSocket, encodedData2);

            }
            else if (clientUsernames.size() == 2) {
                std::cout << fmt::format("sending {} from user {} to user {}", sendToClient2, clientUsernames[0], userStr) << endl;
                send(clientSocket, clientSavePathAs.data(), clientSavePathAs.length(), 0);
                std::vector<uint8_t> fi = sendtoclient.readFile(sendToClient2); //file path is a string to the file path
                std::string encodedData = sendtoclient.b64EF(fi);
                sendtoclient.sendBase64Data(clientSocket, encodedData); //send encoded key
            }
        }
        else if (clientUsernames.size() == 1) {
            cout << "waiting for another client to connect to continue" << endl;
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                if (clientUsernames.size() > 1) {
                    cout << "Another user connected, proceeding..." << endl;
                    break;
                }
            }


            if (clientUsernames.size() == 2) {
                string client1toSavePathAs = fmt::format("keys-from-server/{}-pubkeyfromserver.der", clientUsernames[1]); //file path client 1 needs to save as

                cout << fmt::format("sending to user 1: {}", client1toSavePathAs) << endl;
                //sending the file name to save as for client side
                send(clientSocket, client1toSavePathAs.data(), client1toSavePathAs.length(), 0);
                cout << "SENDING TO CLIENT 1" << endl;
                sleep(1); //gets connection error if dont sleep for 1s because server not ready yet
                // sendFile(sec);
                string sendToClient1 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[1]);
                std::vector<uint8_t> fi2 = sendtoclient.readFile(sendToClient1); //file path is a string to the file path //error when reading the file
                std::string encodedDataClient = sendtoclient.b64EF(fi2);
                sendtoclient.sendBase64Data(clientSocket, encodedDataClient); //send encoded key
                cout << "file to CLIENT 1 SENT" << endl;
            }
            else if (clientUsernames.size() == 3) {
                string client1toSavePathAs = fmt::format("keys-from-server/{}-pubkeyfromserver.der", clientUsernames[1]); //file path client 1 needs to save as
                cout << fmt::format("sending to user 1: {}", client1toSavePathAs) << endl;
                //sending the file name to save as for client side
                send(clientSocket, client1toSavePathAs.data(), client1toSavePathAs.length(), 0);
                cout << "SENDING TO CLIENT 1" << endl;
                sleep(1); //gets connection error if dont sleep for 1s because server not ready yet
                // sendFile(sec);
                string sendToClient1 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[1]);
                std::vector<uint8_t> fi2 = sendtoclient.readFile(sendToClient1); //file path is a string to the file path //error when reading the file
                std::string encodedDataClient = sendtoclient.b64EF(fi2);
                sendtoclient.sendBase64Data(clientSocket, encodedDataClient); //send encoded key
                cout << "file to CLIENT 1 SENT" << endl;
                //-----------------------


                string client1toSavePathAs3 = fmt::format("keys-from-server/{}-pubkeyfromserver.der", clientUsernames[2]); //file path client 1 needs to save as
                cout << fmt::format("sending to user 1: {}", client1toSavePathAs3) << endl;
                //sending the file name to save as for client side
                send(clientSocket, client1toSavePathAs3.data(), client1toSavePathAs3.length(), 0);
                cout << "SENDING TO CLIENT 1" << endl;
                sleep(1); //gets connection error if dont sleep for 1s because server not ready yet
                // sendFile(sec);

                string sendToClient1_3 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[2]);
                std::vector<uint8_t> fi4 = sendtoclient.readFile(sendToClient1_3); //file path is a string to the file path //error when reading the file
                std::string encodedDataClient2 = sendtoclient.b64EF(fi4);
                sendtoclient.sendBase64Data(clientSocket, encodedDataClient2); //send encoded key
                cout << "file to CLIENT 1 SENT" << endl;
            }
        }
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

        while (isConnected) {
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

                if (clientUsernames.size() < 3) {
                    if (clientUsernames[0] == userStr) {
                        int index = 1 + 0;
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
                }

                else if (clientUsernames.size() == 3) {
                    if (clientUsernames[0] == userStr) {
                        int index = 1 + 0;
                        string pathpub = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[index]);
                        string op64 = loadkeyandsend.loadPubAndEncrypt(pathpub, exitMsg);
                        cout << "UPDATED OP64: " << op64 << endl;
                        if (lenOfUser.length() == userStr.length() && lenOfUser == userStr && op64 != "err") {
                            send(connectedClients[index], op64.c_str(), op64.length(), 0);
                        }
                        //---------------
                        string pathpub2 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[index + 1]);
                        string op642 = loadkeyandsend.loadPubAndEncrypt(pathpub2, exitMsg);
                        cout << "UPDATED OP64: " << op642 << endl;
                        if (lenOfUser.length() == userStr.length() && lenOfUser == userStr && op642 != "err") {
                            send(connectedClients[index + 1], op642.c_str(), op642.length(), 0);
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
                        //-------------------------------
                        string pathpub3 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[index + 2]);
                        string op643 = loadkeyandsend.loadPubAndEncrypt(pathpub3, exitMsg);
                        cout << "UPDATED OP64: " << op643 << endl;
                        if (lenOfUser.length() == userStr.length() && lenOfUser == userStr && op643 != "err") {
                            send(connectedClients[index + 2], op643.c_str(), op643.length(), 0);
                        }
                    }
                    else if (clientUsernames[2] == userStr) {
                        int index2 = 2 - 1;
                        string pathpub2 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[index2]);
                        string op642 = loadkeyandsend.loadPubAndEncrypt(pathpub2, exitMsg);
                        cout << "UPDATED OP642: " << op642 << endl;
                        if (lenOfUser.length() == userStr.length() && lenOfUser == userStr && op642 != "err") {
                            // send(connectedClients[index2], op642.c_str(), op642.length(), 0);
                            broadcastMessage(op642, clientSocket);
                        }
                        //-------------------------------
                        //for 1st user
                        string pathpub4 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[index - 1]);
                        string op644 = loadkeyandsend.loadPubAndEncrypt(pathpub4, exitMsg);
                        cout << "UPDATED OP64: " << op644 << endl;
                        if (lenOfUser.length() == userStr.length() && lenOfUser == userStr && op644 != "err") {
                            send(connectedClients[index - 1], op644.c_str(), op644.length(), 0);
                        }
                    }
                }


                // else if (clientUsernames[2] == userStr) {
                //     int index3 = 2; //for user pub key
                //     string pathpub2 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[index3]);
                //     string op643 = loadkeyandsend.loadPubAndEncrypt(pathpub2, exitMsg);
                //     cout << "UPDATED OP642: " << op643 << endl;
                //     if (lenOfUser.length() == userStr.length() && lenOfUser == userStr && op643 != "err") {
                //         // send(connectedClients[index2], op642.c_str(), op642.length(), 0);
                //         broadcastMessage(op643, clientSocket);
                //     }
                // }
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
                lenOfUser.clear();
            }
            // }

            else {
                buffer[bytesReceived] = '\0';
                std::string receivedData(buffer);
                // cout << "______________________________" << endl;
                std::cout << "Received data: " << receivedData << std::endl;

                //CHECK THE END USING SUBSTR TO CUT IT AND SEE WHO IT BELONGS TOO
                // cout << "______________________________" << endl;
                cout << "ciphertext length on server: " << receivedData.length() << endl;
                std::string cipherText = receivedData; //fix server shutdown

                if (!cipherText.empty() && cipherText.length() > 30) { //when sneing somehow losig data when sending | fixed //this may be a problem to why the message is being sent like weirdly
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
    static const string path = "server-recieved-client-keys";
    if (!exists(path)) {
        createDir(path);
    }
    else {
        delIt(path);
    }

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

    std::ofstream file("PORT.txt");
    if (file.is_open())
    {
        file << PORT;
        file.close();
    }
    else
    {
        std::cout << "Warning: cannot write port to file. You may need to configure clients port manually\n";
    }

    listen(serverSocket, 5);
    std::cout << fmt::format("Server listening on port {}", PORT) << "\n";

    while (true)
    {
        sockaddr_in clientAddress;
        socklen_t clientLen = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientLen);

        std::thread(handleClient, clientSocket, serverSocket).detach();
    }

    //delete all keys from key recieves in server
    // auto dirIter = std::filesystem::directory_iterator("keys-server");
    // int fileCount = 0;

    // for (auto& entry : dirIter)
    // {
    // if (entry.is_regular_file())
    // {
    // std::filesystem::remove(entry);
    // ++fileCount;
    // }
    // }
    // cout << "file count is: " << fileCount << endl;


    close(serverSocket);
    return 0;
}
