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
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <sstream>
#include <boost/asio.hpp>
#include <ctime>
#include <chrono>
#include <regex>
#include <stdlib.h>
#include <unistd.h>
#include <filesystem>
#include "serverSendRecv.h"

// add certain length of username allow only

// To run: g++ -std=c++20 -o server server.cpp -lcryptopp -lfmt

#define RED_TEXT "\033[31m"         // red text color
#define GREEN_TEXT "\033[32m"       // green text color
#define BRIGHT_BLUE_TEXT "\033[94m" // bright blue text color
#define RESET_TEXT "\033[0m"        // reset color to default

using boost::asio::ip::tcp;

using namespace std;
using namespace CryptoPP;
using namespace std::chrono;

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

static std::vector<uint8_t> base64Decode(const std::string& encodedData)
{
    std::vector<uint8_t> decoded;
    CryptoPP::StringSource ss(encodedData, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::VectorSink(decoded)));
    return decoded;
}

static void saveFile(const std::string& filePath, const std::vector<uint8_t>& buffer)
{
    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open file to write");
    }

    file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    if (!file)
    {
        throw std::runtime_error("Error writing to file");
    }
}
static std::string receiveBase64Data(int clientSocket)
{
    std::vector<char> buffer(4096);
    std::string receivedData;
    ssize_t bytesRead = recv(clientSocket, buffer.data(), buffer.size(), 0);

    while (bytesRead > 0) //its gonna keep appending without a stop condition
    {
        cout << "Bytes read: " << bytesRead << endl;
        receivedData.append(buffer.data(), bytesRead);
        if (receivedData.size() == bytesRead) {
            break;
        }
    }
    cout << "RECIEVED DATA: " << receivedData.size() << endl;
    cout << "BYTES READ: " << bytesRead << endl;

    if (bytesRead == -1)
    {
        throw std::runtime_error("Error receiving data");
    }

    return receivedData;
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
//     {
//         lock_guard<mutex> lock(clientsMutex);
//         for (int clientSocket : connectedClients)
//         {
//             if (clientSocket == senderSocket) {
//                 continue;
//             }
//             else if (clientSocket != senderSocket)
//             {
//                 //send file to all clients but the sender
//                 sendFile(filename);
//             }
//         }
//     }
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

string countUsernames(string clientsNamesStr)
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
//     int PORT;
//     string portfile = "FILEPORT.TXT";
//     ifstream fileport(portfile);
//     if (!fileport.is_open()) {
//         cerr << "Could not open port file" << endl;
//         return 0;
//     }
//     string PORTSTR;
//     getline(fileport, PORTSTR);
//     istringstream(PORTSTR) >> PORT;
//     return PORT;
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

void handleClient(int clientSocket)
{
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

    // clientsNamesStr = countUsernames(clientsNamesStr); //something is being added making the vecotr 2
    // cout << "Connected clients: (";// (sopsijs,SOMEONE,ssjss,)
    // cout << clientsNamesStr;
    // cout << ")" << endl;
    if (userStr.find(' '))
    {
        for (int i = 0; i < userStr.length(); i++)
        {
            if (userStr[i] == ' ')
            {
                userStr[i] = '_';
            }
        }
        send(clientSocket, userStr.c_str(), userStr.length(), 0);
    }

    const string exists = "\nUsername already exists. You are being kicked.";
    // set a username length max and detect if user already exists
    if (clientUsernames.size() != 1 || clientUsernames.size() != 0)
    {
        if (clientUsernames.size() > 0)
        {
            if (std::find(clientUsernames.begin(), clientUsernames.end(), userStr) != clientUsernames.end())
            {
                std::cout << "2 clients of the same username detected" << endl;
                std::cout << "Client Username vector size: " << clientUsernames.size() << endl;
                std::cout << "New user entered name that already exists. Kicking..." << endl;
                send(clientSocket, exists.data(), sizeof(exists), 0);
                std::lock_guard<std::mutex> lock(clientsMutex);
                std::cout << "Starting deletion of user socket" << endl;
                auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
                connectedClients.erase(it, connectedClients.end());
                std::cout << "Removed client socket from vector" << endl; // probnably getting a segmentation fault because of deletion of client socket before userename making it non accessable
                // std::lock_guard<std::mutex> lock(clientsMutex);

                // for(int i=clientsNamesStr.length();i<0;i--){
                //     if(clientsNamesStr.find())
                // }

                close(clientSocket);
            }
        }
    }

    // cout << "Connected clients: (";// (sopsijs,SOMEONE,ssjss,)
    // cout << clientsNamesStr;
    // cout << ")" << endl;

    if (userStr.empty())
    {
        close(clientSocket);
    }

    else
    {
        clientUsernames.push_back(userStr);
        // clientUsernames.push_back(userStr);
        cout << "username added to client vector usernames" << endl;
        cout << connectedClients[0] << endl;
        //send pub key
        updateActiveFile(clientUsernames.size());
        cout << "client SIZE: " << clientUsernames.size() << endl;

        Send usersactive;
        //send the active users txt file to client
        std::vector<uint8_t> activeBuf = usersactive.readFile("usersActive.txt"); //file path is a string to the file path
        std::string ed = usersactive.b64EF(activeBuf);
        usersactive.sendBase64Data(clientSocket, ed);

        std::string joinMsg = fmt::format("{} has joined the chat", userStr);
        string lenOfUser;
        std::string userJoinMsg = fmt::format("You have joined the chat as {}\n", userStr); // limit of string?????

        const string only = "\nYou are the only user in this chat you cannot send messages until another user joins";

        string pub = fmt::format("keys-server/{}-pubkeyserver.der", userStr);

        // recvServer(pub);
        //recieve the pub key file from the client and save it
        cout << "starting encoded data" << endl;
        std::string encodedData = receiveBase64Data(clientSocket);
        cout << "done encoded data" << endl;
        std::vector<uint8_t> decodedData = base64Decode(encodedData);
        string serverRecv = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", userStr);
        cout << "gonna save file" << endl;
        saveFile(serverRecv, decodedData);
        cout << "recv" << endl;
        cout << "Encoded data recieved is: " << encodedData << endl;


        //file paths
        string sendToClient2 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[0]); //this path is to send the pub key of client 1 to the client that connects 
        string clientSavePathAs = fmt::format("client-saved-from-server/{}-pubkeyfromserver.der", clientUsernames[0]);
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
            send(clientSocket, clientSavePathAs.data(), clientSavePathAs.length(), 0); //problem was with length calculations
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
                if (clientUsernames.size() > 1) {
                    cout << "Another user connected, proceeding..." << endl;
                    break;
                }
            }
            // string sec = fmt::format("keys-server/{}-pubkeyserver.der", clientUsernames[1]); //change userstr to new user without segmentation fault | fixed //second client sending the pub key to the first client
            if (clientUsernames.size() == 2) {
                string client1toSavePathAs = fmt::format("server-recieved-client-keys/{}-pubkeyfromserver.der", clientUsernames[1]); //file path client 1 needs to save as

                cout << fmt::format("sending to user 1: {}", client1toSavePathAs) << endl;
                //sending the file name to save as for client side
                send(clientSocket, client1toSavePathAs.data(), client1toSavePathAs.length(), 0); //problem was with length calculations | fixed
            }
            cout << "SENDING TO CLIENT 1" << endl;
            sleep(1); //gets connection error if dont sleep for 1s because server not ready yet
            // sendFile(sec);
            string sendToClient1 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[1]);
            std::vector<uint8_t> fi2 = sendtoclient.readFile(sendToClient1); //file path is a string to the file path
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
        // string portfile = "FILEPORT.TXT";
        // sleep(1); //actually no need for chrono just use sleep
        // ifstream fileport(portfile);
        // if (!fileport.is_open()) {
        //     cerr << "Could not open port file" << endl;
        //     return;
        // }
        // string PORTSTR;
        // getline(fileport, PORTSTR);
        // istringstream(PORTSTR) >> PORT;

        // cout << "starting check of ports open" << endl;
        // cout << "original port is " << PORT << endl;
        // updatePort(PORT + 1); // check a different way

        // cout << "gonna send file " << newSecSend << endl;
        // cout << "checking port " << PORT << endl;
        // // cout << fmt::format("pOPEN 1: {}", pOpen) << endl;
        // sleep(1); //gets connection error if dont sleep for 1s because server not ready yet
        // if (sendFile(newSecSend) == false) {
        //     updatePort(PORT - 1); // check a different
        //     int newp = showfp();
        //     cout << "checking port " << newp << endl;
        //     cout << fmt::format("pOPEN 2: {}", newp) << endl;
        //     if (sendFile(newSecSend) == false) { //if open check second port back
        //         cout << fmt::format("file server is not open on port {}", newp) << endl;
        //     }
        //     else {
        //         // updatePort(PORT );
        //         cout << "file to CLIENT 1 SENT (A2) on port " << newp << endl;
        //         //send file to client that has their opened port 
        //     }
        // }
        // else {
        //     cout << "file to CLIENT 1 SENT (A3) on port " << PORT << endl;
        //     // send file to client that has their opened port
        // }
        // else {
        //     // updatePort(PORT + 1);
        //     // //send file to client that has their opened port
        //     // cout << "SENDING TO CLIENT (A3)" << endl;
        //     // sleep(1); //gets connection error if dont sleep for 1s because server not ready yet
        //     // sendFile(newSecSend);
        //     cout << "file to CLIENT 1 SENT (A3) on port " << PORT << endl;
        // }
    // }

    // recvServer(pub);



    // string userName = userStr;

    // string some;

    // int counterUsers = 0;
    // thread t1([&]() {
    // });
    // t1.join(); 
    // check if username already exists if it does then kick them

        // broadcastMessage(joinMsg, clientSocket);

        bool isConnected = true;

        // if (clientUsernames.size() > 1) {
        // string ms = "";

        //add join messages somewhere
        //also send the username and time of the message attached to the message by delimeters | done

        while (isConnected)
        {
            //gonna iterate in infinitly

            // if (clientUsernames.size() > 1) {
            //     send(clientSocket, only.c_str(), only.length(), 0);

            // }
            bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (bytesReceived <= 0 || strcmp(buffer, "quit") == 0)
            {
                isConnected = false;
                {
                    // erase socket
                    std::lock_guard<std::mutex> lock(clientsMutex);
                    std::cout << fmt::format("User client socket deletion: BEFORE: {}", connectedClients.size()) << endl;
                    auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
                    connectedClients.erase(it, connectedClients.end());
                    std::cout << fmt::format("User client socket deleted: AFTER: {}", connectedClients.size()) << endl;
                    std::cout << "------------" << endl;
                    std::cout << fmt::format("{} has left the chat", userStr) << endl;
                    // erase username
                    auto user = find(clientUsernames.rbegin(), clientUsernames.rend(), userStr);
                    if (user != clientUsernames.rend()) {
                        clientUsernames.erase((user + 1).base());
                    }
                    std::cout << "Clients connected: (" << countUsernames(clientsNamesStr) << ")" << endl;
                    std::cout << fmt::format("Clients in chat: {} ", clientUsernames.size()) << endl;


                }

                std::string exitMsg = fmt::format("{} has left the chat", userStr);
                // std::cout << exitMsg << std::endl;
                std::cout << "------------" << endl;
                // add if statment if useerrname of user isnt in vector twice
                // string lenOfUser;
                if (lenOfUser.length() == userStr.length() && lenOfUser == userStr)
                {
                    updateActiveFile(clientUsernames.size());
                    broadcastMessage(exitMsg, clientSocket);
                }
                else
                {
                    // cout << fmt::format("Clients connected: ({})", clientsNamesStr) << endl;
                    std::cout << "Disconnected client with same username" << endl;
                    close(clientSocket);
                }
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
                // cout << "mem addr of recieveddata:  " << &receivedData << endl;

                if (!cipherText.empty()) //when sneing somehow losig data when sending | fixed
                {
                    // cout << "cipher: " << cipherText << endl;
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

int main()
{
    //delete all keys from key recieves in server
    auto dirIter = std::filesystem::directory_iterator("server-recieved-client-keys");
    auto keyit = std::filesystem::directory_iterator("client-saved-from-server");
    auto prvf = std::filesystem::directory_iterator("user-keys/prv");
    auto prvp = std::filesystem::directory_iterator("user-keys/pub");
    int fileCount = 0;
    int keyitcount = 0;
    int prvc = 0;
    int prvcp = 0;

    for (auto& entry : dirIter)
    {
        if (entry.is_regular_file())
        {
            std::filesystem::remove(entry);
            ++fileCount;
        }
    }

    for (auto& i : keyit)
    {
        if (i.is_regular_file())
        {
            std::filesystem::remove(i);
            ++keyitcount;
        }
    }

    for (auto& i : prvf)
    {
        if (i.is_regular_file())
        {
            std::filesystem::remove(i);
            ++prvc;
        }
    }

    for (auto& i : prvp)
    {
        if (i.is_regular_file())
        {
            std::filesystem::remove(i);
            ++prvcp;
        }
    }

    cout << "file count in server storage: " << fileCount + prvc + prvcp + keyitcount << endl;
    std::cout << "deleted all\n";

    unsigned short PORT = 8080;

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
            } });
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

                std::thread(handleClient, clientSocket).detach();
            }

            //delete all keys from key recieves in server
            // auto dirIter = std::filesystem::directory_iterator("keys-server");
            // int fileCount = 0;

            // for (auto& entry : dirIter)
            // {
            //     if (entry.is_regular_file())
            //     {
            //         std::filesystem::remove(entry);
            //         ++fileCount;
            //     }
            // }
            // cout << "file count is: " << fileCount << endl;


            close(serverSocket);
            return 0;
}