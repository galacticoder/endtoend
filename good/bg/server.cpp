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
#include <sstream>
#include <boost/asio.hpp>
#include <ctime>
#include <chrono>
#include <regex>
#include <stdlib.h>



//rsa implement later

// fix double message of user leaving chat later | fixed

// add certain length of username allow only

// To run: g++ -o server server.cpp -lcryptopp -lfmt

#define RED_TEXT "\033[31m"         // red text color
#define GREEN_TEXT "\033[32m"       // green text color
#define BRIGHT_BLUE_TEXT "\033[94m" // bright blue text color
#define RESET_TEXT "\033[0m"        // reset color to default

using boost::asio::ip::tcp;

using namespace std;
using namespace CryptoPP;
using namespace std::chrono;

vector<int> connectedClients;
vector<string> clientUsernames;
mutex clientsMutex;

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
                cout << "2 clients of the same username detected" << endl;
                cout << "Client Username vector size: " << clientUsernames.size() << endl;
                cout << "New user entered name that already exists. Kicking..." << endl;
                send(clientSocket, exists.data(), sizeof(exists), 0);
                std::lock_guard<std::mutex> lock(clientsMutex);
                cout << "Starting deletion of user socket" << endl;
                auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
                connectedClients.erase(it, connectedClients.end());
                cout << "Removed client socket from vector" << endl; // probnably getting a segmentation fault because of deletion of client socket before userename making it non accessable
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
        // string userName = userStr;
        std::string joinMsg = fmt::format("{} has joined the chat", userStr);

        std::string userJoinMsg = fmt::format("You have joined the chat as {}", userStr); // limit of string?????
        string lenOfUser;

        string some;

        // int counterUsers = 0;
        // thread t1([&]() {
        // });
        // t1.join();
        // check if username already exists if it does then kick them
        cout << "for join" << endl;
        for (int i = 0; i < clientUsernames.size(); i++)
        {
            if (clientUsernames[i] == userStr)
            {
                cout << "i: " << clientUsernames[i] << endl;
                lenOfUser.append(clientUsernames[i]);
            }
        }
        cout << "LENGTH OF USER: " << lenOfUser.length() << endl;
        cout << "LENGTH OF USERSTR: " << userStr.length() << endl;
        // username joined still prints out fix this later
        if (lenOfUser.length() == userStr.length() && lenOfUser == userStr) {
            send(clientSocket, userJoinMsg.data(), sizeof(userJoinMsg), 0);
            // send(clientSocket, userStr.data(), sizeof(userStr), 0);
            broadcastMessage(joinMsg, clientSocket);
            std::cout << joinMsg << endl; // only print out after evrything done
        }
        // cout << fmt::format("var userlen: BEFORE OP: {}", lenOfUser) << endl;
        // lenOfUser.clear();
        // cout << fmt::format("var userlen: AFTER OP: {}", lenOfUser) << endl;
        // add if statment
        cout << "------------" << endl;

        // update clients to print
        clientsNamesStr = countUsernames(clientsNamesStr);

        cout << "Connected clients: ("; // (sopsijs,SOMEONE,ssjss,)
        cout << clientsNamesStr;
        cout << ")" << endl;

        // start of non func version

        // for(int i=0; i < clientUsernames.size();++i){
        //     if(clientUsernames.size() >= 2){

        //     //for the last index dont print a comma
        //         clientsNamesStr.append(clientUsernames[i]+","); //find the userbname and the before start pos and after end pos should be a comma
        //     } else{
        //         clientsNamesStr.append(clientUsernames[i]);
        //     }
        // }
        // if(!clientsNamesStr.empty()){
        //     clientsNamesStr.pop_back();
        //     cout << clientsNamesStr;
        // }

        // cout << ")" << endl;
        // cout << fmt::format("Clients in chat: {} ", clientUsernames.size()) << endl;
        // end of non func version

        // add an if statment for condition if username doent exist

        cout << "Client Username vector size: " << clientUsernames.size() << endl;
        cout << "------------" << endl;
        // broadcastMessage(joinMsg, clientSocket);

        bool isConnected = true;

        while (isConnected)
        {
            bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (bytesReceived <= 0 || strcmp(buffer, "quit") == 0)
            {
                isConnected = false;
                {
                    // erase socket
                    std::lock_guard<std::mutex> lock(clientsMutex);
                    cout << fmt::format("User client socket deletion: BEFORE: {}", connectedClients.size()) << endl;
                    auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
                    connectedClients.erase(it, connectedClients.end());
                    cout << fmt::format("User client socket deleted: AFTER: {}", connectedClients.size()) << endl;
                    cout << "------------" << endl;
                    cout << fmt::format("{} has left the chat", userStr) << endl;
                    // erase username
                    auto user = find(clientUsernames.rbegin(), clientUsernames.rend(), userStr);
                    if (user != clientUsernames.rend()) {
                        clientUsernames.erase((user + 1).base());
                    }
                    cout << "Clients connected: (" << countUsernames(clientsNamesStr) << ")" << endl;
                    cout << fmt::format("Clients in chat: {} ", clientUsernames.size()) << endl;
                }

                std::string exitMsg = fmt::format("{} has left the chat", userStr);
                // std::cout << exitMsg << std::endl;
                cout << "------------" << endl;
                // add if statment if useerrname of user isnt in vector twice
                cout << "lenofuser: " << lenOfUser << endl;
                if (lenOfUser.length() == userStr.length() && lenOfUser == userStr)
                {
                    broadcastMessage(exitMsg, clientSocket);
                }
                else
                {
                    // cout << fmt::format("Clients connected: ({})", clientsNamesStr) << endl;
                    cout << "Disconnected client with same username" << endl;
                    close(clientSocket);
                }
                lenOfUser.clear();
                // last execution of username exists
            }
            else
            {
                buffer[bytesReceived] = '\0';
                std::string receivedData(buffer);

                std::cout << "Received data: " << receivedData << std::endl;

                // size_t firstDelim = receivedData.find('|');
                // size_t secondDelim = receivedData.find('|', firstDelim + 1);
                // size_t thirdDelim = receivedData.find('|', secondDelim + 1);

                // if (firstDelim != std::string::npos && secondDelim != std::string::npos && thirdDelim != std::string::npos)
                // {
                //     try
                //     {
                //         int msgLength = std::stoi(receivedData.substr(0, firstDelim));
                //         int keyLength = std::stoi(receivedData.substr(firstDelim + 1, secondDelim - firstDelim - 1));
                //         int ivLength = std::stoi(receivedData.substr(secondDelim + 1, thirdDelim - secondDelim - 1));

                //         std::cout << "Message length: " << msgLength << ", Key length: " << keyLength << ", IV length: " << ivLength << std::endl;

                //         if (thirdDelim + 1 + msgLength + keyLength + ivLength <= receivedData.length())
                //         {
                //             std::string encryptedMessage = receivedData.substr(thirdDelim + 1, msgLength);
                //             std::string receivedKeyHex = receivedData.substr(thirdDelim + 1 + msgLength, keyLength);
                //             std::string receivedIvHex = receivedData.substr(thirdDelim + 1 + msgLength + keyLength, ivLength);

                //             SecByteBlock decodedKey(AES::DEFAULT_KEYLENGTH);
                //             StringSource(receivedKeyHex, true, new HexDecoder(new ArraySink(decodedKey, decodedKey.size())));

                //             SecByteBlock decodedIv(AES::BLOCKSIZE);
                //             StringSource(receivedIvHex, true, new HexDecoder(new ArraySink(decodedIv, decodedIv.size())));

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
                } //send stringFormatTime after user decrypts message

                std::string cipherText = receivedData;

                if (!cipherText.empty())
                {
                    std::cout << cipherText << std::endl;
                    broadcastMessage(cipherText, clientSocket);
                }
            }
            //         else
            //         {
            //             string errorMSG = "Couldnt send message";
            //             std::cerr << RED_TEXT << errorMSG << RESET_TEXT << std::endl;
            //         }
            //         }
            //         catch (const std::exception& e)
            //         {
            //             std::cerr << "Exception: " << e.what() << std::endl;
            //         }
            //     }
            //     else
            //     {
            //         std::cerr << "Error: Malformed packet received." << std::endl;
            //     }
            // }
            //         }
            close(clientSocket);
        }
    }
}

int main()
{
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

            close(serverSocket);
            return 0;
}