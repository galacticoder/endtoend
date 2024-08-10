//https://github.com/galacticoder
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

//To run: g++ -o server server.cpp -lcryptopp -lfmt

#define RED_TEXT "\033[31m" //red text color
#define GREEN_TEXT "\033[32m" //green text color
#define BRIGHT_BLUE_TEXT "\033[94m" //bright blue text color
#define RESET_TEXT "\033[0m" //reset color to default

using boost::asio::ip::tcp;
using namespace std;
using namespace CryptoPP;
using namespace chrono;

vector<int> connectedClients;
mutex clientsMutex;

bool isPav(int port) {
    int pavtempsock;
    struct sockaddr_in addr;
    bool available = false;

    pavtempsock = socket(AF_INET, SOCK_STREAM, 0);
    if (pavtempsock < 0) {
        cerr << "Cannot create socket to test port availability" << endl;
        return false;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(pavtempsock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        available = false;
    } else {
        available = true;
    }

    close(pavtempsock);
    return available;
}

void broadcastMessage(const string& message, int senderSocket = -1) {
    lock_guard<mutex> lock(clientsMutex);
    for (int clientSocket : connectedClients) {
        if (clientSocket != senderSocket) {
            send(clientSocket, message.c_str(), message.length(), 0);
        }
    }
}

string aes_decrypt(const string& ciphertext, const SecByteBlock& key, const SecByteBlock& iv) {
    string decrypted;
    CBC_Mode<AES>::Decryption decryption(key, key.size(), iv);
    StringSource(ciphertext, true, new StreamTransformationFilter(decryption, new StringSink(decrypted), StreamTransformationFilter::PKCS_PADDING));
    return decrypted;
}

void handleClient(int clientSocket) {
    char buffer[4096] = {0};

    ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived <= 0) {
        close(clientSocket);
        return;
    }
    buffer[bytesReceived] = '\0';
    string userStr(buffer);

    if (userStr.find(' ')) {
        replace(userStr.begin(), userStr.end(), ' ', '_');
        send(clientSocket, userStr.c_str(), userStr.length(), 0);
    }

    if (userStr.empty()) {
        close(clientSocket);
        return;
    }

    {
        lock_guard<mutex> lock(clientsMutex);
        connectedClients.push_back(clientSocket);
    }
    string joinMsg = BRIGHT_BLUE_TEXT + fmt::format("{} has joined the chat", userStr) + RESET_TEXT;
    cout << GREEN_TEXT << joinMsg << RESET_TEXT << endl;
    broadcastMessage(joinMsg, clientSocket);

    bool isConnected = true;

    while (isConnected) {
        bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0 || strcmp(buffer, "quit") == 0) {
            isConnected = false;
            lock_guard<mutex> lock(clientsMutex);
            auto it = remove(connectedClients.begin(), connectedClients.end(), clientSocket);
            connectedClients.erase(it, connectedClients.end());
            connectedClients.shrink_to_fit();
            close(clientSocket);

            string exitMsg = fmt::format("{} has left the chat", userStr);
            exitMsg = RED_TEXT + exitMsg + RESET_TEXT;
            cout << exitMsg << endl;
            broadcastMessage(exitMsg, clientSocket);
            // break;
        }

        buffer[bytesReceived] = '\0';
        string receivedData(buffer);

        size_t firstDelim = receivedData.find('|');
        size_t secondDelim = receivedData.find('|', firstDelim + 1);
        size_t thirdDelim = receivedData.find('|', secondDelim + 1);

        if (firstDelim != string::npos && secondDelim != string::npos && thirdDelim != string::npos) {
            try {
                int msgLength = stoi(receivedData.substr(0, firstDelim));
                int keyLength = stoi(receivedData.substr(firstDelim + 1, secondDelim - firstDelim - 1));
                int ivLength = stoi(receivedData.substr(secondDelim + 1, thirdDelim - secondDelim - 1));

                std::cout << "Message length: " << msgLength << ", Key length: " << keyLength << ", IV length: " << ivLength << std::endl;

                if (thirdDelim + 1 + msgLength + keyLength + ivLength <= receivedData.length()) {
                    string encryptedMessage = receivedData.substr(thirdDelim + 1, msgLength);
                    string receivedKeyHex = receivedData.substr(thirdDelim + 1 + msgLength, keyLength);
                    string receivedIvHex = receivedData.substr(thirdDelim + 1 + msgLength + keyLength, ivLength);

                    SecByteBlock decodedKey(AES::DEFAULT_KEYLENGTH);
                    StringSource(receivedKeyHex, true, new HexDecoder(new ArraySink(decodedKey, decodedKey.size())));

                    SecByteBlock decodedIv(AES::BLOCKSIZE);
                    StringSource(receivedIvHex, true, new HexDecoder(new ArraySink(decodedIv, decodedIv.size())));

                    auto now = system_clock::now();
                    time_t currentTime = system_clock::to_time_t(now);
                    tm* localTime = localtime(&currentTime);

                    bool isPM = localTime->tm_hour >= 12;
                    int tHour = (localTime->tm_hour > 12) ? (localTime->tm_hour - 12) : ((localTime->tm_hour == 0) ? 12 : localTime->tm_hour);

                    stringstream ss;
                    ss << tHour << ":" << (localTime->tm_min < 10 ? "0" : "") << localTime->tm_min << " " << (isPM ? "PM" : "AM");
                    string formattedTime = ss.str();

                    string message = fmt::format("{}: ", userStr) + aes_decrypt(encryptedMessage, decodedKey, decodedIv) + "\t\t\t" + formattedTime;
                    broadcastMessage(message, clientSocket);
                    cout << message << endl;
                } else {
                    cerr << RED_TEXT << "Error: Incomplete message received." << RESET_TEXT << endl;
                }
            } catch (const exception& e) {
                cerr << RED_TEXT << "Exception: " << e.what() << RESET_TEXT << endl;
            }
        } else {
            cerr << RED_TEXT << "Error: Malformed packet received." << RESET_TEXT << endl;
        }
    }
}

int main() {
    unsigned short PORT = 8080;

    thread t1([&]() {
        if (!isPav(PORT)) {
            cout << fmt::format("Port {} is not usable searching for port to use..", PORT) << endl;
            for (unsigned short i = 49152; i <= 65535; i++) {
                if (isPav(i)) {
                    PORT = i;
                    break;
                }
            }
        }
    });
    t1.join();

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        cerr << "Error opening server socket" << endl;
        return 1;
    }

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        cerr << "Chosen port isn't available. Killing server" << endl;
        close(serverSocket);
        return 1;
    }

    ofstream file("PORT.txt");
    if (file.is_open()) {
        file << PORT;
        file.close();
    } else {
        cerr << "Warning: cannot write port to file. You may need to configure clients port manually\n";
    }

    listen(serverSocket, 5);
    cout << fmt::format("Server listening on port {}", PORT) << endl;

    while (true) {
        sockaddr_in clientAddress;
        socklen_t clientLen = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientLen);

        thread(handleClient, clientSocket).detach();
    }

    close(serverSocket);
    return 0;
}
