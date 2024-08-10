void genKeys() {
    AutoSeededRandomPool rng;
    // Generate private key
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 4096);

    // Generate public key
    RSA::PublicKey publicKey(privateKey);

    // Store private key in file
    Base64Encoder privKeySink(new FileSink("privatekey.key"));
    privateKey.DEREncode(privKeySink);
    privKeySink.MessageEnd();

    // Store public key in file
    Base64Encoder pubKeySink(new FileSink("publickey.key"));
    publicKey.DEREncode(pubKeySink);
    pubKeySink.MessageEnd();

    cout << "Private key and Public key saved in files: privatekey.key, publickey.key" << endl;
}

std::string rsaEncrypt(const std::string& message, RSA::PublicKey publicKey) {
    AutoSeededRandomPool rng;
    std::string cipher;
    RSAES_OAEP_SHA_Encryptor e(publicKey);
    StringSource ss1(message, true, new PK_EncryptorFilter(rng, e, new StringSink(cipher)));
    return cipher;
}

std::string rsaDecrypt(const std::string& cipher, RSA::PrivateKey privateKey) {
    AutoSeededRandomPool rng;
    std::string recovered;
    RSAES_OAEP_SHA_Decryptor d(privateKey);
    StringSource ss2(cipher, true, new PK_DecryptorFilter(rng, d, new StringSink(recovered)));
    return recovered;
}

void receiveMessages(int clientSocket, RSA::PrivateKey privateKey) {
    char buffer[4096];
    while (true) {
        ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            std::string decryptedMessage = rsaDecrypt(buffer, privateKey);
            cout << decryptedMessage << endl;
        }
    }
}

// Load public and private keys
RSA::PrivateKey privateKey;
RSA::PublicKey publicKey;

FileSource privFile("privatekey.key", true, new Base64Decoder);
privateKey.Load(privFile);

FileSource pubFile("publickey.key", true, new Base64Decoder);
publicKey.Load(pubFile);

thread receiver(receiveMessages, clientSocket, privateKey);
std::string cipherText = rsaEncrypt(message, publicKey);


//https://github.com/galacticoder
#include <iostream>
#include <cryptopp/pem.h>
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
#include "encry_to_server.h"
#include <cstdio>
#include <ctime>
#include <arpa/inet.h>
#include <boost/asio.hpp>
#include <cstdlib>
#include <termios.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>


//To run: g++ -o client client.cpp encrypt_traffic.cpp -lcryptopp -lfmt

#define GREEN_TEXT "\033[32m" //green text color
#define RESET_TEXT "\033[0m" //reset color to default

using namespace std;
using namespace CryptoPP;
using boost::asio::ip::tcp;


void genKeys() {
    AutoSeededRandomPool rng;
    //gen private key
    RSA::PrivateKey privatekey;
    privatekey.GenerateRandomWithKeySize(rng, 4096);
    //gen public key
    RSA::PublicKey publickey(privatekey);
    //storing privatre key in file
    Base64Encoder privKeySink(new FileSink("privatekey.key"));
    privatekey.DEREncode(privKeySink);
    privKeySink.MessageEnd();
    //storing public key in file
    Base64Encoder pubKeySink(new FileSink("publickey.key"));
    publickey.DEREncode(pubKeySink);
    pubKeySink.MessageEnd();
    cout << "Private key and Public key saved in files: " << pubKeySink << ", " << privKeySink << endl;
}

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

std::string t_w(std::string strIp) {
    strIp.erase(strIp.begin(), std::find_if(strIp.begin(), strIp.end(), [](unsigned char ch) {
        return !std::isspace(ch);
        }));
    strIp.erase(std::find_if(strIp.rbegin(), strIp.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
        }).base(), strIp.end());
    return strIp;
}

void receiveMessages(int clientSocket) {
    char buffer[1024];
    char keys[1024];
    while (true) {
        ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        ssize_t keysI = recv(clientSocket, keys, sizeof(keys), 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';

            //check for a certain number of bytes thatll be a key and then if its the key encrypt what you want want and send the cipher

            //or treat everything that comes thru as a potential key then yeah

            // SecByteBlock receivedKey(AES_KEY_LENGTH);
            // SecByteBlock receivedIV(AES_IV_LENGTH);
            // decryptWithPreSharedKey(buffer, receivedKey, receivedIV, preSharedKey, preSharedIV); // decrypt the received data from the server

            // std::cout << buffer << std::endl; //instead of outputting the cipher text decrypt then output

        }
    }
}

int main() {
    string local = "127.0.0.1"; //if server is being served locally do not modify
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
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        cout << "Cannot connect to server\n";
        close(clientSocket);
        return 1;
    }

    cout << fmt::format("Found connection to server on port {}", PORT) << endl;
    cout << "Enter a username to go by: ";
    getline(cin, user);
    user = t_w(user);

    if (user.empty()) {
        cout << "Username cannot be empty. Disconnecting from server\n";
        close(clientSocket);
        exit(true);
    }

    else if (user.length() > 12 || user.length() <= 3) {
        cout << "Username length needs to be greater than 3 and less than 12" << endl;
        close(clientSocket);
        return 1;
    }

    send(clientSocket, user.c_str(), user.length(), 0);

    //to recieve new client username if usrname had spaces
    char buffer[4096] = { 0 };
    ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    buffer[bytesReceived] = '\0';
    std::string userStr(buffer);

    // cout << GREEN_TEXT << fmt::format("You have joined the chat as '{}'\n", userStr) << RESET_TEXT << endl;

    const int AES_KEY_LENGTH = 32; // 256-bit key
    const int AES_IV_LENGTH = 16;  // 128-bit IV

    SecByteBlock key(AES_KEY_LENGTH);
    SecByteBlock iv(AES_IV_LENGTH); //gen keys
    generate_key_iv(key, iv);

    SecByteBlock preSharedKey(AES_KEY_LENGTH);
    SecByteBlock preSharedIV(AES_IV_LENGTH); // define a pre-shared secret key and iv for encryption
    generate_key_iv(preSharedKey, preSharedIV);

    std::string keyHex, ivHex, preSharedKeyHex, preSharedIVHex;

    StringSource(key.data(), key.size(), true, new HexEncoder(new StringSink(keyHex)));
    StringSource(iv.data(), iv.size(), true, new HexEncoder(new StringSink(ivHex))); //converting to hex so able to send

    StringSource(preSharedKey.data(), preSharedKey.size(), true, new HexEncoder(new StringSink(preSharedKeyHex)));
    StringSource(preSharedIV.data(), preSharedIV.size(), true, new HexEncoder(new StringSink(preSharedIVHex))); //converting to hex so able to send

    std::string encryptedData = encryptWithPreSharedKey(key, iv, preSharedKey, preSharedIV);

    thread receiver(receiveMessages, clientSocket);
    receiver.detach();

    string message;
    while (true) {
        getline(cin, message); //^<--> none
        //clear input start 
        cout << "\033[A"; //up
        cout << "\r"; //delete
        cout << "\033[K"; //from start mixed up on line 128
        //end
        if (message == "quit") {
            break;
        }
        else if (message.empty()) {
            continue; //skip empty messages
        }
        message = t_w(message);
        if (message == "quit") {
            send(clientSocket, message.c_str(), message.length(), 0);
            close(clientSocket);
            exit(true);
        }

        std::string cipherText = aes_encrypt(message, key, iv);

        //need to send key, iv, and message with a pipe delimeter all at once because of data loss
        bool serverReachable = isPortOpen(local, PORT);
        if (serverReachable != true) { //check if server is reachable before attempting to send a message
            cout << "Server has been shutdown" << endl;
            close(clientSocket);
            exit(true);
        }
        else {
            send(clientSocket, cipherText.c_str(), cipherText.length(), 0);
            cout << GREEN_TEXT << fmt::format("{}(You): {}", userStr, message) << RESET_TEXT << endl; //print the message you sent without it doubkin g tho
        }
    }

    close(clientSocket);
    return 0;
}
