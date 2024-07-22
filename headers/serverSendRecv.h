#ifndef serverSideSendRecv
#define serverSideSendRecv

#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include "rsa.h"



using namespace CryptoPP;
using namespace std;


struct Enc {
    Enc() = default;
    string enc(RSA::PublicKey& pubkey, string& plain) {
        // try {
        AutoSeededRandomPool rng; //using diff rng for better randomness
        string cipher;
        RSAES_OAEP_SHA512_Encryptor e(pubkey); //make sure to push rsa.h or you get errors cuz its modified to sha512 instead of sha1 for better security
        StringSource ss1(plain, true, new PK_EncryptorFilter(rng, e, new StringSink(cipher))); //nested for better verification of both key loading
        return cipher;
        // }
        // catch (const Exception& e) {
        //     string pu = "user-keys/pub";
        //     string pr = "user-keys/prv";
        //     auto pubdel = std::filesystem::directory_iterator(pu);
        //     int puddel = 0;
        //     for (auto& puddel : pubdel)
        //     {
        //         if (puddel.is_regular_file())
        //         {
        //             std::filesystem::remove(puddel);
        //         }
        //     }
        //     auto prvdel = std::filesystem::directory_iterator(pr);
        //     int prvdel2 = 0;
        //     for (auto& prvdel2 : prvdel)
        //     {
        //         if (prvdel2.is_regular_file())
        //         {
        //             std::filesystem::remove(prvdel2);
        //         }
        //     }
        //     const string err = "error";
        //     return err;
        // }
    }

    std::string Base64Encode(const std::string& input) {
        std::string encoded;
        StringSource(input, true, new Base64Encoder(new StringSink(encoded), false));
        return encoded;
    }
};
struct Send {
    Send() = default;
    //std::vector<uint8_t> buffer = readFile(filePath); file path is a string to the file path
    //std::string encodedData = b64EF(buffer);
    //sendBase64Data(clientSocket, encodedData);
    std::string b64EF(const std::vector<uint8_t>& data)
    {
        std::string encoded;
        CryptoPP::StringSource ss(data.data(), data.size(), true,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(encoded),
                false // do not add line breaks
            ));
        return encoded;
    }

    std::vector<uint8_t> readFile(const std::string& filePath)
    {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open())
        {
            cout << "cannot open file " << filePath << endl;
            throw std::runtime_error("Could not open file");
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
        {
            throw std::runtime_error("Error reading file");
        }

        return buffer;
    }

    void sendBase64Data(int socket, const std::string& encodedData) {
        ssize_t sentBytes = send(socket, encodedData.c_str(), encodedData.size(), 0);
        if (sentBytes == -1)
        {
            cout << "error sending: " << encodedData << endl;
            throw std::runtime_error("Error sending data");
        }
    }
    void broadcastBase64Data(int clientSocket, const std::string& encodedData, vector <int>& connectedClients) {
        lock_guard<mutex> lock(clientsMutex);
        for (int clientSocket : connectedClients)
        {
            if (clientSocket != clientSocket)
            {
                send(clientSocket, encodedData.c_str(), encodedData.length(), 0);
            }
        }
    }
};

struct Recieve {
    Recieve() = default;
    //std::string encodedData = receiveBase64Data(clientSocket);
    //std::vector<uint8_t> decodedData = base64Decode(encodedData);
    //saveFile(filePath, decodedData);
    std::vector<uint8_t> base64Decode(const std::string& encodedData)
    {
        std::vector<uint8_t> decoded;
        CryptoPP::StringSource ss(encodedData, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::VectorSink(decoded)));
        return decoded;
    }

    void saveFile(const std::string& filePath, const std::vector<uint8_t>& buffer)
    {
        std::ofstream file(filePath, std::ios::binary);
        if (!file.is_open())
        {
            cout << "couldnt open " << filePath << endl;
            throw std::runtime_error("Could not open file to write");
        }

        file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        if (!file)
        {
            throw std::runtime_error("Error writing to file");
        }
    }
    std::string receiveBase64Data(int clientSocket)
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
};

struct LoadKey {
    LoadKey() = default;
    bool loadPub(const std::string& publicKeyFile) {
        RSA::PublicKey publickey;
        try {
            ifstream fileopencheck(publicKeyFile, ios::binary);
            if (fileopencheck.is_open()) {
                FileSource file(publicKeyFile.c_str(), true /*pumpAll*/);
                publickey.BERDecode(file);
                cout << "Loaded RSA Public key file (" << publicKeyFile << ") successfuly" << endl;
            }
            else {
                cout << fmt::format("could not open file at file path '{}'", publicKeyFile) << endl;
            }
        }
        catch (const Exception& e) {
            std::cerr << fmt::format("error loading public rsa key from path {}: {}", publicKeyFile, e.what()) << endl;
            return false;
        }

        return true;
    }
    string loadPubAndEncrypt(const std::string& publicKeyFile, string& plaintext) {
        Enc encrypt;
        RSA::PublicKey publickey;
        try {
            ifstream fileopencheck(publicKeyFile, ios::binary);
            if (fileopencheck.is_open()) {
                FileSource file(publicKeyFile.c_str(), true /*pumpAll*/);
                publickey.BERDecode(file);
                cout << "Loaded RSA Public key file (" << publicKeyFile << ") successfuly" << endl;
                string encrypted = encrypt.enc(publickey, plaintext);
                // string base64encoded = ;
                return encrypt.Base64Encode(encrypted);
            }
            else {
                cout << fmt::format("Could not open public key at file path '{}'", publicKeyFile) << endl;
                return "err";
            }
        }
        catch (const Exception& e) {
            std::cerr << fmt::format("Error loading public rsa key from path {}: {}", publicKeyFile, e.what()) << endl;
            return "err";
        }

        return "success";
    }
};

#endif