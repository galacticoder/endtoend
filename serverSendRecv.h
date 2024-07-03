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

using namespace CryptoPP;
using namespace std;

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

    void sendBase64Data(int socket, const std::string& encodedData)
    {
        ssize_t sentBytes = send(socket, encodedData.c_str(), encodedData.size(), 0);
        if (sentBytes == -1)
        {
            throw std::runtime_error("Error sending data");
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

#endif