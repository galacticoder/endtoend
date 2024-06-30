#ifndef RSAENC
#define RSAENC

#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <vector>


using namespace CryptoPP;
using namespace std;

const unsigned int KEYSIZE = 4096;

//put all key gen part in a class

struct KeysMake {
    // make constructor that generates the keys
    KeysMake(const std::string privateKeyFile, const std::string publicKeyFile, unsigned int keySize = KEYSIZE) {
        AutoSeededRandomPool rng;
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, keySize);

        RSA::PublicKey publicKey(privateKey);

        {
            FileSink file(privateKeyFile.c_str());
            privateKey.DEREncode(file);
        }
        {
            FileSink file(publicKeyFile.c_str());
            publicKey.DEREncode(file);
        }

        cout << "rsa key pair generated" << endl;
    }
};

struct LoadKey {
    LoadKey() = default;
    bool loadPrv(const std::string& privateKeyFile, RSA::PrivateKey& privateKey) {
        try {
            FileSource file(privateKeyFile.c_str(), true /*pumpAll*/);
            privateKey.BERDecode(file);
            cout << "Loaded RSA Private key successfuly" << endl;
        }
        catch (const Exception& e) {
            std::cerr << "error loading private rsa key: " << e.what() << std::endl;
            return false;
        }

        return true;
    }
    //for pub key
    bool loadPub(const std::string& publicKeyFile, RSA::PublicKey& publickey) {
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
};

struct Enc {
    Enc() = default;
    string enc(RSA::PublicKey& pubkey, string& plain) {
        AutoSeededRandomPool rng; //using diff rng for better randomness
        string cipher;
        RSAES_OAEP_SHA512_Encryptor e(pubkey); //make sure to push rsa.h or you get errors cuz its modified to sha512 instead of sha1 for better security
        StringSource ss1(plain, true, new PK_EncryptorFilter(rng, e, new StringSink(cipher))); //nested for better verification of both key loading
        return cipher;
    }
    std::string Base64Encode(const std::string& input) {
        std::string encoded;
        StringSource(input, true, new Base64Encoder(new StringSink(encoded), false));
        return encoded;
    }
    string hexencode(string& cipher) {
        string encoded;
        CryptoPP::StringSource(cipher, true /*pump all*/, new CryptoPP::HexDecoder(new CryptoPP::StringSink(encoded)));
        cout << encoded << endl;
        return encoded;
    }


};

struct Dec {
    Dec() = default;
    string dec(RSA::PrivateKey& prvkey, string& cipher) {
        AutoSeededRandomPool rng; //using diff rng for better randomness
        string decrypted;
        RSAES_OAEP_SHA512_Decryptor d(prvkey);//modified to decrypt sha512
        StringSource ss2(cipher, true, new PK_DecryptorFilter(rng, d, new StringSink(decrypted)));
        return decrypted;
    }
    std::string Base64Decode(const std::string& input) {
        std::string decoded;
        StringSource(input, true, new Base64Decoder(new StringSink(decoded)));
        return decoded;
    }
    string hexdecode(string& encoded) {
        string decoded;
        CryptoPP::StringSource ssv(encoded, true /*pump all*/, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }
};

struct Send {
    Send() = default;
    //std::vector<uint8_t> buffer = readFile(filePath); file path is a string to the file path
    //std::string encodedData = base64Encode(buffer);
    //sendBase64Data(clientSocket, encodedData);
    std::string b64EF(const std::vector<uint8_t>& data)
    {
        // cout << "Bytes sending: " << data.size() << endl;
        std::string encoded;
        CryptoPP::StringSource ss(data.data(), data.size(), true,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(encoded),
                false // do not add line breaks
            ));
        // cout << "B64 bytes sent: " << encoded.size() << endl;
        return encoded;
    }


    std::vector<uint8_t> readFile(const std::string& filePath)
    {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open())
        {
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
            cout << fmt::format("Could not open file '{}' to write", filePath) << endl;
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
        ssize_t bytesRead;

        while ((bytesRead = recv(clientSocket, buffer.data(), buffer.size(), 0)) > 0)
        {
            receivedData.append(buffer.data(), bytesRead); //probably problem here
            if (receivedData.size() == bytesRead) {
                break;
            }
        }
        // cout << "RECIEVED DATA: " << receivedData.size() << endl;
        // cout << "BYTES READ: " << bytesRead << endl;

        if (bytesRead == -1)
        {
            throw std::runtime_error("Error receiving data");
        }

        return receivedData;
    }
};

#endif