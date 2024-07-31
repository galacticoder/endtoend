#pragma once

#ifndef RSAENC
#define RSAENC

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
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <filesystem>
#include "rsa.h"
#include "leave.h"
// #include <vector>

// using namespace CryptoPP;
using namespace std;

const unsigned int KEYSIZE = 4096;

// put all key gen part in a class

struct KeysMake
{
    // bool generate_key();
    // make constructor that generates the keys
    KeysMake(const std::string &privateKeyFile, const std::string &publicKeyFile, int bits = KEYSIZE)
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        EVP_PKEY *pkey = NULL;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        EVP_PKEY_CTX_free(ctx);

        BIO *privateKeyBio = BIO_new_file(privateKeyFile.c_str(), "w+");
        PEM_write_bio_PrivateKey(privateKeyBio, pkey, NULL, NULL, 0, NULL, NULL);
        BIO_free_all(privateKeyBio);

        BIO *publicKeyBio = BIO_new_file(publicKeyFile.c_str(), "w+");
        PEM_write_bio_PUBKEY(publicKeyBio, pkey);
        BIO_free_all(publicKeyBio);

        EVP_PKEY_free(pkey);
    }
};

struct LoadKey
{
    LoadKey() = default;
    // bool loadPrv(const std::string &privateKeyFile, CryptoPP::RSA::PrivateKey &privateKey)
    // {
    //     try
    //     {
    //         CryptoPP::FileSource file(privateKeyFile.c_str(), true /*pumpAll*/);
    //         privateKey.BERDecode(file);
    //         cout << "Loaded RSA Private key successfuly" << endl;
    //     }
    //     catch (const exception &e)
    //     {
    //         std::cerr << "Error loading private rsa key: " << e.what() << std::endl;
    //         return false;
    //     }

    //     return true;
    // }
    // // for pub key
    // bool loadPub(const std::string &publicKeyFile, CryptoPP::RSA::PublicKey &publickey)
    // {
    //     try
    //     {
    //         ifstream fileopencheck(publicKeyFile, ios::binary);
    //         if (fileopencheck.is_open())
    //         {
    //             CryptoPP::FileSource file(publicKeyFile.c_str(), true /*pumpAll*/);
    //             publickey.BERDecode(file);
    //             cout << "Loaded RSA Public key file (" << publicKeyFile << ") successfuly" << endl;
    //         }
    //         else
    //         {
    //             cout << fmt::format("Could not open public key at file path '{}'", publicKeyFile) << endl;
    //             exit(1);
    //         }
    //     }
    //     catch (const exception &e)
    //     {
    //         std::cerr << fmt::format("Error loading public rsa key from path {}: {}", publicKeyFile, e.what()) << endl;
    //         return false;
    //     }

    //     return true;
    // }
    void extractPubKey(const std::string certFile, const std::string &pubKey)
    {
        FILE *certFileOpen = fopen(certFile.c_str(), "r");
        if (!certFileOpen)
        {
            std::cerr << "Error opening cert file: " << certFile << std::endl;
            return;
        }

        X509 *cert = PEM_read_X509(certFileOpen, nullptr, nullptr, nullptr);
        fclose(certFileOpen);
        if (!cert)
        {
            std::cerr << "Error reading certificate" << std::endl;
            return;
        }

        EVP_PKEY *pubkey = X509_get_pubkey(cert);
        if (!pubkey)
        {
            std::cerr << "Error extracting pubkey from cert" << std::endl;
            X509_free(cert);
            return;
        }

        FILE *pubkeyfile = fopen(pubKey.c_str(), "w");
        if (!pubkeyfile)
        {
            std::cerr << "Error opening pub key file: " << pubKey << std::endl;
            EVP_PKEY_free(pubkey);
            X509_free(cert);
            return;
        }

        if (PEM_write_PUBKEY(pubkeyfile, pubkey) != 1)
        {
            std::cerr << "Error writing public key to file" << std::endl;
        }

        fclose(pubkeyfile);
        EVP_PKEY_free(pubkey);
        X509_free(cert);
        ERR_free_strings();
    }

    EVP_PKEY *LoadPrvOpenssl(const std::string &privateKeyFile)
    {
        BIO *bio = BIO_new_file(privateKeyFile.c_str(), "r");
        if (!bio)
        {
            std::cerr << "Error loading private rsa key: ";
            ERR_print_errors_fp(stderr);
            return nullptr;
        }

        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey)
        {
            std::cerr << "Error loading private rsa key: ";
            ERR_print_errors_fp(stderr);
        }

        cout << "Loaded RSA Private key file (" << privateKeyFile << ") successfuly" << endl;

        return pkey;
    }

    EVP_PKEY *LoadPubOpenssl(const std::string &publicKeyFile)
    {
        BIO *bio = BIO_new_file(publicKeyFile.c_str(), "r");
        if (!bio)
        {
            ERR_print_errors_fp(stderr);
            std::cerr << fmt::format("Error loading public rsa key from path {}", publicKeyFile) << endl;
            return nullptr;
        }

        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey)
        {
            std::cerr << fmt::format("Error loading public rsa key from path {}", publicKeyFile) << endl;
            ERR_print_errors_fp(stderr);
        }
        cout << "Loaded RSA Public key file (" << publicKeyFile << ") successfuly" << endl;

        return pkey;
    }
    EVP_PKEY *loadPemEVP(const std::string pem_key)
    {
        BIO *bio = BIO_new_mem_buf(pem_key.c_str(), -1);

        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        if (!pkey)
        {
            cout << "PEM cant read" << endl;
        }
        BIO_free(bio);
        return pkey;
    }
};

struct Enc
{
    Enc() = default;
    string enc(EVP_PKEY *pkey, const std::string &data)
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx)
        {
            ERR_print_errors_fp(stderr);
            return "";
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        size_t out_len;
        if (EVP_PKEY_encrypt(ctx, nullptr, &out_len, reinterpret_cast<const unsigned char *>(data.c_str()), data.size()) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        std::string out(out_len, '\0');
        if (EVP_PKEY_encrypt(ctx, reinterpret_cast<unsigned char *>(&out[0]), &out_len, reinterpret_cast<const unsigned char *>(data.c_str()), data.size()) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "err";
        }

        EVP_PKEY_CTX_free(ctx);
        out.resize(out_len);
        return out;
    }

    std::string Base64Encode(const std::string &input)
    {
        std::string encoded;
        CryptoPP::StringSource(input, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
        return encoded;
    }

    string hexencode(string &cipher)
    {
        string encoded;
        CryptoPP::StringSource(cipher, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(encoded)));
        cout << encoded << endl;
        return encoded;
    }
};

struct Dec
{
    Dec() = default;
    string dec(EVP_PKEY *pkey, const std::string &encrypted_data)
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx)
        {
            ERR_print_errors_fp(stderr);
            return "";
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        size_t out_len;
        if (EVP_PKEY_decrypt(ctx, nullptr, &out_len, reinterpret_cast<const unsigned char *>(encrypted_data.c_str()), encrypted_data.size()) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        std::string out(out_len, '\0');
        if (EVP_PKEY_decrypt(ctx, reinterpret_cast<unsigned char *>(&out[0]), &out_len, reinterpret_cast<const unsigned char *>(encrypted_data.c_str()), encrypted_data.size()) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        EVP_PKEY_CTX_free(ctx);
        out.resize(out_len); // Adjust the size of the string
        return out;
    }
    std::string Base64Decode(const std::string &input)
    {
        std::string decoded;
        CryptoPP::StringSource(input, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }
    string hexdecode(string &encoded)
    {
        string decoded;
        CryptoPP::StringSource ssv(encoded, true /*pump all*/, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }
};

struct initOpenSSL
{
    initOpenSSL() = default;
    void InitOpenssl()
    {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
    }

    // creating context
    SSL_CTX *createCtx()
    {
        const SSL_METHOD *method = SSLv23_server_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        if (!ctx)
        {
            ERR_print_errors_fp(stderr);
            raise(SIGINT);
        }
        return ctx;
    }
    // config context
    void configureContext(SSL_CTX *ctx, const string &certFilePath)
    {
        if (!SSL_CTX_load_verify_locations(ctx, certFilePath.c_str(), NULL))
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        std::cout << fmt::format("Loaded server cert file ({})", certFilePath) << std::endl;
    }
};

struct Send
{
    Send() = default;
    // string buffer = struct.readFile(filePath); file path is a string to the file path
    // string encodedData = struct.b64EF(string buffer);
    // struct.sendBase64Data(clientSocket, encodedData);
    std::string b64EF(string &data)
    {
        std::string encoded;
        CryptoPP::StringSource(data, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
        return encoded;
    }

    std::string readFile(const std::string &filePath)
    {
        std::ifstream file(filePath);
        if (!file.is_open())
        {
            throw std::runtime_error(fmt::format("Could not open file: {}", filePath));
        }

        string buffer;
        string line;

        while (getline(file, buffer))
        {
            buffer.push_back('\n');
        }

        file.close();
        return buffer;
    }

    void sendBase64Data(SSL *socket, const std::string &encodedData)
    {
        ssize_t sentBytes = SSL_write(socket, encodedData.c_str(), encodedData.size());
        if (sentBytes == -1)
        {
            cout << "Error sending: " << encodedData << endl;
            throw std::runtime_error(fmt::format("Error sending data: {}", encodedData));
        }
    }

    void broadcastBase64Data(int clientSocket, const std::string &encodedData, vector<int> &connectedClients, vector<SSL *> &tlsSocks)
    {
        for (int i = 0; i < connectedClients.size(); i++)
        {
            for (int i = 0; i < connectedClients.size(); i++)
            {
                if (connectedClients[i] != clientSocket)
                {
                    SSL_write(tlsSocks[i], encodedData.c_str(), encodedData.length());
                }
            }
        }
    }
};

struct Recieve
{
    Recieve() = default;
    // std::string encodedData = receiveBase64Data(clientSocket);
    // std::vector<uint8_t> decodedData = base64Decode(encodedData);
    // saveFile(filePath, decodedData);
    std::string read_pem_key(const std::string &path)
    {
        std::ifstream file(path);
        if (!file.is_open())
        {
            std::cout << "Could not open pem file" << std::endl;
        }
        std::string pemKey((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        return pemKey;
    }

    std::string base64Decode(const std::string &encodedData)
    {
        std::string decoded;
        CryptoPP::StringSource(encodedData, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }

    void saveFile(const std::string &filePath, const string &buffer)
    {
        std::ofstream file(filePath);
        if (!file.is_open())
        {
            throw std::runtime_error(fmt::format("Could not open file to write: ", filePath)); // here
        }

        file << buffer;
        // cout << "buffer: " <<

        if (!file)
        {
            throw std::runtime_error("Error writing to file");
        }
    }
    void saveFilePem(const std::string &filePath, const string &buffer)
    {
        std::ofstream file(filePath, std::ios::binary);
        if (!file.is_open())
        {
            throw std::runtime_error(fmt::format("Could not open file to write: ", filePath));
        }

        file << buffer;

        if (!file)
        {
            throw std::runtime_error("Error writing to file");
        }
    }
    std::string receiveBase64Data(SSL *clientSocket)
    {
        std::vector<char> buffer(4096);
        std::string receivedData;
        ssize_t bytesRead = SSL_read(clientSocket, buffer.data(), buffer.size());

        while (bytesRead > 0) // its gonna keep appending without a stop condition
        {
            // cout << "Bytes read: " << bytesRead << endl;
            receivedData.append(buffer.data(), bytesRead);
            if (receivedData.size() == bytesRead)
            {
                break;
            }
        }
        // cout << "RECIEVED DATA: " << receivedData.size() << endl;
        // cout << "BYTES READ: " << bytesRead << endl;

        if (bytesRead == -1)
        {
            // cout << "err here" << endl;
            throw std::runtime_error("Error receiving data");
            // cout << "err here 2" << endl;
        }

        // cout << "file recvd" << endl;

        return receivedData;
    }

    std::string getPemKey(SSL *clientSock, const std::string &filepath)
    {
        char buffer[1024] = {0};
        int valread = SSL_read(clientSock, buffer, 1024);
        buffer[valread] = '\0';
        std::string pemKey(buffer);

        std::ofstream key(filepath);
        if (!key.is_open())
        {
            std::cout << "Could not open key file to write: " << filepath << std::endl;
        }
        key << pemKey;
        key.close();
        std::cout << "File written to: " << filepath << std::endl;

        return std::string(buffer, valread);
    }
};

#endif