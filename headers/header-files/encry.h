#ifndef RSAENC
#define RSAENC

#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/base64.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <filesystem>
#include "leave.h"

const unsigned int KEYSIZE = 4096;
// extern std::function<void(int)> shutdown_handler;
// extern void signal_handler(int signal);
struct KeysMake
{
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

    static void extractPubKey(const std::string certFile, const std::string &pubKey)
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

    static EVP_PKEY *LoadPrvOpenssl(const std::string &privateKeyFile, const short echo = 1)
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
            return nullptr;
        }

        if (echo == 1)
            std::cout << "Loaded RSA Private key file (" << privateKeyFile << ") successfuly" << std::endl;

        return pkey;
    }

    static EVP_PKEY *LoadPubOpenssl(const std::string &publicKeyFile, const short echo = 1)
    {
        BIO *bio = BIO_new_file(publicKeyFile.c_str(), "r");
        if (!bio)
        {
            ERR_print_errors_fp(stderr);
            std::cerr << fmt::format("Error loading public rsa key from path {}", publicKeyFile) << std::endl;
            return nullptr;
        }

        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey)
        {
            std::cerr << fmt::format("Error loading public rsa key from path {}", publicKeyFile) << std::endl;
            return nullptr;
        }

        if (echo == 1)
            std::cout << "Loaded RSA Public key file (" << publicKeyFile << ") successfuly" << std::endl;

        return pkey;
    }
    static EVP_PKEY *loadPemEVP(const std::string pem_key)
    {
        BIO *bio = BIO_new_mem_buf(pem_key.c_str(), -1);

        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        if (!pkey)
        {
            std::cout << "PEM cant read" << std::endl;
            return nullptr;
        }
        BIO_free(bio);
        return pkey;
    }
};

struct Enc
{
    Enc() = default;
    static std::string Encrypt(EVP_PKEY *pkey, const std::string &data)
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

    static std::string Base64Encode(const std::string &input)
    {
        std::string encoded;
        CryptoPP::StringSource(input, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
        return encoded;
    }
};

struct Dec
{
    Dec() = default;
    static std::string Decrypt(EVP_PKEY *pkey, const std::string &encrypted_data)
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
        out.resize(out_len);
        return out;
    }
    static std::string Base64Decode(const std::string &input)
    {
        std::string decoded;
        CryptoPP::StringSource(input, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }
};
struct Send
{
    Send() = default;
    // string buffer = struct.readFile(filePath); file path is a string to the file path
    // string encodedData = struct.b64EF(string buffer);
    // struct.sendBase64Data(clientSocket, encodedData);
    static std::string b64EF(std::string &data)
    {
        std::string encoded;
        CryptoPP::StringSource(data, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
        return encoded;
    }

    static std::string readFile(const std::string &filePath)
    {
        std::ifstream file(filePath);
        if (!file.is_open())
        {
            throw std::runtime_error(fmt::format("Could not open file: {}", filePath));
        }

        std::string buffer;
        std::string line;

        while (getline(file, buffer))
        {
            buffer.push_back('\n');
        }

        file.close();
        return buffer;
    }

    static void sendBase64Data(SSL *socket, const std::string &encodedData)
    {
        ssize_t sentBytes = SSL_write(socket, encodedData.c_str(), encodedData.size());
        if (sentBytes == -1)
        {
            std::cout << "Error sending: " << encodedData << std::endl;
            throw std::runtime_error(fmt::format("Error sending data: {}", encodedData));
        }
    }

    static void broadcastBase64Data(int clientSocket, const std::string &encodedData, std::vector<int> &connectedClients, std::vector<SSL *> &tlsSocks)
    {
        for (unsigned int i = 0; i < connectedClients.size(); i++)
        {
            if (connectedClients[i] != clientSocket)
            {
                SSL_write(tlsSocks[i], encodedData.c_str(), encodedData.length());
            }
        }
    }
};

struct Receive
{
    Receive() = default;
    // std::string encodedData = receiveBase64Data(clientSocket);
    // std::vector<uint8_t> decodedData = base64Decode(encodedData);
    // saveFile(filePath, decodedData);
    static std::string read_pem_key(const std::string &path)
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

    static std::string Base64Decode(const std::string &encodedData)
    {
        std::string decoded;
        CryptoPP::StringSource(encodedData, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }

    static void saveFile(const std::string &filePath, const std::string &buffer)
    {
        std::ofstream file(filePath);
        if (file.is_open())
        {
            file << buffer;
            return;
        }
        std::cout << fmt::format("Could not open file to write: ", filePath) << std::endl;
    }
    static void saveFilePem(const std::string &filePath, const std::string &buffer)
    {
        std::ofstream file(filePath, std::ios::binary);
        if (file.is_open())
        {
            file << buffer;
            return;
        }
        std::cout << fmt::format("Could not open file to write: ", filePath) << std::endl;
        raise(SIGINT);
    }
    static std::string receiveBase64Data(SSL *clientSocket)
    {
        std::vector<char> buffer(4096);
        std::string receivedData;
        unsigned int bytesRead = SSL_read(clientSocket, buffer.data(), buffer.size());

        while (bytesRead > 0)
        {
            receivedData.append(buffer.data(), bytesRead);
            if (receivedData.size() == bytesRead)
            {
                break;
            }
        }

        if ((int)bytesRead == -1)
        {
            throw std::runtime_error("Error receiving data");
        }

        return receivedData;
    }

    static std::string getPemKey(SSL *clientSock, const std::string &filepath)
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