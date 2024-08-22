#ifndef _TLS
#define _TLS

#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <thread>
#include <netinet/in.h>
#include <csignal>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "encry.h"
#include "HandleClient.hpp"
#include "httpCl.h"

#define conSig "C"

int startSock;
EVP_PKEY *receivedPublicKey = nullptr;
EVP_PKEY *privateKey = nullptr;
SSL_CTX *ctx = nullptr;
SSL *tlsSock = nullptr;

class initOpenSSL
{
public:
    initOpenSSL() = default;
    static void InitOpenssl()
    {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        OpenSSL_add_all_algorithms();
    }

    // creating context
    static SSL_CTX *createCtx()
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
    static void configureContext(SSL_CTX *ctx, const std::string &certFilePath)
    {
        if (!SSL_CTX_load_verify_locations(ctx, certFilePath.c_str(), NULL))
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        std::cout << fmt::format("Loaded server cert file ({})", certFilePath) << std::endl;
    }
};

class TlsStart
{
public:
    TlsStart(const char *serverIp, const std::string &privateKeyPath, const std::string &publicKeyPath, const std::string &certPath, const std::string &serverPubKeyPath, unsigned int &port)
    {
        // initialize open tlsSock and create ctx
        initOpenSSL::InitOpenssl();
        ctx = SSL_CTX_new(TLS_client_method());

        { // generate your keys
            std::cout << "Generating keys" << std::endl;
            KeysMake genKeys(privateKeyPath, publicKeyPath);
            std::cout << "Keys have been generated" << std::endl;
        }

        { // get server certPath and extract public key
            const std::string get = fmt::format("http://{}:{}/", serverIp, 80);
            std::cout << fmt::format("Fetching server cert file from: {}", get) << std::endl;
            if (http::fetchAndSave(get, certPath) == 1)
            {
                std::cout << "Could not fetch server cert" << std::endl;
                raise(SIGINT);
            }
            std::cout << "Extracting server public key from cert" << std::endl;
            LoadKey::extractPubKey(certPath, serverPubKeyPath);
            std::cout << "Extracted server public key from cert and stored in: " << serverPubKeyPath << std::endl;
        }

        { // configure ctx
            std::cout << "Configuring ctx" << std::endl;
            initOpenSSL::configureContext(ctx, certPath);
            std::cout << "Context has been configured" << std::endl;
        }

        startSock = socket(AF_INET, SOCK_STREAM, 0);

        { // connect to the server
            sockaddr_in serverAddress;
            serverAddress.sin_family = AF_INET;
            serverAddress.sin_port = htons(port);
            serverAddress.sin_addr.s_addr = inet_addr(serverIp);

            if (inet_pton(AF_INET, serverIp, &serverAddress.sin_addr) <= 0)
            {
                std::cout << "Invalid address / Address not supported\n";
                raise(SIGINT);
            }

            if (connect(startSock, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
            {
                std::cout << "Cannot connect to server. Check server port\n";
                raise(SIGINT);
            }
            { // send connection signal and recieve okay signal from server
                send(startSock, conSig, strlen(conSig), 0);
                char signalOkay[200] = {0};
                read(startSock, signalOkay, sizeof(signalOkay) - 1);
            }
        }

        tlsSock = SSL_new(ctx);

        { // connect using tlsSock
            if (tlsSock == nullptr)
            {
                std::cerr << "Failed to create tlsSock object" << std::endl;
                raise(SIGINT);
            }

            SSL_set_fd(tlsSock, startSock);

            if (SSL_connect(tlsSock) <= 0)
            {
                ERR_print_errors_fp(stderr);
                raise(SIGINT);
            }
        }
    }
};

class TlsFunc
{
public:
    static std::string receiveMessage(SSL *socket)
    {
        try
        {
            char buffer[2048] = {0};
            ssize_t bytes = SSL_read(socket, buffer, sizeof(buffer) - 1);
            buffer[bytes] = '\0';
            std::string msg(buffer);

            if (bytes > 0)
            {
                return msg;
            }
            else
            {
                return "";
            }
        }
        catch (const std::exception &e)
        {
            raise(SIGINT);
        }
        return "";
    }
};

#endif
