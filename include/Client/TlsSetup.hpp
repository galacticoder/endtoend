#ifndef TLS
#define TLS

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
#include "HandleClient.hpp"
#include "Keys.hpp"
#include "httpCl.h"

int startSock;
SSL_CTX *ctx = nullptr;
SSL *clientSocketSSL = nullptr;

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
        std::cout << "Configuring ctx" << std::endl;
        if (!SSL_CTX_load_verify_locations(ctx, certFilePath.c_str(), NULL))
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        std::cout << fmt::format("Loaded server cert file ({})", certFilePath) << std::endl;
        std::cout << "Context has been configured" << std::endl;
    }
};

class StartTLS
{
private:
    void connectUsingTcpSocket(const char *serverIp, unsigned int &port) // connect to the server
    {
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

        // send connection signal
        const std::string connectionSignal = SignalHandling::GetSignalAsString(SignalType::CONNECTIONSIGNAL);
        send(startSock, connectionSignal.c_str(), connectionSignal.length(), 0);

        // recieve signal from server to see if your blacklisted or its an okay signal
        char signalBuffer[2048] = {0};
        ssize_t bytes = read(startSock, signalBuffer, sizeof(signalBuffer) - 1);
        signalBuffer[bytes] = '\0';
        std::string signalMessage(signalBuffer);

        SignalHandling::handleSignal(SignalHandling::getSignalType(signalMessage), signalMessage);
    }

    void connectUsingTlsSocket(SSL *clientSocketSSL) // connect to server and establish tls connection with server
    {
        if (clientSocketSSL == nullptr)
        {
            std::cerr << "Failed to create clientSocketSSL object" << std::endl;
            raise(SIGINT);
        }

        SSL_set_fd(clientSocketSSL, startSock);

        if (SSL_connect(clientSocketSSL) <= 0)
        {
            ERR_print_errors_fp(stderr);
            raise(SIGINT);
        }
    }

public:
    static void generateKeys(const std::string &privateKeyPath, const std::string &publicKeyPath) // generate your keys
    {
        std::cout << "Generating keys" << std::endl;
        GenerateKeys genKeys(privateKeyPath, publicKeyPath);
        std::cout << "Keys have been generated" << std::endl;
    }

    StartTLS(std::string &serverIp, const std::string &certPath, const std::string &serverPubKeyPath, unsigned int &port)
    {
        // initialize open clientSocketSSL and create ctx
        initOpenSSL::InitOpenssl();
        ctx = SSL_CTX_new(TLS_client_method());

        startSock = socket(AF_INET, SOCK_STREAM, 0);

        connectUsingTcpSocket(serverIp.c_str(), port);

        clientSocketSSL = SSL_new(ctx);

        connectUsingTlsSocket(clientSocketSSL);
    }
};

#endif
