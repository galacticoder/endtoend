#ifndef NETWORKINGCLASS
#define NETWORKINGCLASS

#include <iostream>
#include <sys/socket.h>
#include <boost/asio.hpp>
#include <fmt/core.h>
#include <netinet/in.h>
#include <unistd.h>
#include "Encryption.hpp"

class Networking
{
private:
    static bool isPortAvailable(int &port)
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

        bind(pavtempsock, (struct sockaddr *)&addr, sizeof(addr)) < 0 ? available = false : available = true;

        close(pavtempsock);
        return available;
    }

public:
    static int findAvailablePort()
    {
        int port = 8080;
        if (isPortAvailable(port) != true)
        {
            for (int i = 49152; i <= 65535; i++)
            {
                if (isPortAvailable(i) != false)
                {
                    port = i;
                    break;
                }
            }
        }
        return port;
    }

    static int startServerSocket(int &port)
    {
        int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

        if (serverSocket < 0)
        {
            std::cerr << "Error opening server socket" << std::endl;
            raise(SIGINT);
        }

        sockaddr_in serverAddress;
        int opt = 1;

        if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
        {
            perror("setsockopt");
            raise(SIGINT);
        }

        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(port);
        serverAddress.sin_addr.s_addr = INADDR_ANY;

        if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
        {
            std::cout << "Chosen port isn't available. Killing server" << std::endl;
            raise(SIGINT);
        }

        listen(serverSocket, 5);
        std::cout << fmt::format("Server listening on port {}", port) << std::endl;
        return serverSocket;
    }

    static std::string GetClientIpHash(int &ClientTcpSocket)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        getpeername(ClientTcpSocket, (struct sockaddr *)&client_addr, &client_len);

        char clientIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, clientIp, INET_ADDRSTRLEN);

        const std::string ClientHashedIp = Hash::hashData(clientIp);
        clientIp[0] = '\0'; // clear the actual user ip
        return ClientHashedIp;
    }
};

#endif