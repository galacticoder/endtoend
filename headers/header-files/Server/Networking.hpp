#ifndef NETWORKINGCLASS
#define NETWORKINGCLASS

#include <iostream>
#include <sys/socket.h>
#include <boost/asio.hpp>
#include <fmt/core.h>
#include <netinet/in.h>
#include <unistd.h>
#include "ServerSettings.hpp"
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

    static void pingClient(SSL *clientSocketSSL, unsigned int &clientIndex, const std::string clientHashedIp)
    {
        std::cout << "Started thread for pinging client" << std::endl;
        int clientServerPort = ClientResources::clientServerPorts[clientHashedIp];
        while (1)
        {
            try
            {
                if (ClientResources::clientUsernames.size() == clientIndex && clientIndex != 0 && ServerSettings::handleClientIndexChanges == true)
                {
                    std::cout << fmt::format("Updated client index from {} ", clientIndex);
                    clientIndex--;
                    std::cout << fmt::format("to {}", clientIndex) << std::endl;
                }

                int pingingSocket = socket(AF_INET, SOCK_STREAM, 0);

                sockaddr_in serverAddress;
                serverAddress.sin_family = AF_INET;
                serverAddress.sin_port = htons(clientServerPort);

                if (inet_pton(AF_INET, "127.0.0.1" /*replace with user ip*/, &serverAddress.sin_addr) <= 0)
                    std::cerr << "Pton conversion error in clStat" << std::endl;

                if (connect(pingingSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
                {
                    ServerSettings::exitSignal = 1;

                    std::cout << "Client disconnected. Cannot reach client server" << std::endl;

                    if (ClientResources::cleanUpInPing != false)
                    {
                        if (ClientResources::clientUsernames.size() > 1)
                            Send::BroadcastEncryptedExitMessage(clientIndex, (clientIndex + 1) % ClientResources::clientUsernames.size());

                        ClientResources::clientSocketsTcp.size() > (unsigned)clientIndex ? CleanUp::CleanUpClient(clientIndex) : CleanUp::CleanUpClient(-1, -1, clientSocketSSL);
                    }
                    else
                    {
                        std::cout << "cleanUpInPing is false. Clean up occuring somewhere else." << std::endl;
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                        ClientResources::cleanUpInPing = true; // set back to default
                    }

                    break;
                }

                const std::string statusCheckMsg = ServerSetMessage::PreLoadedSignalMessages(SignalType::STATUSCHECKSIGNAL);
                send(pingingSocket, statusCheckMsg.c_str(), statusCheckMsg.length(), 0);

                std::string readStr = Receive::ReceiveMessageTcp(pingingSocket);

                close(pingingSocket);
            }
            catch (const std::exception &e)
            {
                std::cout << "Exception caught in clStat function: " << e.what() << std::endl; // replace
                break;
            }
        }

        return;
    }

    static int acceptClientConnection(int &serverSocket)
    {
        sockaddr_in clientAddress;
        socklen_t clientLen = sizeof(clientAddress);
        return accept(serverSocket, (struct sockaddr *)&clientAddress, &clientLen);
    }
};

#endif