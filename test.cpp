#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <atomic>
#include <boost/asio.hpp>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fmt/core.h>
#include <fstream>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <queue>
#include <regex>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#define ServerKeysPath "server-keys"
#define ServerPrivateKeyPath "server-keys"
#define ServerCertPath ServerKeysPath + "server-keys"
#define ServerReceivedKeysPath "server-recieved-client-keys/"

class Networking
{
private:
    // static int defaultPort;

public:
    static int findAvailablePort()
    {
        int defaultPort = 8080;
        int port;
        int pavtempsock;
        struct sockaddr_in addr;
        pavtempsock = socket(AF_INET, SOCK_STREAM, 0);

        if (pavtempsock < 0)
        {
            std::cerr << "Cannot create socket to test port availability" << std::endl;
            return -1;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;

        for (unsigned short i = 49152; i <= 65535; i++)
        {
            if (defaultPort != -1)
            {

                addr.sin_port = htons(i);
                if (bind(pavtempsock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
                    defaultPort = -1;
                else
                    return defaultPort;
            }

            if (bind(pavtempsock, (struct sockaddr *)&addr, sizeof(addr)) >= 0)
            {
                port = i;
                break;
            }
        }
        close(pavtempsock);
        return port;
    }

    static int startServerSocket(int &port)
    {
        int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        int *serverSocketPointer = &serverSocket;

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
        std::cout << fmt::format("Server listening on port {}", port) << "\n";
        std::cout << "in class: " << serverSocketPointer << "\n";
        std::cout << "dereferenced in class: " << serverSocket << std::endl;
        return serverSocket;
    }
};

int main()
{
    int port = Networking::findAvailablePort();
    std::cout << "Port is: " << port << std::endl;

    int serverSocket = Networking::startServerSocket(port);
    // std::cout << "Serversocket addr: " << serverSocket << std::endl;
    // int serverSocketDeref = *serverSocket;
    std::cout << "dereferenced: " << serverSocket << std::endl;
    // std::cout << "dereferenced: " << serverSocket << std::endl;
    // const std::string ServerPublicKeyPath = (std::string)ServerKeysPath + "/server-pubkey.pem";
    // std::cout << "dereferenced: " << ServerPublicKeyPath << std::endl;

    // close(serverSocket);
}