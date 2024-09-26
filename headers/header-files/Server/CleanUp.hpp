#pragma once

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>
#include <mutex>
#include <algorithm>
#include <vector>
#include <unordered_map>
#include "FileHandler.hpp"
#include "Keys.hpp"
#include "Encryption.hpp"
#include "SendAndReceive.hpp"
#include "ServerSettings.hpp"

std::mutex clientCleanUpMutex;
extern void printUsersConnected();

class CleanUp
{
private:
    static void CleanUpOpenSSL()
    {
        EVP_cleanup();
        ERR_free_strings();
        CRYPTO_cleanup_all_ex_data();
    }

    static void FreeAndDelSSL(SSL *socket)
    {
        auto sslSocketIndex = std::remove(ClientResources::clientSocketsSSL.begin(), ClientResources::clientSocketsSSL.end(), socket);

        std::cout << "ClientResources::clientSocketsSSL size before: " << ClientResources::clientSocketsSSL.size() << std::endl;
        if (sslSocketIndex != ClientResources::clientSocketsSSL.end())
        {
            ClientResources::clientSocketsSSL.erase(sslSocketIndex, ClientResources::clientSocketsSSL.end());
        }
        std::cout << "ClientResources::clientSocketsSSL size after: " << ClientResources::clientSocketsSSL.size() << std::endl;
    }

    static void FreeAndDelTCP(int &socket)
    {
        auto tcpSocketIndex = std::remove(ClientResources::clientSocketsTcp.begin(), ClientResources::clientSocketsTcp.end(), socket);

        std::cout << "ClientResources::clientSocketsTcp size before: " << ClientResources::clientSocketsTcp.size() << std::endl;
        if (tcpSocketIndex != ClientResources::clientSocketsTcp.end())
        {
            ClientResources::clientSocketsTcp.erase(tcpSocketIndex, ClientResources::clientSocketsTcp.end());
        }
        std::cout << "ClientResources::clientSocketsTcp size after: " << ClientResources::clientSocketsTcp.size() << std::endl;
    }

    static void FindAndDelPassword(unsigned int &clientIndex)
    {
        std::cout << "ClientResources::passwordVerifiedClients size before: " << ClientResources::passwordVerifiedClients.size() << std::endl;

        if ((unsigned)clientIndex < ClientResources::passwordVerifiedClients.size())
            ClientResources::passwordVerifiedClients.erase(ClientResources::passwordVerifiedClients.begin() + clientIndex);

        std::cout << "ClientResources::passwordVerifiedClients size after: " << ClientResources::passwordVerifiedClients.size() << std::endl;
    }

    static void FindAndDelUsername(unsigned int &clientIndex)
    {
        auto findClientUsername = std::find(ClientResources::clientUsernames.begin(), ClientResources::clientUsernames.end(), ClientResources::clientUsernames[clientIndex]);

        if (findClientUsername != ClientResources::clientUsernames.end())
        {
            std::cout << "ClientResources::clientUsernames size before: " << ClientResources::clientUsernames.size() << std::endl;

            ClientResources::clientUsernames.erase(findClientUsername);

            std::cout << "ClientResources::clientUsernames size after: " << ClientResources::clientUsernames.size() << std::endl;
        }
    }

    static void DeleteClientKeys(unsigned int &clientIndex)
    {
        auto findClientUsername = std::find(ClientResources::clientUsernames.begin(), ClientResources::clientUsernames.end(), ClientResources::clientUsernames[clientIndex]);

        if (findClientUsername != ClientResources::clientUsernames.end())
        {
            // delete client key file if exists
            if (std::filesystem::is_regular_file(PublicPath(ClientResources::clientUsernames[clientIndex])))
            {
                Delete::DeletePath(PublicPath(ClientResources::clientUsernames[clientIndex]));

                (!std::filesystem::is_regular_file(PublicPath(ClientResources::clientUsernames[clientIndex]))) ? std::cout << fmt::format("Deleted {}'s public key from server", ClientResources::clientUsernames[clientIndex]) << std::endl : std::cout << fmt::format("Could not delete {}'s public key from server", ClientResources::clientUsernames[clientIndex]) << std::endl;
            }

            auto findClientKeyContents = std::find(ClientResources::clientsKeyContents.begin(), ClientResources::clientsKeyContents.end(), ClientResources::clientsKeyContents[clientIndex]);

            if (findClientKeyContents != ClientResources::clientsKeyContents.end())
            {
                std::cout << "ClientResources::clientsKeyContents size before: " << ClientResources::clientsKeyContents.size() << std::endl;

                ClientResources::clientsKeyContents.erase(findClientKeyContents);

                std::cout << "ClientResources::clientsKeyContents size after: " << ClientResources::clientsKeyContents.size() << std::endl;
            }
        }
    }

public:
    static void CleanUpServer(SSL_CTX *serverCtx, int &serverSocket)
    {
        SSL_CTX_free(serverCtx);
        close(serverSocket);

        Delete::DeletePath(ServerKeysPath);
        Delete::DeletePath(ServerReceivedKeysPath);

        CleanUpOpenSSL();
    }

    static void CleanUpClient(unsigned int clientIndex)
    {
        try
        {
            std::lock_guard<std::mutex> lock(clientCleanUpMutex);
            std::cout << "Client index in clean up: " << clientIndex << std::endl;

            close(ClientResources::clientSocketsTcp[clientIndex]);

            SSL_shutdown(ClientResources::clientSocketsSSL[clientIndex]);
            SSL_free(ClientResources::clientSocketsSSL[clientIndex]);

            std::cout << "Starting clean up of client resources" << std::endl;

            FreeAndDelSSL(ClientResources::clientSocketsSSL[clientIndex]);
            FreeAndDelTCP(ClientResources::clientSocketsTcp[clientIndex]);
            FindAndDelPassword(clientIndex);
            DeleteClientKeys(clientIndex);
            FindAndDelUsername(clientIndex);

            std::cout << "Client clean up finished" << std::endl;
            printUsersConnected();
        }
        catch (const std::exception &e)
        {
            std::cout << fmt::format("[{}:{}] Exception caught [in function {}]: {}", __FILE__, __LINE__, __func__, e.what()) << std::endl;
        }
    }
};