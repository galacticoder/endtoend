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

std::mutex ClientMutex;

class CleanUp
{
private:
    static void CleanUpOpenSSL()
    {
        EVP_cleanup();
        ERR_free_strings();
        CRYPTO_cleanup_all_ex_data();
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

    static void CleanUpClient(int clientIndex, int clientSocketTcp = -1, SSL *clientSocketSSL = nullptr)
    {
        try
        {
            std::lock_guard<std::mutex> lock(ClientMutex);
            if (clientSocketTcp != -1)
                close(clientSocketTcp);
            else if (clientIndex != -1 && ClientResources::clientSocketsTcp.size() > (unsigned)clientIndex)
                close(ClientResources::clientSocketsTcp[clientIndex]);

            if (clientSocketSSL != nullptr)
            {
                SSL_shutdown(clientSocketSSL);
                SSL_free(clientSocketSSL);
            }
            std::cout << "Starting clean up of client resources" << std::endl;

            auto FreeAndDelSSL = [&](SSL *socket)
            {
                auto sslSocketIndex = std::remove(ClientResources::clientSocketsSSL.begin(), ClientResources::clientSocketsSSL.end(), socket);

                std::cout << "ClientResources::clientSocketsSSL size before: " << ClientResources::clientSocketsSSL.size() << std::endl;
                if (sslSocketIndex != ClientResources::clientSocketsSSL.end())
                {
                    ClientResources::clientSocketsSSL.erase(sslSocketIndex, ClientResources::clientSocketsSSL.end());
                }
                std::cout << "ClientResources::clientSocketsSSL size after: " << ClientResources::clientSocketsSSL.size() << std::endl;
            };

            (clientSocketSSL == nullptr) ? FreeAndDelSSL(ClientResources::clientSocketsSSL[clientIndex]) : FreeAndDelSSL(clientSocketSSL);

            auto tcpSocketIndex = std::remove(ClientResources::clientSocketsTcp.begin(), ClientResources::clientSocketsTcp.end(), ClientResources::clientSocketsTcp[clientIndex]);

            std::cout << "ClientResources::clientSocketsTcp size before: " << ClientResources::clientSocketsTcp.size() << std::endl;
            if (tcpSocketIndex != ClientResources::clientSocketsTcp.end())
            {
                ClientResources::clientSocketsTcp.erase(tcpSocketIndex, ClientResources::clientSocketsTcp.end());
            }
            std::cout << "ClientResources::clientSocketsTcp size after: " << ClientResources::clientSocketsTcp.size() << std::endl;

            if (clientIndex == -1)
            {
                std::cout << "Client clean up finished" << std::endl;
                return;
            }

            if ((unsigned)clientIndex < ClientResources::passwordVerifiedClients.size())
                ClientResources::passwordVerifiedClients.erase(ClientResources::passwordVerifiedClients.begin() + clientIndex);

            auto findClientUsername = std::find(ClientResources::clientUsernames.begin(), ClientResources::clientUsernames.end(), ClientResources::clientUsernames[clientIndex]);

            if (findClientUsername != ClientResources::clientUsernames.end())
            {
                ClientResources::clientUsernames.erase(findClientUsername);

                auto findClientKeyContents = std::find(ClientResources::clientsKeyContents.begin(), ClientResources::clientsKeyContents.end(), ClientResources::clientsKeyContents[clientIndex]);

                if (findClientKeyContents != ClientResources::clientsKeyContents.end())
                    ClientResources::clientsKeyContents.erase(deleteClientKeyContents);
                // delete client key file if exists
                if (std::filesystem::is_regular_file(PublicPath(ClientResources::clientUsernames[clientIndex])))
                    Delete::DeletePath(PublicPath(ClientResources::clientUsernames[clientIndex]));
            }

            std::cout << "Client clean up finished" << std::endl;
        }
        catch (const std::exception &e)
        {
            Error::LOGERROR(Errors::EXCEPTION, e.what(), FILE, LINE, FUNC);
        }
    }
};