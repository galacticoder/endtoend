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

#define PublicPath(username) fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.pem", username)

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

    static void CleanUpClient(int clientIndex, SSL *clientSocketSSL = NULL)
    {
        try
        {
            std::lock_guard<std::mutex> lock(ClientMutex);

            if (ClientResources::clientSocketsSSL.size() > 0)
            {
                SSL_shutdown(clientSocketSSL);
                SSL_free(clientSocketSSL);

                auto sslSocketIndex = std::remove(ClientResources::clientSocketsSSL.begin(), ClientResources::clientSocketsSSL.end(), clientSocketSSL);

                close(ClientResources::clientSocketsTcp[(sslSocketIndex)-ClientResources::clientSocketsSSL.begin()]);

                auto tcpSocketIndex = std::remove(ClientResources::clientSocketsTcp.begin(), ClientResources::clientSocketsTcp.end(), ClientResources::clientSocketsTcp[(sslSocketIndex)-ClientResources::clientSocketsSSL.begin()]);

                ClientResources::clientSocketsSSL.erase(sslSocketIndex, ClientResources::clientSocketsSSL.end());

                ClientResources::clientSocketsTcp.erase(tcpSocketIndex, ClientResources::clientSocketsTcp.end());

                if (clientIndex == -1)
                {
                    std::cout << "Client clean up finished" << std::endl;
                    return;
                }
            }

            if ((unsigned)clientIndex < ClientResources::passwordVerifiedClients.size())
                ClientResources::passwordVerifiedClients.erase(ClientResources::passwordVerifiedClients.begin() + clientIndex);

            if ((unsigned)clientIndex < ClientResources::clientUsernames.size())
            {
                auto deleteClientUsername = std::find(ClientResources::clientUsernames.begin(), ClientResources::clientUsernames.end(), ClientResources::clientUsernames[clientIndex]);

                if (deleteClientUsername != ClientResources::clientUsernames.end())
                    ClientResources::clientUsernames.erase(deleteClientUsername);

                auto deleteClientKeyContents = std::find(ClientResources::clientsKeyContents.begin(), ClientResources::clientsKeyContents.end(), ClientResources::clientsKeyContents[clientIndex]);
                ClientResources::clientsKeyContents.erase(deleteClientKeyContents);

                Delete::DeletePath(PublicPath(ClientResources::clientUsernames[clientIndex])); // delete client key file
            }

            std::cout << "Client clean up finished" << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cout << "Exception caught in leaveCl: " << e.what() << std::endl;
        }
    }
};