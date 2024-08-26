#ifndef CLEANSERVER
#define CLEANSERVER

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

#define PublicPath(username) fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.pem", username)

extern std::vector<SSL *> SSLsocks;
extern std::vector<int> connectedClients;
extern std::vector<int> PasswordVerifiedClients;
extern std::vector<std::string> clientUsernames;

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

    static void CleanUpClient(int ClientIndex, SSL *ClientSSLsocket = NULL, int ClientTCPsocket = -1)
    {
        try
        {
            std::lock_guard<std::mutex> lock(ClientMutex);
            if (ClientTCPsocket != -1 && ClientIndex == -1 && ClientSSLsocket != NULL)
            {
                SSL_shutdown(ClientSSLsocket);
                SSL_free(ClientSSLsocket);
                close(ClientTCPsocket);

                auto DeleteClientTcpSocket = std::remove(connectedClients.begin(), connectedClients.end(), ClientTCPsocket);
                connectedClients.erase(DeleteClientTcpSocket, connectedClients.end());

                auto DeleteClientSSLSocket = std::remove(SSLsocks.begin(), SSLsocks.end(), ClientSSLsocket);
                SSLsocks.erase(DeleteClientSSLSocket, SSLsocks.end());

                std::cout << "Client clean up finished" << std::endl;
                return;
            }

            if (SSLsocks.size() > 0)
            {
                std::cout << "Deleting tls socks" << std::endl;
                SSL_shutdown(SSLsocks[ClientIndex]);
                std::cout << "shutdown tls socks" << std::endl;
                SSL_free(SSLsocks[ClientIndex]);
                std::cout << "freed tls socks" << std::endl;
                close(connectedClients[ClientIndex]);
                std::cout << "closed tls socks" << std::endl;

                auto DeleteClientTcpSocket = std::remove(connectedClients.begin(), connectedClients.end(), connectedClients[ClientIndex]);
                connectedClients.erase(DeleteClientTcpSocket, connectedClients.end());

                auto DeleteClientSSLSocket = std::remove(SSLsocks.begin(), SSLsocks.end(), SSLsocks[ClientIndex]);
                SSLsocks.erase(DeleteClientSSLSocket, SSLsocks.end());
            }

            if (ClientIndex < PasswordVerifiedClients.size())
                PasswordVerifiedClients.erase(PasswordVerifiedClients.begin() + ClientIndex);

            if (clientUsernames.size() > ClientIndex)
            {
                auto DeleteClientUsername = std::find(clientUsernames.begin(), clientUsernames.end(), clientUsernames[ClientIndex]);
                if (DeleteClientUsername != clientUsernames.end())
                    clientUsernames.erase(DeleteClientUsername);
            }

            Delete::DeletePath(PublicPath(clientUsernames[ClientIndex]));

            std::cout << "Client clean up finished" << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cout << "Exception caught in leaveCl: " << e.what() << std::endl;
        }
    }
};

#endif