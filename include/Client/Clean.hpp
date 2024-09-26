#pragma once

#include <unistd.h>
#include <ncurses.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

class CleanUp
{
public:
    static void cleanWins(WINDOW *win1, WINDOW *win2, WINDOW *win3)
    {
        if (win1)
            delwin(win1);
        if (win2)
            delwin(win2);
        if (win3)
            delwin(win3);

        curs_set(1);
        endwin();
    }

    static void cleanUpOpenssl(SSL *clientSocketSSL, int startSock, EVP_PKEY *receivedPublicKey, SSL_CTX *ctx)
    {
        if (clientSocketSSL)
        {
            std::cout << "Closing tlssock " << std::endl;
            SSL_shutdown(clientSocketSSL);
            SSL_free(clientSocketSSL);
            std::cout << "Closed tlssock" << std::endl;
        }
        if (startSock)
        {
            std::cout << "Closing start sock" << std::endl;
            close(startSock);
            startSock = 0;
            std::cout << "Closed start sock" << std::endl;
        }
        if (receivedPublicKey)
        {
            std::cout << "Freeing received public key " << std::endl;
            EVP_PKEY_free(receivedPublicKey);
            std::cout << "Freed received public key" << std::endl;
        }

        if (ctx)
        {
            std::cout << "Freeing SSL context" << std::endl;
            SSL_CTX_free(ctx);
            std::cout << "Freed SSL context" << std::endl;
        }
    }
};