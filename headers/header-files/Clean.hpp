#ifndef CLEANUP
#define CLEANUP

#include <unistd.h>
#include <ncurses.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

class cleanUp
{
public:
    static void cleanWins(WINDOW *win1, WINDOW *win2, WINDOW *win3)
    {
        if (win1)
        {
            delwin(win1);
        }
        if (win2)
        {
            delwin(win2);
        }
        if (win3)
        {
            delwin(win3);
            curs_set(1);
            endwin();
        }
    }

    static void cleanUpOpenssl(SSL *tlsSock, int startSock, EVP_PKEY *receivedPublicKey, EVP_PKEY *prkey, SSL_CTX *ctx)
    {
        if (tlsSock)
        {
            std::cout << "Closing tlssock " << std::endl;
            SSL_shutdown(tlsSock);
            SSL_free(tlsSock);
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

        if (prkey)
        {
            std::cout << "Freeing private key" << std::endl;
            EVP_PKEY_free(prkey);
            std::cout << "Freed private key" << std::endl;
        }

        if (ctx)
        {
            std::cout << "Freeing SSL context" << std::endl;
            SSL_CTX_free(ctx);
            std::cout << "Freed SSL context" << std::endl;
        }
    }
};

#endif
