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
        }
        curs_set(1);
        endwin();
    }

    static void cleanUpOpenssl(SSL *tlsSock, int startSock, EVP_PKEY *receivedPublicKey, EVP_PKEY *prkey, SSL_CTX *ctx)
    {
        if (tlsSock)
        {
            SSL_shutdown(tlsSock);
            SSL_free(tlsSock);
            tlsSock = nullptr;
        }
        if (startSock)
        {
            close(startSock);
            startSock = 0;
        }
        if (receivedPublicKey)
        {
            EVP_PKEY_free(receivedPublicKey);
            receivedPublicKey = nullptr;
        }

        if (prkey)
        {
            EVP_PKEY_free(prkey);
            prkey = nullptr;
        }

        if (ctx)
        {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }

        EVP_cleanup();
    }
};

#endif
