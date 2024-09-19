#pragma once

#include <iostream>
#include <csignal>
#include <fmt/core.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

class TlsSetup
{
public:
    static void LoadSSLAlgs()
    {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
    }

    static SSL_CTX *CreateCtx()
    {
        const SSL_METHOD *method = SSLv23_server_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        if (!ctx)
        {
            ERR_print_errors_fp(stderr);
            raise(SIGINT);
        }
        return ctx;
    }

    static void ConfigureCtx(SSL_CTX *ctx, const std::string &certPath, const std::string &privateKeyPath)
    {
        const char *certPathFormatted = certPath.c_str();
        const char *privateKeyPathFormatted = privateKeyPath.c_str();

        std::cout << fmt::format("Private key path passed: {}", privateKeyPathFormatted) << std::endl;
        std::cout << fmt::format("Cert path passed: {}", certPathFormatted) << std::endl;

        if (SSL_CTX_use_certificate_file(ctx, certPathFormatted, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            std::cout << "Could not find cert file at path: " << certPathFormatted << std::endl;
            raise(SIGINT);
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, privateKeyPathFormatted, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            raise(SIGINT);
        }
        const char *cipherList = "ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:";

        if (SSL_CTX_set_cipher_list(ctx, cipherList) <= 0)
        {
            ERR_print_errors_fp(stderr);
            raise(SIGINT);
        }
    }
};
