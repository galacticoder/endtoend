#ifndef KEY
#define KEY

#include <iostream>
#include <fstream>
#include <cryptopp/base64.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <csignal>
#include <fmt/core.h>

#define KEYSIZE 4096

class GenerateKeys
{
public:
    GenerateKeys(const std::string &privateKeyFile, const std::string &publicKeyFile, int bits = KEYSIZE)
    {
        std::cout << "Generating keys.." << std::endl;
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx)
        {
            ERR_print_errors_fp(stderr);
            raise(SIGINT);
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            raise(SIGINT);
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            raise(SIGINT);
        }

        EVP_PKEY *pkey = NULL;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            raise(SIGINT);
        }

        EVP_PKEY_CTX_free(ctx);

        BIO *privateKeyBio = BIO_new_file(privateKeyFile.c_str(), "w+");
        PEM_write_bio_PrivateKey(privateKeyBio, pkey, NULL, NULL, 0, NULL, NULL);
        BIO_free_all(privateKeyBio);

        BIO *publicKeyBio = BIO_new_file(publicKeyFile.c_str(), "w+");
        PEM_write_bio_PUBKEY(publicKeyBio, pkey);
        BIO_free_all(publicKeyBio);

        EVP_PKEY_free(pkey);
    }
};

class LoadKey
{
public:
    static void extractPubKey(const std::string certFile, const std::string &pubKey)
    {
        FILE *certFileOpen = fopen(certFile.c_str(), "r");
        if (!certFileOpen)
        {
            std::cerr << "Error opening cert file: " << certFile << std::endl;
            return;
        }

        X509 *cert = PEM_read_X509(certFileOpen, nullptr, nullptr, nullptr);
        fclose(certFileOpen);
        if (!cert)
        {
            std::cerr << "Error reading certificate" << std::endl;
            return;
        }

        EVP_PKEY *pubkey = X509_get_pubkey(cert);
        if (!pubkey)
        {
            std::cerr << "Error extracting pubkey from cert" << std::endl;
            X509_free(cert);
            return;
        }

        FILE *pubkeyfile = fopen(pubKey.c_str(), "w");
        if (!pubkeyfile)
        {
            std::cerr << "Error opening pub key file: " << pubKey << std::endl;
            EVP_PKEY_free(pubkey);
            X509_free(cert);
            return;
        }

        if (PEM_write_PUBKEY(pubkeyfile, pubkey) != 1)
        {
            std::cerr << "Error writing public key to file" << std::endl;
        }

        fclose(pubkeyfile);
        EVP_PKEY_free(pubkey);
        X509_free(cert);
        ERR_free_strings();
    }

    static EVP_PKEY *LoadPrivateKey(const std::string &privateKeyFile, const short echo = 1 /*Echo output or not. On by default. Off is 0 */)
    {
        BIO *bio = BIO_new_file(privateKeyFile.c_str(), "r");
        if (!bio)
        {
            std::cerr << "Error loading private rsa key: ";
            ERR_print_errors_fp(stderr);
            return nullptr;
        }

        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey)
        {
            std::cerr << "Error loading private rsa key: ";
            ERR_print_errors_fp(stderr);
            return nullptr;
        }

        if (echo == 1)
            std::cout << "Loaded RSA Private key file (" << privateKeyFile << ") successfuly" << std::endl;

        return pkey;
    }

    static EVP_PKEY *LoadPublicKey(const std::string &publicKeyFile, const short echo = 1 /*Echo output or not. On by default. Off is 0 */)
    {
        BIO *bio = BIO_new_file(publicKeyFile.c_str(), "r");
        if (!bio)
        {
            ERR_print_errors_fp(stderr);
            std::cerr << fmt::format("Error loading public rsa key from path {}", publicKeyFile) << std::endl;
            return nullptr;
        }

        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey)
        {
            std::cerr << fmt::format("Error loading public rsa key from path {}", publicKeyFile) << std::endl;
            return nullptr;
        }

        if (echo != 0)
            std::cout << "Loaded RSA Public key file (" << publicKeyFile << ") successfuly" << std::endl;

        return pkey;
    }
};

#endif