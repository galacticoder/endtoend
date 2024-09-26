#pragma once

#include <iostream>
#include <csignal>
#include <fmt/core.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define KEYSIZE 4096

class GenerateServerCert
{
public:
    GenerateServerCert(const std::string &privateKeySavePath, const std::string &certSavePath)
    {
        EVP_PKEY *pkey = nullptr;
        X509 *x509 = nullptr;
        EVP_PKEY_CTX *pctx = nullptr;
        BIO *bio = nullptr;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!pctx)
        {
            ERR_print_errors_fp(stderr);
            return;
        }

        if (EVP_PKEY_keygen_init(pctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, KEYSIZE) <= 0 ||
            EVP_PKEY_keygen(pctx, &pkey) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(pctx);
            return;
        }
        EVP_PKEY_CTX_free(pctx);

        x509 = X509_new();
        if (!x509)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_free(pkey);
            return;
        }

        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1year
        X509_set_pubkey(x509, pkey);

        X509_NAME *name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"organization", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"common name", -1, -1, 0);

        X509_set_issuer_name(x509, name);
        if (X509_sign(x509, pkey, EVP_sha3_512()) == 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_free(pkey);
            X509_free(x509);
            return;
        }

        bio = BIO_new_file(privateKeySavePath.c_str(), "w");
        if (!bio)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_free(pkey);
            X509_free(x509);
            return;
        }
        if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1)
        {
            ERR_print_errors_fp(stderr);
        }
        BIO_free_all(bio);

        bio = BIO_new_file(certSavePath.c_str(), "w");
        if (!bio)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_free(pkey);
            X509_free(x509);
            return;
        }
        if (PEM_write_bio_X509(bio, x509) != 1)
        {
            ERR_print_errors_fp(stderr);
        }

        BIO_free_all(bio);
        EVP_PKEY_free(pkey);
        X509_free(x509);
    }
};

class LoadKey
{
public:
    static EVP_PKEY *LoadPrivateKey(const std::string &privateKeyFile)
    {
        std::cout << fmt::format("Loading server private key from path [{}]", privateKeyFile) << std::endl;
        BIO *bio = BIO_new_file(privateKeyFile.c_str(), "r");
        if (!bio)
        {
            std::cerr << "Error loading private pem key: ";
            ERR_print_errors_fp(stderr);
            return nullptr;
        }

        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey)
        {
            std::cerr << "Error loading private pem key: ";
            ERR_print_errors_fp(stderr);
            return nullptr;
        }

        std::cout << fmt::format("Loaded PEM Private key file ({}) successfully", privateKeyFile) << std::endl;

        return pkey;
    }

    static EVP_PKEY *LoadPublicKey(const std::string &publicKeyFile)
    {
        std::cout << fmt::format("Loading public key from path [{}]", publicKeyFile) << std::endl;
        BIO *bio = BIO_new_file(publicKeyFile.c_str(), "r");
        if (!bio)
        {
            ERR_print_errors_fp(stderr);
            std::cout << fmt::format("Error loading public key from path {}", publicKeyFile) << std::endl;
            return nullptr;
        }

        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey)
        {
            std::cout << fmt::format("Error loading public key from path {}", publicKeyFile) << std::endl;
            ERR_print_errors_fp(stderr);
            return nullptr;
        }
        std::cout << fmt::format("Loaded PEM Public key file ({}) successfully", publicKeyFile) << std::endl;

        return pkey;
    }

    static void extractPubKey(const std::string certFilePath, const std::string &pubKeySavePath)
    {
        FILE *certFileOpen = fopen(certFilePath.c_str(), "r");
        if (!certFileOpen)
        {
            std::cerr << "Error opening cert file: " << certFilePath << std::endl;
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

        FILE *pubkeyfile = fopen(pubKeySavePath.c_str(), "w");
        if (!pubkeyfile)
        {
            std::cerr << "Error opening pub key file: " << pubKeySavePath << std::endl;
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
};