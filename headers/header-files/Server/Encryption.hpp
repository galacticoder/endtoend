#pragma once

#include <iostream>
#include <sstream>
#include <iomanip>
#include <fmt/core.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <cryptopp/base64.h>
#include "Decryption.hpp"

class Encrypt
{
public:
    static std::string EncryptData(EVP_PKEY *privateKey, const std::string &data)
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
        if (!ctx)
        {
            ERR_print_errors_fp(stderr);
            return "";
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        size_t outLen;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outLen, reinterpret_cast<const unsigned char *>(data.c_str()), data.size()) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        std::string out(outLen, '\0');
        if (EVP_PKEY_encrypt(ctx, reinterpret_cast<unsigned char *>(&out[0]), &outLen, reinterpret_cast<const unsigned char *>(data.c_str()), data.size()) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        EVP_PKEY_CTX_free(ctx);
        out.resize(outLen);

        return out;
    }
};

class Hash
{
public:
    static std::string hashData(const std::string &data)
    {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int lenHash = 0;
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (mdctx == nullptr)
        {
            std::cout << "Error creating ctx" << std::endl;
            return "err";
        }

        if (EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr) != 1)
        {
            std::cout << "Error initializing digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return "err";
        }

        if (EVP_DigestUpdate(mdctx, data.c_str(), data.size()) != 1)
        {
            std::cout << "Error updating digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return "err";
        }
        if (EVP_DigestFinal_ex(mdctx, hash, &lenHash) != 1)
        {
            std::cout << "Error finalizing digest" << std::endl;
            EVP_MD_CTX_free(mdctx);
            return "err";
        }

        EVP_MD_CTX_free(mdctx);

        std::stringstream ss;
        for (unsigned int i = 0; i < lenHash; ++i)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str(); // returning hash
    }
};

class Encode
{
public:
    static std::string Base64Encode(const std::string &input)
    {
        std::string encoded;
        CryptoPP::StringSource(input, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
        return encoded;
    }

    static int CheckBase64(const std::string &message)
    {
        for (int i = 0; (unsigned)i < message.size(); i++)
        {
            if (static_cast<unsigned char>(message[i]) > 128)
            {
                return -1;
            }
        }

        return 0;
    }
};
