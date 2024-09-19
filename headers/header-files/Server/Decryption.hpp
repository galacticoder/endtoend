#pragma once

#include <iostream>
#include <fmt/core.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <cryptopp/base64.h>

class Decrypt
{
public:
    static std::string DecryptData(EVP_PKEY *privateKey, const std::string &encryptedData)
    {
        try
        {
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
            if (!ctx)
            {
                ERR_print_errors_fp(stderr);
                return "";
            }

            if (EVP_PKEY_decrypt_init(ctx) <= 0)
            {
                ERR_print_errors_fp(stderr);
                EVP_PKEY_CTX_free(ctx);
                return "";
            }

            size_t out_len;
            if (EVP_PKEY_decrypt(ctx, nullptr, &out_len, reinterpret_cast<const unsigned char *>(encryptedData.c_str()), encryptedData.size()) <= 0)
            {
                ERR_print_errors_fp(stderr);
                EVP_PKEY_CTX_free(ctx);
                return "";
            }

            std::string out(out_len, '\0');
            if (EVP_PKEY_decrypt(ctx, reinterpret_cast<unsigned char *>(&out[0]), &out_len, reinterpret_cast<const unsigned char *>(encryptedData.c_str()), encryptedData.size()) <= 0)
            {
                ERR_print_errors_fp(stderr);
                EVP_PKEY_CTX_free(ctx);
                return "";
            }

            EVP_PKEY_CTX_free(ctx);
            out.resize(out_len);
            return out;
        }
        catch (const std::exception &e)
        {
            std::cout << fmt::format("Exception caught in {}: {}", __func__, e.what()) << std::endl;
            return "";
        }
        return "";
    }
};

class Decode
{
public:
    static std::string Base64Decode(const std::string &input)
    {
        std::string decoded;
        CryptoPP::StringSource(input, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }
};
