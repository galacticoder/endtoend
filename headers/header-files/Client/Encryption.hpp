#ifndef _ENCRYPTION_
#define _ENCRYPTION_

#include <iostream>
#include <cryptopp/base64.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

class Encrypt
{
public:
    static std::string EncryptData(EVP_PKEY *publicKey, const std::string &data)
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(publicKey, nullptr);
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

        size_t out_len;
        if (EVP_PKEY_encrypt(ctx, nullptr, &out_len, reinterpret_cast<const unsigned char *>(data.c_str()), data.size()) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        std::string out(out_len, '\0');
        if (EVP_PKEY_encrypt(ctx, reinterpret_cast<unsigned char *>(&out[0]), &out_len, reinterpret_cast<const unsigned char *>(data.c_str()), data.size()) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "err";
        }

        EVP_PKEY_CTX_free(ctx);
        out.resize(out_len);
        return out;
    }
};

struct Encode
{
    static std::string Base64Encode(const std::string &input)
    {
        std::string encoded;
        CryptoPP::StringSource(input, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
        return encoded;
    }
};

#endif