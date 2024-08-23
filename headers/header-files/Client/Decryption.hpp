#ifndef _DECRYPTION_
#define _DECRYPTION_

#include <iostream>
#include <cryptopp/base64.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

class Decrypt
{
public:
    static std::string DecryptData(EVP_PKEY *privateKey, const std::string &encryptedData)
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
            // ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        std::string out(out_len, '\0');
        if (EVP_PKEY_decrypt(ctx, reinterpret_cast<unsigned char *>(&out[0]), &out_len, reinterpret_cast<const unsigned char *>(encryptedData.c_str()), encryptedData.size()) <= 0)
        {
            // ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        EVP_PKEY_CTX_free(ctx);
        out.resize(out_len);
        return out;
    }
};

struct Decode
{
    static std::string Base64Decode(const std::string &input)
    {
        std::string decoded;
        CryptoPP::StringSource(input, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }
};

#endif