#ifndef AES_CRYPT_H
#define AES_CRYPT_H

#include <string>
#include <cryptopp/secblock.h>

using namespace CryptoPP;

std::string aes_decrypt(const std::string& encrypted_text, const SecByteBlock& key, const SecByteBlock& iv);

#endif
