#ifndef AES_CRYPT_H
#define AES_CRYPT_H

#include <string>
#include <cryptopp/secblock.h>

using namespace CryptoPP;

const int AES_KEY_LENGTH = 32;
const int AES_IV_LENGTH = 16;
std::string aes_encrypt(const std::string& plaintext, const SecByteBlock& key, const SecByteBlock& iv);
void generate_key_iv(::SecByteBlock& key, SecByteBlock& iv);
std::string encryptWithPreSharedKey(const SecByteBlock& key, const SecByteBlock& iv, const SecByteBlock& preSharedKey, const SecByteBlock& preSharedIV);
void decryptWithPreSharedKey(const std::string& encryptedData, SecByteBlock& key, SecByteBlock& iv, const SecByteBlock& preSharedKey, const SecByteBlock& preSharedIV);

#endif