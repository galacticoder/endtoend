#include <iostream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include "encry_to_server.h"

using namespace std;
using namespace CryptoPP;

void printHex(const std::string& label, const SecByteBlock& data) {
    std::string encoded;
    HexEncoder encoder(new StringSink(encoded));
    encoder.Put(data, data.size());
    encoder.MessageEnd();
    std::cout << label << ": " << encoded << std::endl;
}

void generate_key_iv(SecByteBlock& key, SecByteBlock& iv) {
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());
}

std::string aes_encrypt(const std::string& plaintext, const SecByteBlock& key, const SecByteBlock& iv) {
    std::string ciphertext;
    CBC_Mode<AES>::Encryption encryption(key, key.size(), iv);
    StringSource(plaintext, true,
        new StreamTransformationFilter(encryption,
            new StringSink(ciphertext),
            StreamTransformationFilter::PKCS_PADDING)
    );
    return ciphertext;
}

std::string aes_decrypt(const std::string& ciphertext, const SecByteBlock& key, const SecByteBlock& iv)
{
    std::string decrypted;
    CBC_Mode<AES>::Decryption decryption(key, key.size(), iv);
    StringSource(ciphertext, true, new StreamTransformationFilter(decryption, new StringSink(decrypted), StreamTransformationFilter::PKCS_PADDING));
    return decrypted;
}

std::string encryptWithPreSharedKey(const SecByteBlock& key, const SecByteBlock& iv, const SecByteBlock& preSharedKey, const SecByteBlock& preSharedIV) {
    std::string ciphertext;
    try {
        CBC_Mode<AES>::Encryption encryption(preSharedKey, preSharedKey.size(), preSharedIV);

        std::string plaintext(reinterpret_cast<const char*>(key.BytePtr()), key.size());
        plaintext.append(reinterpret_cast<const char*>(iv.BytePtr()), iv.size());

        StringSource ss(plaintext, true,
            new StreamTransformationFilter(encryption,
                new StringSink(ciphertext)
            )
        );
    }
    catch (const Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    return ciphertext;
}

void decryptWithPreSharedKey(const std::string& encryptedData, SecByteBlock& key, SecByteBlock& iv, const SecByteBlock& preSharedKey, const SecByteBlock& preSharedIV) {
    try {
        CBC_Mode<AES>::Decryption decryption(preSharedKey, preSharedKey.size(), preSharedIV);

        std::string plaintext;
        StringSource ss(encryptedData, true,
            new StreamTransformationFilter(decryption,
                new StringSink(plaintext)
            )
        );

        std::string decryptedKey = plaintext.substr(0, key.size());
        std::string decryptedIV = plaintext.substr(key.size());

        memcpy(key.BytePtr(), decryptedKey.data(), key.size());
        memcpy(iv.BytePtr(), decryptedIV.data(), iv.size());
    }
    catch (const Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main() {
    const int AES_KEY_LENGTH = 32; // 256-bit key
    const int AES_IV_LENGTH = 16;  // 128-bit IV

    SecByteBlock aesKey(AES_KEY_LENGTH);
    SecByteBlock aesIV(AES_IV_LENGTH); //gen keys
    generate_key_iv(aesKey, aesIV);

    printHex("AES Key", aesKey);
    printHex("AES IV", aesIV); //only printing the hex not converting

    SecByteBlock preSharedKey(AES_KEY_LENGTH);
    SecByteBlock preSharedIV(AES_IV_LENGTH);     // define a pre-shared secret key and iv for encryption
    generate_key_iv(preSharedKey, preSharedIV);

    printHex("Pre-Shared Key", preSharedKey);
    printHex("Pre-Shared IV", preSharedIV);

    std::string encryptedData = encryptWithPreSharedKey(aesKey, aesIV, preSharedKey, preSharedIV);     // encrypt the aes key and iv with the pre-shared secret

    string text = "some strng message from  cleint user or whatevr";
    string textE = aes_encrypt(text, aesKey, aesIV);
    string unencry = aes_decrypt(textE, aesKey, aesIV);
    cout << "unencry: " << unencry << endl;

    string unencryptedCipher;

    // send the encrypted data to the server
    cout << "Encrypted key and iv sent to Server: " << encryptedData << endl;
    cout << "sent cipher text from user: " << textE << endl;

    //server side handling

    SecByteBlock receivedKey(AES_KEY_LENGTH);
    SecByteBlock receivedIV(AES_IV_LENGTH);
    decryptWithPreSharedKey(encryptedData, receivedKey, receivedIV, preSharedKey, preSharedIV); // decrypt the received data from the server
    // buffer[bytesReceived] = '\0';

    // cout << "Decoded Iv: " <<  << endl;
    // printHex("Received AES IV: ", receivedIV);

    cout << "\tTrying to decrypt" << endl;

    cout << "Decrypted cipher: " << aes_decrypt(textE, aesKey, aesIV) << endl;

    cout << "\t\t\t\t\tthis" << endl;


    return 0;
}
