#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>

//perfect so tomorrow im going to do the client and server and implement this script i wrote in their it shouldnt be hard this was the hard part
using namespace CryptoPP;
using namespace std;

void generateAndSaveRSAKeyPair(const std::string& privateKeyFile, const std::string& publicKeyFile, unsigned int keySize = 2048) {
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, keySize);

    RSA::PublicKey publicKey(privateKey);

    {
        FileSink file(privateKeyFile.c_str());
        privateKey.DEREncode(file);
    }
    {
        FileSink file(publicKeyFile.c_str());
        publicKey.DEREncode(file);
    }

    cout << "rsa key pair generated" << endl;
}

bool loadPrv(const std::string& privateKeyFile, RSA::PrivateKey& privateKey) {
    try {
        FileSource file(privateKeyFile.c_str(), true /*pumpAll*/);
        privateKey.BERDecode(file);
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "error loading private rsa key: " << e.what() << std::endl;
        return false;
    }

    return true;
}

//for pub key
bool loadPub(const std::string& publicKeyFile, RSA::PublicKey& publickey) {
    try {
        FileSource file(publicKeyFile.c_str(), true /*pumpAll*/);
        publickey.BERDecode(file);
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "error loading public rsa key: " << e.what() << std::endl;
        return false;
    }

    return true;
}

string enc(RSA::PublicKey& pubkey, string& plain) {
    AutoSeededRandomPool rng; //using diff rng for better randomness
    string cipher;
    RSAES_OAEP_SHA512_Encryptor e(pubkey); //make sure to push rsa.h or you get errors cuz its modified to sha512 instead of sha1 for better security
    StringSource ss1(plain, true, new PK_EncryptorFilter(rng, e, new StringSink(cipher))); //nested for better verification of both key loading
    return cipher;
}

string dec(RSA::PrivateKey& prvkey, string& cipher) {
    AutoSeededRandomPool rng; //using diff rng for better randomness
    string decrypted;
    RSAES_OAEP_SHA512_Decryptor d(prvkey);//modified to decrypt sha512
    StringSource ss2(cipher, true, new PK_DecryptorFilter(rng, d, new StringSink(decrypted)));
    return decrypted;
}

int main() {
    // AutoSeededRandomPool rng; //using diff rng for better randomness
    const std::string privateKeyFile = "private.der";//key file path to save to
    const std::string publicKeyFile = "public.der";
    generateAndSaveRSAKeyPair(privateKeyFile, publicKeyFile);
    string plain = "somhrhhrtyhtrhtrhtrtt", cipher, decrypted;

    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    if (loadPrv(privateKeyFile, privateKey)) { //time to add encryption part now this is the fun part
        std::cout << "RSA private key loaded successfully.(1/2)" << std::endl;
        if (loadPub(publicKeyFile, publicKey)) {
            std::cout << "RSA public key loaded successfully.(2/2)" << std::endl;
            cipher = enc(publicKey, plain);
            cout << "cipher: " << cipher << endl;
        }
        else {
            std::cerr << "Failed to load RSA public key." << std::endl;
            return 1;
        }
        //mess around with server code if private key loaded but nest pub key loading too
        decrypted = dec(privateKey, cipher);
        cout << "decrypted: " << decrypted << endl;
    }
    else {
        std::cerr << "Failed to load RSA private key." << std::endl;
        return 1;
    }

    return 0;
}
