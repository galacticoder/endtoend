#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
// #include "encry.h"
#include <vector>


using namespace CryptoPP;
using namespace std;

static const unsigned int KEYSIZE = 4096;

//put all key gen part in a class

struct KeysMake {
    // make constructor that generates the keys
    KeysMake(const std::string privateKeyFile, const std::string publicKeyFile, unsigned int keySize = KEYSIZE) {
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
};

struct LoadKey {
    LoadKey() = default;
    bool loadPrv(const std::string& privateKeyFile, RSA::PrivateKey& privateKey) {
        try {
            FileSource file(privateKeyFile.c_str(), true /*pumpAll*/);
            privateKey.BERDecode(file);
            cout << "Loaded RSA Private key successfuly" << endl;
        }
        catch (const Exception& e) {
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
            cout << "Loaded RSA Public key file (" << publicKeyFile << ") successfuly" << endl;
        }
        catch (const Exception& e) {
            std::cerr << "error loading public rsa key: " << e.what() << std::endl;
            return false;
        }

        return true;
    }
};

struct Enc {
    Enc() = default;
    string enc(RSA::PublicKey& pubkey, string& plain) {
        AutoSeededRandomPool rng; //using diff rng for better randomness
        string cipher;
        RSAES_OAEP_SHA512_Encryptor e(pubkey); //make sure to push rsa.h or you get errors cuz its modified to sha512 instead of sha1 for better security
        StringSource ss1(plain, true, new PK_EncryptorFilter(rng, e, new StringSink(cipher))); //nested for better verification of both key loading
        return cipher;
    }
    std::string Base64Encode(const std::string& input) {
        std::string encoded;
        StringSource(input, true, new Base64Encoder(new StringSink(encoded), false));
        return encoded;
    }
    string hexencode(string& cipher) {
        string encoded;
        CryptoPP::StringSource(cipher, true /*pump all*/, new CryptoPP::HexDecoder(new CryptoPP::StringSink(encoded)));
        cout << encoded << endl;
        return encoded;
    }


};

struct Dec {
    Dec() = default;
    string dec(RSA::PrivateKey& prvkey, string& cipher) {
        AutoSeededRandomPool rng; //using diff rng for better randomness
        string decrypted;
        RSAES_OAEP_SHA512_Decryptor d(prvkey);//modified to decrypt sha512
        StringSource ss2(cipher, true, new PK_DecryptorFilter(rng, d, new StringSink(decrypted)));
        return decrypted;
    }
    std::string Base64Decode(const std::string& input) {
        std::string decoded;
        StringSource(input, true, new Base64Decoder(new StringSink(decoded)));
        return decoded;
    }
    string hexdecode(string& encoded) {
        string decoded;
        CryptoPP::StringSource ssv(encoded, true /*pump all*/, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }
};

// std::string Base64Encode(const std::string& input) {
//     std::string encoded;
//     StringSource(input, true, new Base64Encoder(new StringSink(encoded), false));
//     return encoded;
// }

// std::string Base64Decode(const std::string& input) {
//     std::string decoded;
//     StringSource(input, true, new Base64Decoder(new StringSink(decoded)));
//     return decoded;
// }

// string hexencode(string& cipher) {
//     string encoded;
//     CryptoPP::StringSource(cipher, true /*pump all*/, new CryptoPP::HexDecoder(new CryptoPP::StringSink(encoded)));
//     cout << encoded << endl;
//     return encoded;
// }

// string hexdecode(string& encoded) {
//     string decoded;
//     CryptoPP::StringSource ssv(encoded, true /*pump all*/, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
//     return decoded;
// }

// void generateAndSaveRSAKeyPair(const std::string privateKeyFile, const std::string publicKeyFile, unsigned int keySize) {
//     AutoSeededRandomPool rng;
//     RSA::PrivateKey privateKey;
//     privateKey.GenerateRandomWithKeySize(rng, keySize);

//     RSA::PublicKey publicKey(privateKey);

//     {
//         FileSink file(privateKeyFile.c_str());
//         privateKey.DEREncode(file);
//     }
//     {
//         FileSink file(publicKeyFile.c_str());
//         publicKey.DEREncode(file);
//     }

//     cout << "rsa key pair generated" << endl;
// }

// void base64file(string& pubfilepath, string* bsvar) {
//     ifstream pubkey(pubfilepath, ios::binary);
//     if (pubkey.is_open()) {
//         pubkey.seekg(0, ios::end); //from beggioning of file to end
//         streamsize size = pubkey.tellg();
//         pubkey.seekg(0, ios::beg);
//         static vector<char> buff(size); //static for only this file we dont want any other to access this
//         //.data for pointer to first in buff
//         if (pubkey.read(buff.data(), size)) {
//             cout << "opened file" << endl; //later use this to convert to base 64;
//             string b64d;
//             StringSource(reinterpret_cast<const unsigned char*>(buff.data()), buff.size(), true,
//                 new Base64Encoder(
//                     new StringSink(b64d),
//                     false
//                 )
//             );
//             bsvar->clear(); //clears string var
//             *bsvar = b64d; //dereference at addr
//             // cout << "b64d: " << b64d << endl;

//             //see converting then save to a new base 64 file as {user}-pubkeyb64.der
//         }
//         else {
//             cout << "failed reading file '" << pubfilepath << "'" << endl;
//         }
//     }
//     else {
//         cout << "failed opening file '" << pubfilepath << "'" << endl;
//     }
//     pubkey.close();

// }

// string serialize(RSA::PublicKey& publickey) {
//     string serialized;
//     StringSink Sink(serialized);
//     publickey.DEREncode(Sink);
//     return serialized;
// }

// bool loadPrv(const std::string& privateKeyFile, RSA::PrivateKey& privateKey) {
//     try {
//         FileSource file(privateKeyFile.c_str(), true /*pumpAll*/);
//         privateKey.BERDecode(file);
//         cout << "Loaded RSA Private key successfuly" << endl;
//     }
//     catch (const Exception& e) {
//         std::cerr << "error loading private rsa key: " << e.what() << std::endl;
//         return false;
//     }

//     return true;
// }

// //for pub key
// bool loadPub(const std::string& publicKeyFile, RSA::PublicKey& publickey) {
//     try {
//         FileSource file(publicKeyFile.c_str(), true /*pumpAll*/);
//         publickey.BERDecode(file);
//         cout << "Loaded RSA Public key file (" << publicKeyFile << ") successfuly" << endl;
//     }
//     catch (const Exception& e) {
//         std::cerr << "error loading public rsa key: " << e.what() << std::endl;
//         return false;
//     }

//     return true;
// }

// string enc(RSA::PublicKey& pubkey, string& plain) {
//     AutoSeededRandomPool rng; //using diff rng for better randomness
//     string cipher;
//     RSAES_OAEP_SHA512_Encryptor e(pubkey); //make sure to push rsa.h or you get errors cuz its modified to sha512 instead of sha1 for better security
//     StringSource ss1(plain, true, new PK_EncryptorFilter(rng, e, new StringSink(cipher))); //nested for better verification of both key loading
//     return cipher;
// }

// string dec(RSA::PrivateKey& prvkey, string& cipher) {
//     AutoSeededRandomPool rng; //using diff rng for better randomness
//     string decrypted;
//     RSAES_OAEP_SHA512_Decryptor d(prvkey);//modified to decrypt sha512
//     StringSource ss2(cipher, true, new PK_DecryptorFilter(rng, d, new StringSink(decrypted)));
//     return decrypted;
// }

// int main()
// {
//     //Generate params
//     AutoSeededRandomPool rng;
//     InvertibleRSAFunction params;
//     params.Initialize(rng, 4096);

//     //Generate Keys
//     RSA::PrivateKey privKey(params);
//     RSA::PublicKey pubKey(params);

//     //Encode keys to Base64
//     string encodedPriv, encodedPub;

//     Base64Encoder privKeySink(new StringSink(encodedPriv));
//     privKey.DEREncode(privKeySink);
//     privKeySink.MessageEnd();

//     Base64Encoder pubKeySink(new StringSink(encodedPub));
//     pubKey.DEREncode(pubKeySink);
//     pubKeySink.MessageEnd();

//     cout << encodedPriv;

//     RSA::PrivateKey pvKeyDecoded;
//     RSA::PublicKey pbKeyDecoded;

//     StringSource ss(encodedPriv, true, new Base64Decoder);
//     pvKeyDecoded.BERDecode(ss);

//     //how to decode...

//     cin.get();
//     return 0;
// }

// int main() {
//     string publicKeyFile = "user-keys/pub/jkhfgh-pubkey.der"; //a problem with how the files are sending to the se3rver some data loss of the file so ima fix it by encoding the file with base 64 and then decoding it when were gonna try decrypting the key
//     string privateKeyFile = "user-keys/prv/jkhfgh-privkey.der";
//     string b;
//     // KeysMake keysgen(privateKeyFile, publicKeyFile, &b);

//     string privkeyname = "user-keys/prv/jkhfgh-privkeyb64.der"; //a problem with how the files are sending to the se3rver some data loss of the file so ima fix it by encoding the file with base 64 and then decoding it when were gonna try decrypting the key
//     RSA::PrivateKey privateKey;

//     LoadKey priv;
//     priv.LoadPrivateKey(privkeyname, privateKey);
    // string publicKeyFileServer = "keys-server/jkhfgh-pubkeyserver.der";
    // string publicKeyFileServer = "keys-recv/jkhfgh-pubkeyserverfromser.der";
    // string text = "some text";
    // string b1;
    // base64file(publicKeyFile, &b1);
    // cout << "b1: " << b1 << endl;
    // cout << "opening server pub client recv file" << endl;
    // string b2;
    // base64file(publicKeyFileServer, &b2);
    // cout << "b2: " << b2 << endl;

    // if (b2 == b1) {
    //     cout << "\tTHEY ARE EQUAL" << endl;
    // }
    // else {
    //     cout << "\tTHEY ARE NOT EQUAL" << endl; //so problem arises when sending the file from the server to the client 2 after client 1 sends it to the srver and the server broadcasts it
    // }

    // RSA::PublicKey pub;
    // RSA::PrivateKey prvk;

    // if (!loadPub(publicKeyFile, pub) || !loadPrv(privateKeyFile, prvk)) {
    //     return -1;
    // }

    // string encrypted = enc(pub, text);
    // string encoded = Base64Encode(encrypted);//when sending the key we can encode it and then send it and decode it at the destination which is client 2
    // string decoded = Base64Decode(encoded);

    // cout << "Original Text: " << text << endl;
    // cout << "Encrypted (Hex): " << hexencode(encrypted) << endl;
    // cout << "Encoded: " << encoded << endl;
    // cout << "Decoded (Hex): " << hexencode(decoded) << endl;

    // if (encrypted == decoded) {
    //     cout << "Decoded matches encrypted." << endl;
    // }
    // else {
    //     cout << "Decoded does NOT match encrypted!" << endl;
    // }

    // try {
    //     string decrypted = dec(prvk, decoded);
    //     cout << "Decrypted: " << decrypted << endl;
    // }
    // catch (const Exception& e) {
    //     cerr << "Decryption failed: " << e.what() << endl;
    // }
// return 0;
// }

// int main() {
//     // AutoSeededRandomPool rng; //using diff rng for better randomness
//     const std::string privateKeyFile = "private.der";//key file path to save to
//     const std::string publicKeyFile = "public.der";
//     generateAndSaveRSAKeyPair(privateKeyFile, publicKeyFile);
//     string plain = "somhrhhrtyhtrhtrhtrtt", cipher, decrypted;

//     RSA::PrivateKey privateKey;
//     RSA::PublicKey publicKey;
//     if (loadPrv(privateKeyFile, privateKey)) { //time to add encryption part now this is the fun part
//         std::cout << "RSA private key loaded successfully.(1/2)" << std::endl;
//         if (loadPub(publicKeyFile, publicKey)) {
//             std::cout << "RSA public key loaded successfully.(2/2)" << std::endl;
//             cipher = enc(publicKey, plain);
//             cout << "cipher: " << cipher << endl;
//         }
//         else {
//             std::cerr << "Failed to load RSA public key." << std::endl;
//             return 1;
//         }
//         //mess around with server code if private key loaded but nest pub key loading too
//         decrypted = dec(privateKey, cipher);
//         cout << "decrypted: " << decrypted << endl;
//     }
//     else {
//         std::cerr << "Failed to load RSA private key." << std::endl;
//         return 1;
//     }

//     return 0;
// }
