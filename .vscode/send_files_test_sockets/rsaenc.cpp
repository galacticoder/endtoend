#include <iostream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <fmt/core.h>
#include <fstream>

using namespace std;
using namespace CryptoPP;

void genKeys() { //function to generate private and public keys
    ByteQueue queue;
    AutoSeededRandomPool rng;
    //gen private key
    RSA::PrivateKey privatekey;
    privatekey.GenerateRandomWithKeySize(rng, 4096);
    //gen public key
    RSA::PublicKey publickey(privatekey);
    //storing privatre key in file
    Base64Encoder privKeySink(new FileSink("privatekey.key"));
    privatekey.DEREncode(privKeySink);
    privKeySink.MessageEnd();

    Base64Encoder pubKeySink(new FileSink("publickey.key"));
    publickey.DEREncode(pubKeySink);
    pubKeySink.MessageEnd();
}

void Load(const string& filename, BufferedTransformation& bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

int main() {
    ByteQueue queue;
    // genKeys();
    RSA::PublicKey publickey;
    LoadPublicKey("publickey.key", publickey);
    // privatekey.BERDecode(queue);

}