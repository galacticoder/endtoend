#ifndef SIGNALHANDLER
#define SIGNALHANDLER

#include <iostream>
#include <csignal>
#include "Keys.hpp"
#include "SendAndReceive.hpp"
#include "FileHandling.hpp"
#include "Decryption.hpp"
#include "Encryption.hpp"

std::function<void(int)> shutdownHandler;
std::function<void(int)> windowCleaning;
std::function<EVP_PKEY *(int)> valuePasser;

std::vector<std::string> signalsVector = {
    "KEYLOADERROR",
    "KEYEXISTERR",
    "PASSWORDVERIFIED",
    "PASSWORDNOTVERIFIED",
    "NAMEEXISTSERR",
    "SERVERNEEDSREQUEST",
    "RATELIMITED",
    "USERLIMITREACHED",
    "USERACCEPTED",
    "USERNOTACCEPTED",
    "CLIENTREJOIN",
    "PASSWORDNEEDED",
    "PASSWORDNOTNEEDED",
    "INVALIDNAMECHARS",
    "INVALIDNAMELENGTH",
    "OKAYSIGNAL",
    "SERVERJOINREQUESTDENIED",
    "SERVERJOINREQUESTACCEPTED",
    "CONNECTIONSIGNAL",
    "BLACKLISTED",
};

enum class SignalType
{
    KEYLOADERROR,
    EXISTERR,
    VERIFIED,
    NOTVERIFIED,
    NAMEEXISTSERR,
    REQUESTNEEDED,
    RATELIMITED,
    SERVERLIMIT,
    ACCEPTED,
    NOTACCEPTED,
    CLIENTREJOIN,
    PASSWORDNEEDED,
    PASSWORDNOTNEEDED,
    INVALIDNAME,
    INVALIDNAMELENGTH,
    OKAYSIGNAL,
    SERVERJOINREQUESTDENIED,
    SERVERJOINREQUESTACCEPTED,
    CONNECTIONSIGNAL,
    BLACKLISTED,
    UNKNOWN
};

auto CheckBase64 = [](const std::string &message)
{
    for (int i = 0; (unsigned)i < message.size(); i++)
    {
        if (static_cast<unsigned char>(message[i]) > 128)
        {
            return -1;
        }
    }

    return 0;
};

class SignalHandling
{
private:
    static std::string hashSignals(const std::string &data)
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

public:
    static void handleSignal(SignalType signal, const std::string &msg, SSL *tlsSock = NULL, EVP_PKEY *receivedPublicKey = NULL)
    {
        if (signal == SignalType::UNKNOWN)
        {
            return;
        }

        if (signal != SignalType::CLIENTREJOIN && signal != SignalType::OKAYSIGNAL)
        {
            const std::string decodedMessage = Decode::Base64Decode(msg);

            signal == SignalType::PASSWORDNEEDED ? std::cout << decodedMessage.substr(0, decodedMessage.length() - signalsVector[(int)signal].length()) : std::cout << decodedMessage.substr(0, decodedMessage.length() - signalsVector[(int)signal].length()) << std::endl;

            if (signal != SignalType::VERIFIED && signal != SignalType::ACCEPTED && signal != SignalType::OKAYSIGNAL && signal != SignalType::PASSWORDNOTNEEDED && signal != SignalType::PASSWORDNEEDED && signal != SignalType::REQUESTNEEDED && signal != SignalType::SERVERJOINREQUESTACCEPTED)
                raise(SIGINT);
        }

        else if (signal == SignalType::CLIENTREJOIN)
        {
            std::string userPublicKey = Receive::ReceiveMessageSSL(tlsSock);

            std::string userName = userPublicKey.substr(userPublicKey.find_first_of("/") + 1, (userPublicKey.find_last_of("-") - userPublicKey.find_first_of("/")) - 1);

            // receive and save user public key
            std::string encodedKeyData = Receive::ReceiveMessageSSL(tlsSock);
            std::string DecodedKeyData = Decode::Base64Decode(encodedKeyData);
            SaveFile::saveFile(userPublicKey, DecodedKeyData, std::ios::binary);

            receivedPublicKey = LoadKey::LoadPublicKey(userPublicKey, 0);

            if (!receivedPublicKey)
                raise(SIGINT);
        }
    }

    static SignalType getSignalType(const std::string &msg)
    {
        const std::string decodedMessage = Decode::Base64Decode(msg); // encrypted stuff

        if (CheckBase64(decodedMessage) != 0)
        {
            return SignalType::UNKNOWN;
        }

        for (unsigned int i = 0; i <= signalsVector.size(); i++)
        {
            if (decodedMessage.find(signalsVector[i]) < decodedMessage.size())
                return (SignalType)i;
        }

        return SignalType::UNKNOWN;
    }

    static std::string GetSignalAsString(SignalType signalType)
    {
        if ((unsigned int)signalType <= signalsVector.size())
            return Encode::Base64Encode(signalsVector[(int)signalType]);
        else
            std::cout << "Signal passed to SignalSetType::SetServerMessageBySignal is not a valid signal" << std::endl;

        return "";
    }

    static void signalShutdownHandler(int signal) /*this is the shutdown handler*/
    {
        shutdownHandler(signal);
    }
};

#endif