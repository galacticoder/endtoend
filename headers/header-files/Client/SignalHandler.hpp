#ifndef SIGNALHANDLER
#define SIGNALHANDLER

#include <iostream>
#include <csignal>
#include "Keys.hpp"
#include "SendAndReceive.hpp"
#include "FileHandling.hpp"
#include "Decryption.hpp"

std::function<void(int)> shutdownHandler;

std::vector<std::string> signalsVector = {
    "KEYLOADERROR",
    "NAMEEXISTS",
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
    UNKNOWN
};

class signalHandling
{
public:
    static void handleSignal(SignalType signal, const std::string &msg, SSL *tlsSock = NULL, EVP_PKEY *receivedPublicKey = NULL)
    {
        if (signal != SignalType::CLIENTREJOIN && signal != SignalType::OKAYSIGNAL && signal != SignalType::UNKNOWN)
        {
            const std::string decodedMessage = Decode::Base64Decode(msg);
            std::cout << decodedMessage.substr(0, decodedMessage.length() - signalsVector[(int)signal].length()) << std::endl;

            if (signal != SignalType::VERIFIED && signal != SignalType::ACCEPTED && signal != SignalType::OKAYSIGNAL)
                raise(SIGINT);
        }

        else if (signal == SignalType::CLIENTREJOIN)
        {
            std::string userPublicKey = Receive::ReceiveMessageSSL(tlsSock);

            std::string userName = userPublicKey.substr(userPublicKey.find_first_of("/") + 1, (userPublicKey.find_last_of("-") - userPublicKey.find_first_of("/")) - 1);

            // receive and save user public key
            std::string encodedKeyData = Receive::ReceiveMessageSSL(tlsSock);
            std::string DecodeodedKeyData = Decode::Base64Decode(encodedKeyData);
            SaveFile::saveFile(userPublicKey, DecodeodedKeyData, std::ios::binary);

            receivedPublicKey = LoadKey::LoadPublicKey(userPublicKey, 0);

            if (!receivedPublicKey)
                raise(SIGINT);
        }
    }

    static SignalType getSignalType(const std::string &msg)
    {
        const std::string decodedMessage = Decode::Base64Decode(msg);
        for (unsigned int i = 0; i < signalsVector.size(); i++)
        {
            if (decodedMessage.find(signalsVector[i]) < decodedMessage.size())
                return (SignalType)i;
        }

        return SignalType::UNKNOWN;
    }

    static void signalShutdownHandler(int signal) /*this is the shutdown handler*/
    {
        shutdownHandler(signal);
    }
};

#endif