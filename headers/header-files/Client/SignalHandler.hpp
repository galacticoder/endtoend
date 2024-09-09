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