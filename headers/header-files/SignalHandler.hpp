#ifndef SIGNALHANDLER
#define SIGNALHANDLER

#include <iostream>
#include <csignal>
#include "encry.h"
#include "OpenSSL_TLS.hpp"

std::function<void(int)> shutdown_handler;

enum class SignalType
{
    LOADERR,
    EXISTERR,
    VERIFIED,
    NOTVERIFIED,
    EXISTNAME,
    REQUESTNEEDED,
    RATELIMITED,
    SERVERLIMIT,
    ACCEPTED,
    NOTACCEPTED,
    CLIENTREJOIN,
    UNKNOWN
};

class signalHandling
{
public:
    static void handleSignal(SignalType signal, const std::string &msg, SSL *tlsSock = NULL, EVP_PKEY *receivedPublicKey = NULL)
    {
        if (signal == SignalType::LOADERR)
        {
            std::cout << Dec::Base64Decode(msg.substr(0, msg.length() - 7)) << std::endl;
            raise(SIGINT);
        }
        else if (signal == SignalType::EXISTERR)
        {
            std::cout << Dec::Base64Decode(msg.substr(0, msg.length() - 8)) << std::endl;
            raise(SIGINT);
        }
        else if (signal == SignalType::VERIFIED)
        {
            std::cout << msg.substr(0, msg.length() - 2) << std::endl;
        }
        else if (signal == SignalType::NOTVERIFIED)
        {
            std::cout << msg.substr(0, msg.length() - 2) << std::endl;
            raise(SIGINT);
        }
        else if (signal == SignalType::EXISTNAME)
        {
            std::cout << msg.substr(0, msg.length() - 9) << std::endl;
            raise(SIGINT);
        }
        else if (signal == SignalType::ACCEPTED)
        {
            std::cout << Dec::Base64Decode(msg.substr(0, msg.length() - 3)) << std::endl;
        }
        else if (signal == SignalType::NOTACCEPTED)
        {
            std::cout << Dec::Base64Decode(msg.substr(0, msg.length() - 3)) << std::endl;
            raise(SIGINT);
        }
        else if (signal == SignalType::RATELIMITED)
        {
            std::cout << Dec::Base64Decode(msg.substr(0, msg.length() - 11)) << std::endl;
            raise(SIGINT);
        }
        else if (signal == SignalType::SERVERLIMIT)
        {
            std::cout << Dec::Base64Decode(msg.substr(0, msg.length() - 3)) << std::endl;
            raise(SIGINT);
        }
        else if (signal == SignalType::SERVERLIMIT)
        {
            std::cout << Dec::Base64Decode(msg.substr(0, msg.length() - 3)) << std::endl;
            raise(SIGINT);
        }
        else if (signal == SignalType::CLIENTREJOIN)
        {
            std::string userPublicKey = TlsFunc::receiveMessage(tlsSock);

            std::string userName = userPublicKey.substr(userPublicKey.find_first_of("/") + 1, (userPublicKey.find_last_of("-") - userPublicKey.find_first_of("/")) - 1);

            // receive and save user public key
            std::string encodedKeyData = Receive::receiveBase64Data(tlsSock);
            std::string decodedKeyData = Receive::Base64Decode(encodedKeyData);
            Receive::saveFilePem(userPublicKey, decodedKeyData);

            receivedPublicKey = LoadKey::LoadPubOpenssl(userPublicKey, 0);

            if (!receivedPublicKey)
                raise(SIGINT);
        }
        else if (signal == SignalType::UNKNOWN)
        {
            return;
        }
    }

    static SignalType getSignalType(const std::string &msg)
    {
        std::string array[11] = {
            "LOADERR",
            "EXSTERR",
            "#V",
            "#N",
            "EXISTNAME",
            "REQ",
            "RATELIMITED",
            "LIM",
            "ACC",
            "DEC",
            "CLIENTREJOIN",
        };

        for (int i = 0; i < 10; i++)
        {
            if (msg.find(array[i]) < msg.size())
            {
                return (SignalType)i;
            }
        }
        return SignalType::UNKNOWN;
    }
    static void signalShutdownHandler(int signal)
    {
        shutdown_handler(signal);
    }
};

#endif