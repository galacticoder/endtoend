#ifndef SIGNALHANDLER
#define SIGNALHANDLER

#include <iostream>
#include <csignal>
#include "Keys.hpp"
#include "SendAndReceive.hpp"
#include "FileHandling.hpp"
#include "Decryption.hpp"

std::function<void(int)> shutdownHandler;

enum class SignalType
{
    LOADERR,       // 0
    EXISTERR,      // 1
    VERIFIED,      // 2
    NOTVERIFIED,   // 3
    EXISTNAME,     // 4
    REQUESTNEEDED, // 5
    RATELIMITED,   // 6
    SERVERLIMIT,   // 7
    ACCEPTED,      // 8
    NOTACCEPTED,   // 9
    CLIENTREJOIN,  // 10
    UNKNOWN        // 11
};

class signalHandling
{
public:
    static void handleSignal(SignalType signal, const std::string &msg, SSL *tlsSock = NULL, EVP_PKEY *receivedPublicKey = NULL)
    {
        if (signal == SignalType::LOADERR)
        {
            std::cout << Decode::Base64Decode(msg.substr(0, msg.length() - 7)) << std::endl;
            raise(SIGINT);
        }
        else if (signal == SignalType::EXISTERR)
        {
            std::cout << Decode::Base64Decode(msg.substr(0, msg.length() - 8)) << std::endl;
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
            std::cout << msg.substr(0, msg.length() - 13) << std::endl;
            raise(SIGINT);
        }
        else if (signal == SignalType::ACCEPTED)
        {
            std::cout << Decode::Base64Decode(msg.substr(0, msg.length() - 3)) << std::endl;
        }
        else if (signal == SignalType::NOTACCEPTED)
        {
            std::cout << Decode::Base64Decode(msg.substr(0, msg.length() - 3)) << std::endl;
            raise(SIGINT);
        }
        else if (signal == SignalType::RATELIMITED)
        {
            std::cout << Decode::Base64Decode(msg.substr(0, msg.length() - 11)) << std::endl;
            raise(SIGINT);
        }
        else if (signal == SignalType::SERVERLIMIT)
        {
            std::cout << Decode::Base64Decode(msg.substr(0, msg.length() - 3)) << std::endl;
            raise(SIGINT);
        }
        else if (signal == SignalType::SERVERLIMIT)
        {
            std::cout << Decode::Base64Decode(msg.substr(0, msg.length() - 3)) << std::endl;
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
        else if (signal == SignalType::UNKNOWN)
            return;
    }

    static SignalType getSignalType(const std::string &msg)
    {
        std::string signalsArray[11] = {
            "LOADERR",
            "EXSTERR",
            "#V",
            "#N",
            "NAMEEXISTSERR",
            "REQ",
            "RATELIMITED",
            "LIM",
            "ACC",
            "DEC",
            "CLIENTREJOIN",
        };
        for (int i = 0; i < 10; i++)
        {
            if (msg.find(signalsArray[i]) < msg.size())
            {
                return (SignalType)i;
            }
        }
        return SignalType::UNKNOWN;
    }
    static void signalShutdownHandler(int signal)
    {
        shutdownHandler(signal);
    }
};

#endif