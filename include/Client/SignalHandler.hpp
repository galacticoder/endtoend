#pragma once

#include <iostream>
#include <csignal>
#include <fstream>
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
    "/quit",
};

enum class SignalType
{
    KEYLOADERROR,              // 0
    EXISTERR,                  // 1
    VERIFIED,                  // 2
    NOTVERIFIED,               // 3
    NAMEEXISTSERR,             // 4
    REQUESTNEEDED,             // 5
    RATELIMITED,               // 6
    SERVERLIMIT,               // 7
    ACCEPTED,                  // 8
    NOTACCEPTED,               // 9
    CLIENTREJOIN,              // 10
    PASSWORDNEEDED,            // 11
    PASSWORDNOTNEEDED,         // 12
    INVALIDNAME,               // 13
    INVALIDNAMELENGTH,         // 14
    OKAYSIGNAL,                // 15
    SERVERJOINREQUESTDENIED,   // 16
    SERVERJOINREQUESTACCEPTED, // 17
    CONNECTIONSIGNAL,          // 18
    BLACKLISTED,               // 19
    QUIT,                      // 20
    UNKNOWN                    // 21
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
    static void handleSignal(SignalType signal, const std::string &msg, SSL *clientSocketSSL = NULL, EVP_PKEY *receivedPublicKey = NULL)
    {
        if (signal == SignalType::UNKNOWN)
            return;

        if (signal != SignalType::CLIENTREJOIN && signal != SignalType::OKAYSIGNAL)
        {
            const std::string decodedMessage = Decode::Base64Decode(msg);

            signal == SignalType::PASSWORDNEEDED ? std::cout << decodedMessage.substr(0, decodedMessage.length() - signalsVector[(int)signal].length()) : std::cout << decodedMessage.substr(0, decodedMessage.length() - signalsVector[(int)signal].length()) << std::endl;

            if (signal != SignalType::VERIFIED && signal != SignalType::ACCEPTED && signal != SignalType::OKAYSIGNAL && signal != SignalType::PASSWORDNOTNEEDED && signal != SignalType::PASSWORDNEEDED && signal != SignalType::REQUESTNEEDED && signal != SignalType::SERVERJOINREQUESTACCEPTED)
                raise(SIGINT);
        }

        else if (signal == SignalType::CLIENTREJOIN)
        {
            std::ofstream file("testing-folder/clientrejoin.txt", std::ios::app);
            std::string userPublicKey = Receive::ReceiveMessageSSL(clientSocketSSL);

            file << "User received public key: " << userPublicKey << std::endl;

            std::string username = userPublicKey.substr(userPublicKey.find_first_of("/") + 1, (userPublicKey.find_last_of("-") - userPublicKey.find_first_of("/")) - 1);

            file << fmt::format("Received {}'s public key", username) << std::endl;

            // receive and save user public key
            std::string encodedKeyData = Receive::ReceiveMessageSSL(clientSocketSSL);
            std::string decodedKeyData = Decode::Base64Decode(encodedKeyData);
            file << fmt::format("Decoded {}'s public key: {}", username, decodedKeyData) << std::endl;
            SaveFile::saveFile(userPublicKey, decodedKeyData, std::ios::binary);

            receivedPublicKey = LoadKey::LoadPublicKey(userPublicKey, 0);

            if (!receivedPublicKey)
                raise(SIGINT);
        }
    }

    static SignalType getSignalType(const std::string &msg)
    {
        std::string decodedMessage = Decode::Base64Decode(msg);

        std::ofstream file("testing-folder/signals.txt", std::ios::app);
        file << "Received signal: " << msg;
        file << "\n";
        file << "Decoded signal: " << decodedMessage;
        file << "\n---------------------------\n";
        file.close();

        // set it to test if the size is greater than the greatest size in signals vector later
        for (unsigned int i = 0; i < signalsVector.size(); i++)
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

enum class ErrorTypes
{
    ERROR,
    EXCEPTION
};
class ErrorHandling
{
public:
    template <auto line>
    constexpr static void LOGERROR(ErrorTypes errorType, const std::string message, const char *file, auto func)
    {
        (errorType == ErrorTypes::ERROR) ? std::cout << fmt::format("[{}:{}] Error caught [{}]: {}", file, line, func, message) << std::endl : std::cout << fmt::format("[{}:{}] Exception caught [in function {}]: {}", file, line, func, message) << std::endl;
    }
};