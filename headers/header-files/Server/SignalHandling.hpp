#pragma once

#include <iostream>
#include <vector>
#include <algorithm>
#include "Encryption.hpp"
#include "CleanUp.hpp"
#include "SendAndReceive.hpp"

std::vector<std::string> signalStringsVector = {
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
    "STATUSCHECKSIGNAL",
    "PINGBACK",
    "PING",
    "BLACKLISTED",
};

std::vector<std::string> ServerMessages = {
    "Public key that you sent to server cannot be loaded on server",
    "Username already exists. You have been kicked.",
    "You have entered the correct password",
    "Wrong password. You have been kicked.",
    "Username already exists on server",
    "Server needs to accept your join request. Waiting for server to accept..",
    "", // rate limiting gets replaced
    "The limit of users has been reached for this chat. Exiting..",
    "You request to join the server has been accepted",
    "You request to join the server has not been accepted",
    "N/A" /*client rejoin signal has no message*/,
    "This server is password protected enter the password to join: ",
    "You have entered the server", /*if server isnt password protected then they just join*/
    "Username contains invalid character[s]",
    fmt::format("Your username is over the allowed user length by the server [{}-{}]", ServerSettings::minimumNameLength, ServerSettings::maximumNameLength),
    "N/A", /*Okay signal has no message*/
    "Your request to join the server has been denied",
    "Your request to join the server has been accepted",
    "N/A" /*connection signal is never sent appended to a message*/,
    "N/A" /*status check signal is never sent appended to a message*/,
    "N/A" /*ping back signal is never sent appended to a message*/,
    "N/A" /*ping signal is never sent appended to a message*/,
    "You have been blacklisted and cannot join the server again" /*ping signal is never sent appended to a message*/,
};

enum class SignalType
{
    LOADERR,
    KEYEXISTERR,
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
    STATUSCHECKSIGNAL,
    PINGBACK,
    PING,
    BLACKLISTED,
    UNKNOWN
};

enum class ErrorTypes
{
    ERROR,
    EXCEPTION
};
class ServerSetMessage
{
public:
    static std::string GetMessageBySignal(SignalType signalType, int appendSignal = 0, const std::string &hashedIp = "N/A")
    {
        if (signalType == SignalType::RATELIMITED)
            ServerMessages[(int)SignalType::RATELIMITED] = fmt::format("Rate limit reached. Try again in {} seconds", ClientResources::clientTimeLimits[hashedIp]); // add the rate limited message to vector every time function called since cant format string in vector

        if ((unsigned int)signalType <= ServerMessages.size() && appendSignal == 0)
            return Encode::Base64Encode(signalStringsVector[(int)signalType]);

        else if ((unsigned int)signalType <= ServerMessages.size() && appendSignal == 1)
            return Encode::Base64Encode(ServerMessages[(int)signalType].append(signalStringsVector[(int)signalType]));

        else
            std::cout << fmt::format("Signal passed to {} is not a valid signal", __func__) << std::endl;

        return "";
    }
};

class Error
{
public:
    constexpr static void LOGERROR(ErrorTypes errorType, const std::string message, const char *file, unsigned int line, auto func)
    {
        (errorType == ErrorTypes::ERROR) ? std::cout << fmt::format("[{}:{}] Error caught [{}]: {}", file, line, func, message) << std::endl : std::cout << fmt::format("[{}:{}] Exception caught [in function {}]: {}", file, line, func, message) << std::endl;
    }

    static void CaughtERROR(SignalType errorType, unsigned int &clientIndex, const std::string &message)
    {
        std::cout << message << std::endl;
        const std::string errorMessage = ServerSetMessage::GetMessageBySignal(errorType, 1);

        Send::SendMessage<__LINE__>(ClientResources::clientSocketsSSL[clientIndex], errorMessage, __FILE__);

        ClientResources::cleanUpInPing = false;
        CleanUp::CleanUpClient(clientIndex);

        std::cout << fmt::format("Kicked user [{}]", ClientResources::clientUsernames[clientIndex]) << std::endl;
        return;
    }
};