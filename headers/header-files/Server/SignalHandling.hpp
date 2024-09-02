#pragma once

#include <iostream>
#include <vector>
#include <algorithm>
#include "Encryption.hpp"
#include "SendAndReceive.hpp"
#include "CleanUp.hpp"

extern short timeLimit;
extern bool cleanUpInPing;

std::vector<std::string> signalStringsVector = {
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
    "CONNECTIONSIGNAL",
    "STATUSCHECKSIGNAL",
};

std::vector<std::string> ServerMessages = {
    "Public key that you sent to server cannot be loaded on server",
    "Username already exists. You have been kicked.",
    "You have entered the correct password",
    "Wrong password. You have been kicked.",
    "Username already exists on server",
    "Server needs to accept your join request. Waiting for server to accept..",
    "Rate limit reached. Try again in x seconds",
    "The limit of users has been reached for this chat. Exiting..",
    "You request to join the server has been accepted",
    "You request to join the server has not been accepted",
    "CLIENTREJOIN",
    "This server is password protected enter the password to join: ",
    "You have entered the server", /*if server isnt password protected then they just join*/
    "Username contains invalid character[s]",
    "", /*Okay signal has no message*/
    "Your request to join the server has been denied",
    "Your request to join the server has been accepted",
    "" /*connection signal is never sent appended to a message*/,
    "" /*status check signal is never sent appended to a message*/,
};

enum class SignalType
{
    LOADERR,
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
    STATUSCHECKSIGNAL,
    UNKNOWN
};

class ServerSetMessage
{
public:
    static std::string GetMessageBySignal(SignalType signalType, int AppendSignal = 0 /*Get the message with the signal appended (for sending signal to client)*/)
    {
        if ((unsigned int)signalType <= ServerMessages.size() && AppendSignal == 0)
            return Encode::Base64Encode(signalStringsVector[(int)signalType]);

        else if ((unsigned int)signalType <= ServerMessages.size() && AppendSignal == 1)
            return Encode::Base64Encode(ServerMessages[(int)signalType].append(signalStringsVector[(int)signalType]));

        else
            std::cout << "Signal passed to SignalSetType::SetServerMessageBySignal is not a valid signal" << std::endl;

        return "";
    }
};

class Error
{
public:
    static void CaughtERROR(const std::string &clientUsername, unsigned int &clientIndex, SSL *clientSocket, SignalType ERRORTYPE, const std::string &message)
    {
        std::cout << message << std::endl;
        const std::string ErrorMessage = ServerSetMessage::GetMessageBySignal(ERRORTYPE, 1);

        Send::SendMessage(clientSocket, ErrorMessage);
        {
            cleanUpInPing = false;
            CleanUp::CleanUpClient(clientIndex);
        }
        std::cout << fmt::format("Kicked user [{}]", clientUsername) << std::endl;
        return;
    }
};