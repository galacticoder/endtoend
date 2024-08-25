#ifndef SIGNALHANDLINGSERVER
#define SIGNALHANDLINGSERVER

#include <iostream>
#include <vector>
#include <algorithm>

extern short timeLimit;

std::vector<std::string> signalStringsVector = {
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
    "1",
    "2",
    "INVALIDNAME",
    "INVALIDLENGTH",
    "OKAYSIGNAL",
    "SERVERJOINREQUESTDENIED",
    "SERVERJOINREQUESTACCEPTED",
};

std::vector<std::string> ServerMessages = {
    "Public key that you sent to server cannot be loaded on server",
    "Username already exists. You have been kicked.",
    "#V",
    "#N",
    "NAMEEXISTSERR",
    "Server needs to accept your join request. Waiting for server to accept..",
    fmt::format("Rate limit reached. Try again in {} seconds", timeLimit),
    "The limit of users has been reached for this chat. Exiting..",
    "ACC",
    "DEC",
    "CLIENTREJOIN",
    "1",
    "2",
    "Username contains invalid character[s]",
    "",
    "Your request to join the server has been denied",
    "Your request to join the server has been accepted",
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
    UNKNOWN
};

class ServerSetMessage
{
public:
    static std::string GetMessageBySignal(SignalType signalType, int AppendSignal = 0 /*Get the message with the signal appended (for sending signal to client)*/)
    {
        if ((int)signalType < ServerMessages.size() && AppendSignal == 1)
            return ServerMessages[(int)signalType].append(signalStringsVector[(int)signalType]);
        else if ((int)signalType < ServerMessages.size() && AppendSignal == 0)
        {
            return signalStringsVector[(int)signalType];
        }
        else
            std::cout << "Signal passed to SignalSetType::SetServerMessageBySignal is not a valid signal" << std::endl;

        return "";
    }
};

#endif