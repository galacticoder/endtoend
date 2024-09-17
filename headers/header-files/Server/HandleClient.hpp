#pragma once

#include <iostream>
#include <queue>
#include <fmt/core.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <thread>
#include "SendAndReceive.hpp"
#include "ServerSettings.hpp"
#include "FileHandler.hpp"
#include "Keys.hpp"
#include "Decryption.hpp"
#include "CleanUp.hpp"
#include "SignalHandling.hpp"
#include "bcrypt.h"

#define TrimmedHashedIp(hashedIp) (hashedIp.substr(0, hashedIp.length() / 4)).append("..")
#define FindInVec(vectorName, value) (std::find(vectorName.begin(), vectorName.end(), value)) - vectorName.begin()

extern void RateLimitTimer(const std::string hashedClientIp);

class HandleClient
{
public:
    static int ClientPasswordVerification(SSL *clientSSLSocket, unsigned int &clientIndex, const std::string &ServerPrivateKeyPath, const std::string &clientHashedIp, const std::string &serverHashedPassword)
    {
        if (serverHashedPassword.empty())
            return 0;

        std::cout << "Waiting to receive password from client.." << std::endl;

        std::string receivedPasswordCipher = Receive::ReceiveMessageSSL<__LINE__>(clientSSLSocket, __FILE__);

        if (receivedPasswordCipher.empty() || ServerSettings::exitSignal == true || !clientSSLSocket)
        {
            std::cout << "Unexpected error from user side encountered" << std::endl;
            return -1;
        }

        std::cout << "Password cipher recieved from client: " << receivedPasswordCipher << std::endl;

        EVP_PKEY *serverPrivateKey = LoadKey::LoadPrivateKey(ServerPrivateKeyPath);

        if (!serverPrivateKey)
        {
            std::cout << "Could not load server private key for decryption. Killing server." << std::endl;
            raise(SIGINT);
        }

        std::cout << "Decoding pass cipher" << std::endl;
        std::string decodedPassGet = Decode::Base64Decode(receivedPasswordCipher);

        std::cout << "Decrypting password cipher" << std::endl;
        receivedPasswordCipher = Decrypt::DecryptData(serverPrivateKey, decodedPassGet);
        EVP_PKEY_free(serverPrivateKey);

        std::cout << "Validating password hash sent by user" << std::endl;

        if (bcrypt::validatePassword(receivedPasswordCipher, serverHashedPassword) != 1)
        {
            std::cout << "Password not validated" << std::endl;
            const std::string passwordNotVerifiedMessage = ServerSetMessage::GetMessageBySignal(SignalType::NOTVERIFIED, 1);
            // sends them the not VerifiedMessage message // assuming its always sending the message successfully change this later
            if (Send::SendMessage<__LINE__>(clientSSLSocket, passwordNotVerifiedMessage, __FILE__) != 0)
            {
                std::cout << "User has disconnected" << std::endl;
                return -1;
            }

            ClientResources::cleanUpInPing = false; // dont clean up in pingClient function
            CleanUp::CleanUpClient(clientIndex);
            std::cout << fmt::format("User with hashed ip [{}] has entered the wrong password and has been kicked", TrimmedHashedIp(clientHashedIp)) << std::endl;

            return -1;
        }

        const std::string passwordVerifiedMessage = ServerSetMessage::GetMessageBySignal(SignalType::VERIFIED, 1);

        if (Send::SendMessage<__LINE__>(clientSSLSocket, passwordVerifiedMessage, __FILE__) != 0)
        {
            std::cout << "User has disconnected" << std::endl;
            return -1;
        }

        if ((unsigned)(FindInVec(ClientResources::passwordVerifiedClients, ClientResources::passwordVerifiedClients[clientIndex])) != ClientResources::passwordVerifiedClients.size())
        {
            ClientResources::passwordVerifiedClients[clientIndex] = 1; // set client as verified
            std::cout << "User password verified and added to clientHashVerifiedClients vector" << std::endl;
            std::cout << "Updated vector size: " << ClientResources::passwordVerifiedClients.size() << std::endl;
            return 0;
        }

        std::cout << "User does not exist on server" << std::endl;
        return -1;
    }

    static int ClientUsernameValidity(SSL *clientSSLSocket, unsigned int &clientIndex, const std::string &clientUsername)
    {
        // check if client username is invalid in length
        if (clientUsername.size() <= 3 || clientUsername.size() > 12)
        {
            std::cout << "Client with invalid username length has attempted to join. kicking.." << std::endl;
            const std::string InvalidUsernameLengthMessage = ServerSetMessage::GetMessageBySignal(SignalType::INVALIDNAMELENGTH, 1);

            if (Send::SendMessage<__LINE__>(clientSSLSocket, InvalidUsernameLengthMessage, __FILE__) != 0)
                return -1;

            if (ServerSettings::exitSignal != true)
            {
                ClientResources::cleanUpInPing = false; // dont clean up in pingClient function
                CleanUp::CleanUpClient(clientIndex);
            }

            std::cout << "Disconnected client with invalid username length" << std::endl;
            return -1;
        }

        std::vector<std::string> unallowedCharacters = {"\\", "/", "~", " "};
        // checks if username already exists
        if (std::find(ClientResources::clientUsernames.begin(), ClientResources::clientUsernames.end(), clientUsername) != ClientResources::clientUsernames.end())
        {
            std::cout << "Client with the same username detected has attempted to join. kicking.." << std::endl;
            const std::string NameAlreadyExistsMessage = ServerSetMessage::GetMessageBySignal(SignalType::NAMEEXISTSERR, 1);
            if (Send::SendMessage<__LINE__>(clientSSLSocket, NameAlreadyExistsMessage, __FILE__) != 0)
                return -1;

            if (ServerSettings::exitSignal != true)
            {
                ClientResources::cleanUpInPing = false; // dont clean up in pingClient function
                CleanUp::CleanUpClient(clientIndex);
            }

            std::cout << "Kicked client with same username" << std::endl;
            return -1;
        }

        // check if client username contains unallowed characters
        for (char i : clientUsername)
        {
            std::string iToStr(1, i);
            unsigned int findChar = (std::find(unallowedCharacters.begin(), unallowedCharacters.end(), iToStr)) - unallowedCharacters.begin();

            if (findChar == std::string::npos)
            {
                std::cout << fmt::format("Client username includes invalid character[s] from unallowedCharacters variable. Kicking. [CHAR: {}]", i) << std::endl;
                const std::string InvalidUsernameMessage = ServerSetMessage::GetMessageBySignal(SignalType::INVALIDNAME, 1);
                Send::SendMessage<__LINE__>(clientSSLSocket, InvalidUsernameMessage, __FILE__);

                if (ServerSettings::exitSignal != true)
                {
                    ClientResources::cleanUpInPing = false; // dont clean up in pingClient function
                    CleanUp::CleanUpClient(clientIndex);
                }

                std::cout << "Disconnected user with invalid character[s] in username name" << std::endl;

                return -1;
            }
        }

        return 0;
    }

    static int IncrementUserTries(const std::string &clientHashedIp)
    {
        auto clientIpExistenceCheck = ClientResources::amountOfTriesFromIP.find(clientHashedIp);

        clientIpExistenceCheck == ClientResources::amountOfTriesFromIP.end() ? ClientResources::amountOfTriesFromIP[clientHashedIp] = 1 : ClientResources::amountOfTriesFromIP[clientHashedIp]++;

        if (ClientResources::amountOfTriesFromIP[clientHashedIp] > 8)
        {
            ClientResources::blackListedClients.push_back(clientHashedIp);
            std::cout << fmt::format("Hashed ip [{}] has attempting connecting {} times. Client has been black listed", TrimmedHashedIp(clientHashedIp), ClientResources::amountOfTriesFromIP[clientHashedIp]) << std::endl;
            return -1;
        }

        return 0;
    }

    static bool isBlackListed(const std::string &clientHashedIp)
    {
        // if (ClientResources::blackListedClients.find(ClientResources::blackListedClients.begin(), ClientResources::blackListedClients.end(), clientHashedIp) != ClientResources::blackListedClients.end())
        // return true;

        return false;
    }
};

class CheckClientConnectValidity
{
private:
    static int CheckUserLimitReached(SSL *clientSocketSSL)
    {
        if (ClientResources::clientUsernames.size() == ServerSettings::limitOfUsers)
        {
            const std::string userLimitReachedMessage = ServerSetMessage::GetMessageBySignal(SignalType::SERVERLIMIT, 1);
            Send::SendMessage<__LINE__>(clientSocketSSL, userLimitReachedMessage, __FILE__);
            CleanUp::CleanUpClient(-1, -1, clientSocketSSL);
            std::cout << "Kicked user that tried to join over users limit" << std::endl;
            return -1;
        }

        return 0;
    }

    static int CheckUserRatelimited(SSL *clientSocketSSL, const std::string &clientHashedIp)
    {
        // check for timeout on ip
        if (ClientResources::amountOfTriesFromIP[clientHashedIp] >= 3) // also check the time with the condition later
        {
            std::cout << fmt::format("Client [{}] is rate limited", TrimmedHashedIp(clientHashedIp)) << std::endl;
            if (ClientResources::amountOfTriesFromIP[clientHashedIp] < 4)
                std::thread(RateLimitTimer, clientHashedIp).detach(); // run the timer if not running already

            const std::string userRatelimitedMessage = ServerSetMessage::GetMessageBySignal(SignalType::RATELIMITED, 1);
            Send::SendMessage<__LINE__>(clientSocketSSL, userRatelimitedMessage, __FILE__);
            CleanUp::CleanUpClient(-1, -1, clientSocketSSL);
            std::cout << "Client kicked for attempting to join too frequently" << std::endl;
            return -1;
        }

        const std::string userOkaySignal = ServerSetMessage::GetMessageBySignal(SignalType::OKAYSIGNAL);
        Send::SendMessage<__LINE__>(clientSocketSSL, userOkaySignal, __FILE__); // if they are not rate limited send them an okay signal
        return 0;
    }

    static int CheckRequestNeededForServer(SSL *userSSLsocket, const std::string &clientHashedIp)
    { // checks if users need to send a request to the server to join
        if (ServerSettings::requestNeeded != true)
        {
            const std::string userOkaySignal = ServerSetMessage::GetMessageBySignal(SignalType::OKAYSIGNAL);
            Send::SendMessage<__LINE__>(userSSLsocket, userOkaySignal, __FILE__); // send an okay signal if they dont need to request to join the server
            return 0;
        }

        // send user needs to request message
        const std::string serverRequestMessage = ServerSetMessage::GetMessageBySignal(SignalType::REQUESTNEEDED, 1);
        Send::SendMessage<__LINE__>(userSSLsocket, serverRequestMessage, __FILE__);

        ClientResources::serverJoinRequests.push(clientHashedIp);
        std::cout << fmt::format("User from hashed ip [{}] is requesting to join the server. Accept or not?(y/n): ", TrimmedHashedIp(clientHashedIp));

        const char answer = toupper(getchar());

        if (answer == 'Y')
        {
            const std::string userAcceptedMessage = ServerSetMessage::GetMessageBySignal(SignalType::SERVERJOINREQUESTACCEPTED, 1);
            Send::SendMessage<__LINE__>(userSSLsocket, userAcceptedMessage, __FILE__);
            ClientResources::serverJoinRequests.pop();
            std::cout << "\nUser has been allowed in server" << std::endl;
            return 0;
        }

        const std::string userNotAcceptedMessage = ServerSetMessage::GetMessageBySignal(SignalType::SERVERJOINREQUESTDENIED, 1);
        Send::SendMessage<__LINE__>(userSSLsocket, userNotAcceptedMessage, __FILE__);
        ClientResources::serverJoinRequests.pop();
        std::cout << "\nUser has been not been allowed in server" << std::endl;
        CleanUp::CleanUpClient(-1, -1, userSSLsocket);
        return -1;
    }

public:
    static int CheckUserValidity(SSL *clientSocketSSL, const std::string &clientHashedIp)
    {
        if (CheckUserRatelimited(clientSocketSSL, clientHashedIp) != 0)
            return -1;
        if (CheckUserLimitReached(clientSocketSSL) != 0)
            return -1;
        if (CheckRequestNeededForServer(clientSocketSSL, clientHashedIp) != 0)
            return -1;

        return 0;
    }
};