#pragma once

#include <iostream>
#include <ctype.h>
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
private:
    inline static std::string unallowedCharacters = "\\/~ ";

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
            const std::string passwordNotVerifiedMessage = ServerSetMessage::PreLoadedSignalMessages(SignalType::NOTVERIFIED);
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

        const std::string passwordVerifiedMessage = ServerSetMessage::PreLoadedSignalMessages(SignalType::VERIFIED);

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
            const std::string InvalidUsernameLengthMessage = ServerSetMessage::PreLoadedSignalMessages(SignalType::INVALIDNAMELENGTH);

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

        // checks if username already exists
        if (std::find(ClientResources::clientUsernames.begin(), ClientResources::clientUsernames.end(), clientUsername) != ClientResources::clientUsernames.end())
        {
            std::cout << "Client with the same username detected has attempted to join. kicking.." << std::endl;
            const std::string nameAlreadyExistsMessage = ServerSetMessage::PreLoadedSignalMessages(SignalType::NAMEEXISTSERR);
            if (Send::SendMessage<__LINE__>(clientSSLSocket, nameAlreadyExistsMessage, __FILE__) != 0)
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
            if (unallowedCharacters.find(i) != std::string::npos)
            {
                (std::isspace(i)) ? std::cout << "Client username includes invalid character[s] from unallowedCharacters variable. Kicking. [Character was: <space>]" << std::endl : std::cout << fmt::format("Client username includes invalid character[s] from unallowedCharacters variable. Kicking. [Character was: {}]", i) << std::endl;

                const std::string InvalidUsernameMessage = ServerSetMessage::PreLoadedSignalMessages(SignalType::INVALIDNAME);

                if (Send::SendMessage<__LINE__>(clientSSLSocket, InvalidUsernameMessage, __FILE__) != 0)
                    return -1;

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
        auto findUser = std::find(ClientResources::blackListedClients.begin(), ClientResources::blackListedClients.end(), clientHashedIp);

        return (findUser != ClientResources::blackListedClients.end()) ? true : false;
    }
};

class CheckClientConnectValidity
{
private:
    static void CleanUpUserSocks(SSL *clientSocketSSL, int &clientSocketTCP)
    {
        SSL_shutdown(clientSocketSSL);
        SSL_free(clientSocketSSL);
        close(clientSocketTCP);
    }

    static int CheckUserLimitReached(SSL *clientSocketSSL, int &clientSocketTCP)
    {
        if (ClientResources::clientUsernames.size() == ServerSettings::limitOfUsers)
        {
            const std::string userLimitReachedMessage = ServerSetMessage::PreLoadedSignalMessages(SignalType::SERVERLIMIT);
            Send::SendMessage<__LINE__>(clientSocketSSL, userLimitReachedMessage, __FILE__);
            CleanUpUserSocks(clientSocketSSL, clientSocketTCP);
            std::cout << "Kicked user that tried to join over users limit" << std::endl;
            return -1;
        }

        return 0;
    }

    static int CheckUserRatelimited(SSL *clientSocketSSL, int &clientSocketTCP, const std::string &clientHashedIp)
    {
        // check for timeout on ip
        if (ClientResources::amountOfTriesFromIP[clientHashedIp] >= 3) // also check the time with the condition later
        {
            std::cout << fmt::format("Client [{}] is rate limited", TrimmedHashedIp(clientHashedIp)) << std::endl;
            if (ClientResources::amountOfTriesFromIP[clientHashedIp] < 4)
                std::thread(RateLimitTimer, clientHashedIp).detach(); // run the timer if not running already

            const std::string userRatelimitedMessage = ServerSetMessage::PreLoadedSignalMessages(SignalType::RATELIMITED);

            Send::SendMessage<__LINE__>(clientSocketSSL, userRatelimitedMessage, __FILE__);
            CleanUpUserSocks(clientSocketSSL, clientSocketTCP);
            std::cout << "Client kicked for attempting to join too frequently" << std::endl;
            return -1;
        }

        const std::string userOkaySignal = ServerSetMessage::PreLoadedSignalMessages(SignalType::OKAYSIGNAL);
        if (Send::SendMessage<__LINE__>(clientSocketSSL, userOkaySignal, __FILE__) != 0)
            return -1;

        return 0;
    }

    static int CheckRequestNeededForServer(SSL *clientSocketSSL, int &clientSocketTCP, const std::string &clientHashedIp)
    { // checks if users need to send a request to the server to join
        if (ServerSettings::requestNeeded != true)
        {
            const std::string userOkaySignal = ServerSetMessage::PreLoadedSignalMessages(SignalType::OKAYSIGNAL);
            if (Send::SendMessage<__LINE__>(clientSocketSSL, userOkaySignal, __FILE__) != 0)
                return -1;
            return 0;
        }

        // send user needs to request message
        const std::string serverRequestMessage = ServerSetMessage::PreLoadedSignalMessages(SignalType::REQUESTNEEDED);
        if (Send::SendMessage<__LINE__>(clientSocketSSL, serverRequestMessage, __FILE__) != 0)
            return -1;

        ClientResources::serverJoinRequests.push(clientHashedIp);
        std::cout << fmt::format("User from hashed ip [{}] is requesting to join the server. Accept or not?(y/n): ", TrimmedHashedIp(clientHashedIp));

        char answer;
        std::cin >> answer;
        answer = toupper(answer);

        const std::string userAcceptedMessage = ServerSetMessage::PreLoadedSignalMessages((answer == 'Y') ? SignalType::SERVERJOINREQUESTACCEPTED : SignalType::SERVERJOINREQUESTDENIED);
        if (Send::SendMessage<__LINE__>(clientSocketSSL, userAcceptedMessage, __FILE__) != 0)
            return -1;
        ClientResources::serverJoinRequests.pop();

        (answer == 'Y') ? std::cout << "User has been allowed in server" << std::endl : std::cout << "User has been not been allowed in server" << std::endl;

        (answer != 'Y') ? CleanUpUserSocks(clientSocketSSL, clientSocketTCP) : (void)0;
        return (answer == 'Y') ? 0 : -1;
    }

public:
    static int
    CheckUserValidity(SSL *clientSocketSSL, int &clientSocketTCP, const std::string &clientHashedIp)
    {
        if (CheckUserRatelimited(clientSocketSSL, clientSocketTCP, clientHashedIp) != 0)
            return -1;
        if (CheckUserLimitReached(clientSocketSSL, clientSocketTCP) != 0)
            return -1;
        if (CheckRequestNeededForServer(clientSocketSSL, clientSocketTCP, clientHashedIp) != 0)
            return -1;

        return 0;
    }
};