#pragma once

#include <iostream>
#include <queue>
#include <fmt/core.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <thread>
#include "SendAndReceive.hpp"
#include "FileHandler.hpp"
#include "Keys.hpp"
#include "Decryption.hpp"
#include "CleanUp.hpp"
#include "SignalHandling.hpp"
#include "bcrypt.h"

extern std::vector<SSL *> SSLsocks;
extern std::vector<int> connectedClients;
extern std::vector<int> PasswordVerifiedClients;
extern std::vector<std::string> clientUsernames;
extern std::queue<std::string> serverJoinRequests;
extern std::map<std::string, short> amountOfTriesFromIP;
extern void waitTimer(const std::string hashedClientIp);
extern bool cleanUpInPing;

class HandleClient
{
public:
    static int ClientPasswordVerification(SSL *ClientSSLSocket, unsigned int &clientIndex, const std::string &ServerPrivateKeyPath, const std::string &ClientHashedIp, const std::string &serverHashedPassword)
    {
        if (serverHashedPassword.empty())
            return 0;

        std::cout << "Waiting to receive password from client.." << std::endl;

        std::string ReceivedPasswordCipher = Receive::ReceiveMessageSSL(ClientSSLSocket);
        std::cout << "Password cipher recieved from client: " << ReceivedPasswordCipher << std::endl;

        EVP_PKEY *serverPrivateKey = LoadKey::LoadPrivateKey(ServerPrivateKeyPath);

        if (!serverPrivateKey)
        {
            std::cout << "Could not load server private key for decryption. Killing server." << std::endl;
            raise(SIGINT);
        }

        std::cout << "Decoding pass cipher" << std::endl;
        std::string decodedPassGet = Decode::Base64Decode(ReceivedPasswordCipher);

        std::cout << "Decrypting password cipher" << std::endl;
        ReceivedPasswordCipher = Decrypt::DecryptData(serverPrivateKey, decodedPassGet);
        EVP_PKEY_free(serverPrivateKey);

        std::cout << "Validating password hash sent by user" << std::endl;

        if (bcrypt::validatePassword(ReceivedPasswordCipher, serverHashedPassword) != 1)
        {
            std::cout << "Password not validated" << std::endl;
            const std::string PasswordNotVerifiedMessage = ServerSetMessage::GetMessageBySignal(SignalType::NOTVERIFIED, 1);
            Send::SendMessage(ClientSSLSocket, PasswordNotVerifiedMessage); // sends them the not VerifiedMessage message
            {
                cleanUpInPing = false; // dont clean up in pingClient function
                CleanUp::CleanUpClient(clientIndex);
            }
            std::cout << fmt::format("User with hashed ip [{}..] has entered the wrong password and has been kicked", ClientHashedIp) << std::endl;
            return -1;
        }

        const std::string PasswordVerifiedMessage = ServerSetMessage::GetMessageBySignal(SignalType::VERIFIED, 1);
        Send::SendMessage(ClientSSLSocket, PasswordVerifiedMessage);
        PasswordVerifiedClients[clientIndex] = 1; // set client as verified
        std::cout << "User password VerifiedMessage and added to clientHashVerifiedClients vector" << std::endl;
        std::cout << "Updated vector size: " << PasswordVerifiedClients.size() << std::endl;
        return 0;
    }

    static int ClientUsernameValidity(SSL *ClientSSLSocket, unsigned int &clientIndex, const std::string &clientUsername)
    {
        const std::string UnallowedCharacters = "\\/~ ";
        // checks if username already exists
        if (std::find(clientUsernames.begin(), clientUsernames.end(), clientUsername) != clientUsernames.end())
        {
            std::cout << "Client with the same username detected has attempted to join. kicking.." << std::endl;
            const std::string NameAlreadyExistsMessage = ServerSetMessage::GetMessageBySignal(SignalType::NAMEEXISTSERR, 1);
            Send::SendMessage(ClientSSLSocket, NameAlreadyExistsMessage);
            {
                cleanUpInPing = false; // dont clean up in pingClient function
                CleanUp::CleanUpClient(clientIndex);
            }
            std::cout << "Kicked client with same username" << std::endl;
            return -1;
        }

        // check if client username is invalid in length
        if (clientUsername.size() <= 3 || clientUsername.size() > 12)
        {
            std::cout << "Client with invalid username length has attempted to join. kicking.." << std::endl;
            const std::string InvalidUsernameLengthMessage = ServerSetMessage::GetMessageBySignal(SignalType::INVALIDNAMELENGTH, 1);
            Send::SendMessage(ClientSSLSocket, InvalidUsernameLengthMessage);
            {
                cleanUpInPing = false; // dont clean up in pingClient function
                CleanUp::CleanUpClient(clientIndex);
            }
            std::cout << "Disconnected user with empty name" << std::endl;
            return -1;
        }

        // check if client username contains unallowed characters
        for (unsigned int i = 0; i < clientUsername.size(); i++)
        {
            if (UnallowedCharacters.find(clientUsername[i]) < clientUsername.size())
            {
                std::cout << fmt::format("Client username includes invalid character[s] from UnallowedCharacters variable. Kicking. [CHAR: {}]", clientUsername[i]) << std::endl;
                const std::string InvalidUsernameMessage = ServerSetMessage::GetMessageBySignal(SignalType::INVALIDNAME, 1);
                Send::SendMessage(ClientSSLSocket, InvalidUsernameMessage);
                {
                    cleanUpInPing = false; // dont clean up in pingClient function
                    CleanUp::CleanUpClient(clientIndex);
                }
                std::cout << "Disconnected user with invalid character[s] in username name" << std::endl;
                return -1;
            }
        }

        if (Encode::CheckBase64(clientUsername) == -1)
        {
            std::cout << "Client username includes invalid character[s] in base 64 decoding attempt. Kicking." << std::endl;
            const std::string InvalidUsernameMessage = ServerSetMessage::GetMessageBySignal(SignalType::INVALIDNAME, 1);
            Send::SendMessage(ClientSSLSocket, InvalidUsernameMessage);
            {
                cleanUpInPing = false; // dont clean up in pingClient function
                CleanUp::CleanUpClient(clientIndex);
            }
            std::cout << "Disconnected user with invalid character[s] in username name" << std::endl;
            return -1;
        }

        return 0;
    }

    static int CheckUserLimitReached(SSL *userSSLSocket, int &userTcpSocket, unsigned int &limitOfUsers)
    {
        if (clientUsernames.size() == limitOfUsers)
        {
            const std::string userLimitReachedMessage = ServerSetMessage::GetMessageBySignal(SignalType::SERVERLIMIT, 1);
            Send::SendMessage(userSSLSocket, userLimitReachedMessage);
            CleanUp::CleanUpClient(-1, userSSLSocket, userTcpSocket);
            std::cout << "Kicked user that tried to join over users limit" << std::endl;
            return -1;
        }
        return 0;
    }

    static int CheckUserRatelimited(SSL *userSSLSocket, int &userTcpSocket, const std::string &ClientHashedIp)
    {
        // check for timeout on ip
        if (amountOfTriesFromIP[ClientHashedIp] >= 3) // also check the time with the condition later
        {
            if (amountOfTriesFromIP[ClientHashedIp] < 4)
                std::thread(waitTimer, ClientHashedIp).detach(); // run the timer if not running already

            const std::string userRatelimitedMessage = ServerSetMessage::GetMessageBySignal(SignalType::RATELIMITED, 1);
            Send::SendMessage(userSSLSocket, userRatelimitedMessage);
            CleanUp::CleanUpClient(-1, userSSLSocket, userTcpSocket);
            std::cout << "Client kicked for attempting to join too frequently" << std::endl;
            return -1;
        }

        const std::string userOkaySignal = ServerSetMessage::GetMessageBySignal(SignalType::OKAYSIGNAL);
        Send::SendMessage(userSSLSocket, userOkaySignal); // if they are not rate limited send them an okay signal
        return 0;
    }

    static int CheckRequestNeededForServer(SSL *userSSLsocket, int &userTcpSocket, bool &requestNeeded, const std::string &ClientHashedIp)
    { // checks if users need to send a request to the server to join
        if (requestNeeded != true)
        {
            const std::string userOkaySignal = ServerSetMessage::GetMessageBySignal(SignalType::OKAYSIGNAL);
            Send::SendMessage(userSSLsocket, userOkaySignal); // send an okay signal if they dont need to request to join the server
            return 0;
        }

        // send user needs to request message
        const std::string serverRequestMessage = ServerSetMessage::GetMessageBySignal(SignalType::REQUESTNEEDED, 1);
        Send::SendMessage(userSSLsocket, serverRequestMessage);

        serverJoinRequests.push(ClientHashedIp);
        std::cout << fmt::format("User from hashed ip [{}..] is requesting to join the server. Accept or not?(y/n): ", ClientHashedIp.substr(0, ClientHashedIp.length() / 4));

        const char answer = toupper(getchar());

        if (answer == 'Y')
        {
            const std::string userAcceptedMessage = ServerSetMessage::GetMessageBySignal(SignalType::SERVERJOINREQUESTACCEPTED, 1);
            Send::SendMessage(userSSLsocket, userAcceptedMessage);
            serverJoinRequests.pop();
            std::cout << "\nUser has been allowed in server" << std::endl;
            return 0;
        }

        const std::string userNotAcceptedMessage = ServerSetMessage::GetMessageBySignal(SignalType::SERVERJOINREQUESTDENIED, 1);
        Send::SendMessage(userSSLsocket, userNotAcceptedMessage);
        serverJoinRequests.pop();
        std::cout << "\nUser has been not been allowed in server" << std::endl;
        CleanUp::CleanUpClient(-1, userSSLsocket, userTcpSocket);
        return -1;
    }
};