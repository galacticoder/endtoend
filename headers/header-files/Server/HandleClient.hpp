#ifndef CLIENTHANDLER
#define CLIENTHANDLER

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
;

class HandleClient
{
    // private:
    //     // static ;

public:
    static void ClientPasswordVerification(SSL *ClientSSLSocket, int &ClientIndex, const std::string &ServerPrivateKeyPath, const std::string &ClientHashedIp, const std::string &ServerHashedPassword)
    {
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

        if (bcrypt::validatePassword(ReceivedPasswordCipher, ServerHashedPassword) != 1)
        {
            const std::string PasswordNotVerifiedMessage = ServerSetMessage::GetMessageBySignal(SignalType::NOTVERIFIED, 1);
            Send::SendMessage(ClientSSLSocket, PasswordNotVerifiedMessage); // sends them the not VerifiedMessage message
            CleanUp::CleanUpClient(ClientIndex);
            std::cout << fmt::format("User with hashed ip [{}..] has entered the wrong password and has been kicked", ClientHashedIp.substr(0, ClientHashedIp.length() / 4)) << std::endl;
            return;
        }

        const std::string PasswordVerifiedMessage = ServerSetMessage::GetMessageBySignal(SignalType::VERIFIED, 1);
        Send::SendMessage(ClientSSLSocket, PasswordVerifiedMessage);
        PasswordVerifiedClients[ClientIndex] = 1; // set client as verified
        std::cout << "User password VerifiedMessage and added to clientHashVerifiedClients vector" << std::endl;
        std::cout << "Updated vector size: " << PasswordVerifiedClients.size() << std::endl;
    }

    static void ClientUsernameValidity(SSL *ClientSSLSocket, int &ClientIndex, const std::string &ClientUsername)
    {
        const std::string UnallowedCharacters = "\\/~ ";
        // checks if username already exists
        if (std::find(clientUsernames.begin(), clientUsernames.end(), ClientUsername) != clientUsernames.end())
        {
            std::cout << "Client with the same username detected. kicking.." << std::endl;
            const std::string NameAlreadyExistsMessage = ServerSetMessage::GetMessageBySignal(SignalType::NAMEEXISTSERR, 1);
            Send::SendMessage(ClientSSLSocket, NameAlreadyExistsMessage);
            CleanUp::CleanUpClient(ClientIndex);
            std::cout << "Kicked client with same username kicked" << std::endl;
            return;
        }

        // check if client username is invalid in length
        if (ClientUsername.size() <= 3 || ClientUsername.size() > 12)
        {
            const std::string InvalidUsernameLengthMessage = ServerSetMessage::GetMessageBySignal(SignalType::INVALIDNAMELENGTH, 1);
            Send::SendMessage(ClientSSLSocket, InvalidUsernameLengthMessage);
            CleanUp::CleanUpClient(ClientIndex);
            std::cout << "Disconnected user with empty name" << std::endl;
            return;
        }

        // check if client username contains unallowed characters
        for (int i = 0; i < ClientUsername.size(); i++)
        {
            if (UnallowedCharacters.find(ClientUsername[i]))
            {
                std::cout << "Client username includes invalid character[s] from UnallowedCharacters variable. Kicking." << std::endl;
                const std::string InvalidUsernameMessage = ServerSetMessage::GetMessageBySignal(SignalType::INVALIDNAME, 1);
                Send::SendMessage(ClientSSLSocket, InvalidUsernameMessage);
                CleanUp::CleanUpClient(ClientIndex);
                return;
            }
        }
    }

    static int CheckUserLimitReached(SSL *userSSLSocket, int &userTcpSocket, int &limitOfUsers)
    {
        if (clientUsernames.size() == limitOfUsers)
        {
            const std::string userLimitReachedMessage = ServerSetMessage::GetMessageBySignal(SignalType::SERVERLIMIT, 1);
            const std::string encodedLimitReachedMessage = Encode::Base64Encode(userLimitReachedMessage);
            Send::SendMessage(userSSLSocket, encodedLimitReachedMessage);
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
            std::string encodedRatelimitedMessage = Encode::Base64Encode(userRatelimitedMessage);
            Send::SendMessage(userSSLSocket, encodedRatelimitedMessage);
            CleanUp::CleanUpClient(-1, userSSLSocket, userTcpSocket);
            std::cout << "Client kicked for attempting to join too frequently" << std::endl;
            return -1;
        }

        const std::string userOkaySignal = ServerSetMessage::GetMessageBySignal(SignalType::OKAYSIGNAL);
        Send::SendMessage(userSSLSocket, userOkaySignal); // if they are not rate limited send them an okay signal
        return 0;
    }

    static int CheckRequestNeededForServer(SSL *userSSLsocket, int &userTcpSocket, int &requestNeeded, const std::string &ClientHashedIp)
    { // checks if users need to send a request to the server to join
        if (requestNeeded != 1)
        {
            const std::string userOkaySignal = ServerSetMessage::GetMessageBySignal(SignalType::OKAYSIGNAL);
            Send::SendMessage(userSSLsocket, userOkaySignal); // send an okay signal if they dont need to request to join the server
            return 0;
        }

        // send user needs to request message
        const std::string serverRequestMessage = ServerSetMessage::GetMessageBySignal(SignalType::REQUESTNEEDED, 1);
        const std::string encodedServerRequestMessage = Encode::Base64Encode(serverRequestMessage);
        Send::SendMessage(userSSLsocket, encodedServerRequestMessage);

        serverJoinRequests.push(ClientHashedIp);
        std::cout << fmt::format("User from hashed ip [{}..] is requesting to join the server. Accept or not?(y/n): ", ClientHashedIp.substr(0, ClientHashedIp.length() / 4));

        const char answer = toupper(getchar());

        if (answer == 'Y')
        {
            const std::string userAcceptedMessage = ServerSetMessage::GetMessageBySignal(SignalType::SERVERJOINREQUESTACCEPTED, 1);
            const std::string encodedAcceptedMessage = Encode::Base64Encode(userAcceptedMessage);
            Send::SendMessage(userSSLsocket, encodedAcceptedMessage);
            serverJoinRequests.pop();
            std::cout << "\nUser has been allowed in server" << std::endl;
            return 0;
        }

        const std::string userNotAcceptedMessage = ServerSetMessage::GetMessageBySignal(SignalType::SERVERJOINREQUESTDENIED, 1);
        const std::string encodedNotAcceptedMessage = Encode::Base64Encode(userNotAcceptedMessage);
        Send::SendMessage(userSSLsocket, encodedNotAcceptedMessage);
        serverJoinRequests.pop();
        std::cout << "\nUser has been not been allowed in server" << std::endl;
        CleanUp::CleanUpClient(-1, userSSLsocket, userTcpSocket);
        return -1;
    }
};

#endif
// else if (pnInt == 2)
// {
//     std::cout << fmt::format("Sending hashed ip [{}..] signal okay [2]", ClientHashedIp.substr(0, ClientHashedIp.length() / 4)) << std::endl;
//     std::string encoded = enc.Base64Encode((std::string)OKSIG);
//     encoded.append("OK");
//     SSL_write(clientSSLSocket, encoded.c_str(), encoded.size());
// }
