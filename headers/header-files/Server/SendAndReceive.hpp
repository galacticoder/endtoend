#pragma once

#include <iostream>
#include <cstring>
#include <vector>
#include <fmt/core.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "Keys.hpp"
#include "Encryption.hpp"
#include "ServerSettings.hpp"
#include "CleanUp.hpp"

std::mutex mut;
class Send
{
public:
    Send() = default;
    static void SendKey(SSL *clientSocket, int &&clientSendIndex /*index of client to send the key to*/, unsigned int &clientIndex)
    {
        std::lock_guard<std::mutex> lock(mut);

        std::cout << fmt::format("Sending Client {}'s key to Client {}", ClientResources::clientUsernames[clientIndex], ClientResources::clientUsernames[clientSendIndex]) << std::endl;
        const std::string publicKeyPath = PublicPath(ClientResources::clientUsernames[clientSendIndex]); // set the path for key to send

        Send::SendMessage<__LINE__>(clientSocket, publicKeyPath, __FILE__); // send path so client can get username of client

        const std::string keyContents = ReadFile::ReadPemKeyContents(PublicPath(ClientResources::clientUsernames[clientSendIndex]));

        if (keyContents.empty())
            return;

        std::cout << fmt::format("Key contents sending to client {}: {}", ClientResources::clientUsernames[clientSendIndex], keyContents) << std::endl;

        Send::SendMessage<__LINE__>(clientSocket, keyContents, __FILE__); // send the encoded key
    }

    template <auto lineNumberCalled>
    static int SendMessage(SSL *clientSocketSSL, const std::string &message, const char *fileCalledFrom)
    { // send the full message without missing bytes
        try
        {
            unsigned long int totalBytesWritten = 0;
            while (totalBytesWritten < message.length())
            {
                int bytesWritten = SSL_write(clientSocketSSL, message.c_str() + totalBytesWritten, message.length() - totalBytesWritten);

                if (bytesWritten > 0)
                {
                    totalBytesWritten += bytesWritten;
                    return 0;
                }
                else
                {
                    unsigned long sslError = ERR_get_error();
                    std::string errorMessage = ERR_error_string(sslError, nullptr);

                    if (sslError == 0)
                    {
                        std::cout << fmt::format("[{}:{} -> {}:{}] Error [{}:{}]: {}", __FILE__, __LINE__, fileCalledFrom, lineNumberCalled, __func__, __LINE__, errorMessage) << std::endl;
                        return -2;
                    }
                    else
                    {
                        std::cout << fmt::format("[{}:{} -> {}:{}] Error [{}:{}]: {}", __FILE__, __LINE__, fileCalledFrom, lineNumberCalled, __func__, __LINE__, errorMessage) << std::endl;
                        return -1;
                    }

                    break;
                }
            }
        }
        catch (const std::exception &e)
        {
            std::cout << fmt::format("[{}:{} -> {}:{}] Exception caught [{}:{}]: {}", __FILE__, __LINE__, fileCalledFrom, lineNumberCalled, __func__, __LINE__, e.what()) << std::endl;
        }
        return -1;
    }

    static void BroadcastMessage(SSL *senderSocket, const std::string &message)
    {
        for (SSL *clientSocketSSL : ClientResources::clientSocketsSSL)
        {
            if (clientSocketSSL != senderSocket)
            {
                std::cout << "Sending message to tls sock [" << clientSocketSSL << "]" << std::endl;
                SendMessage<__LINE__>(clientSocketSSL, message, __FILE__);
            }
        }
    }

    static void BroadcastEncryptedExitMessage(unsigned int &clientIndex, int clientToSendMsgIndex)
    {
        std::cout << "Broadcasting exit message of user " << ClientResources::clientUsernames[clientIndex] << "to " << ClientResources::clientUsernames[clientToSendMsgIndex] << std::endl;
        std::string UserExitMessage = fmt::format("{} has left the chat", ClientResources::clientUsernames[clientIndex]);
        EVP_PKEY *LoadedUserPublicKey = LoadKey::LoadPublicKey(PublicPath(ClientResources::clientUsernames[clientToSendMsgIndex])); // load other user public key
        if (!LoadedUserPublicKey)
        {
            std::cout << fmt::format("User [{}] pub key cannot be loaded for encrypted exit message", ClientResources::clientUsernames[clientToSendMsgIndex]) << std::endl;
            CleanUp::CleanUpClient(clientToSendMsgIndex);
            return;
        }

        std::string EncryptedExitMessage = Encrypt::EncryptData(LoadedUserPublicKey, UserExitMessage);
        EncryptedExitMessage = Encode::Base64Encode(EncryptedExitMessage);

        if (EncryptedExitMessage != "err" && !EncryptedExitMessage.empty())
        {
            std::cout << fmt::format("Broadcasting user [{}]'s exit message", ClientResources::clientUsernames[clientIndex]) << std::endl;
            Send::BroadcastMessage(ClientResources::clientSocketsSSL[clientToSendMsgIndex], EncryptedExitMessage);
        }

        EVP_PKEY_free(LoadedUserPublicKey);
    }
};

class Receive
{
public:
    Receive() = default;

    template <auto lineNumberCalled>
    static std::string ReceiveMessageSSL(SSL *clientSocketSSL, const char *fileCalledFrom)
    {
        try
        {
            char buffer[2048] = {0};
            ssize_t bytes = SSL_read(clientSocketSSL, buffer, sizeof(buffer) - 1);
            buffer[bytes] = '\0';
            std::string message(buffer);

            if (bytes > 0)
            {
                return message;
            }
            else
            {
                unsigned long sslError = ERR_get_error();
                std::string errorMessage = ERR_error_string(sslError, nullptr);

                if (bytes == 0)
                {
                    std::cout << fmt::format("[{}:{} -> {}:{}] Error [{}:{}]: {}", __FILE__, __LINE__, fileCalledFrom, lineNumberCalled, __func__, __LINE__, errorMessage) << std::endl;
                }
                else
                {
                    std::cout << fmt::format("[{}:{} -> {}:{}] Error [{}:{}]: {}", __FILE__, __LINE__, fileCalledFrom, lineNumberCalled, __func__, __LINE__, errorMessage) << std::endl;
                }

                return "";
            }
        }
        catch (const std::exception &e)
        {
            std::cout << fmt::format("[{}:{} -> {}:{}] Exception caught in function [{}]: {}", __FILE__, __LINE__, fileCalledFrom, lineNumberCalled, __func__, e.what()) << std::endl;
        }

        return "";
    }

    static std::string ReceiveMessageTcp(int &clientTcpsocket)
    {
        try
        {
            char buffer[2048] = {0};
            ssize_t bytes = recv(clientTcpsocket, buffer, sizeof(buffer) - 1, 0);
            buffer[bytes] = '\0';
            std::string message(buffer);

            if (bytes > 0)
                return message;
        }
        catch (const std::exception &e)
        {
            std::cout << "Exception caught in ReceiveMessageTcp: " << e.what() << std::endl;
        }
        return "";
    }
};
