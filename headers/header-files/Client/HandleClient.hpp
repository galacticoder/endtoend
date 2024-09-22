#pragma once

#include <iostream>
#include <thread>
#include <fmt/core.h>
#include <csignal>
#include <mutex>
#include "SendAndReceive.hpp"
#include "Encryption.hpp"
#include "Decryption.hpp"
#include "SignalHandler.hpp"
#include "FileHandling.hpp"

#define FILE __FILE__
#define LINE __LINE__
#define FUNC __func__

extern long int lineTrack;
extern int clientPort;
extern short usersConnected;
extern std::string TrimWhitespaces(std::string strIp);

std::mutex handleClientMutex;

class HandleClient
{
private:
    inline static std::vector<std::string> clientInfo;

    static void threadSafeWrefresh(WINDOW *win)
    {
        std::lock_guard<std::mutex> lock(handleClientMutex);
        wrefresh(win);
    }

    static void printAndRefreshWindow(WINDOW *subwindow, WINDOW *inputWindow, std::string message)
    {
        curs_set(0);
        wmove(subwindow, lineTrack, 0);
        message += "\n";
        wprintw(subwindow, message.c_str(), lineTrack);
        threadSafeWrefresh(subwindow);
        wmove(inputWindow, 1, 1);
        curs_set(1);
    }

    static void redrawWindow(WINDOW *window)
    {
        wclear(window);
        box(window, 0, 0);
        threadSafeWrefresh(window);
        wmove(window, 1, 1);
    }

    static void ClientMessageExtract(std::string &receivedMessage)
    {
        int firstPipe = receivedMessage.find_first_of("|");
        int secondPipe = receivedMessage.find_last_of("|");

        clientInfo.push_back(receivedMessage.substr(secondPipe + 1));                              // cipherText
        clientInfo.push_back(receivedMessage.substr(firstPipe + 1, (secondPipe - firstPipe) - 1)); // time
        clientInfo.push_back(receivedMessage.substr(0, firstPipe));                                // username
    }

    static std::string GetFormattedMessage(const std::string &decryptedMessage, const std::string username /*, const std::string time*/, bool clientMessage = true)
    {
        if (username.empty())
            return fmt::format("{}", decryptedMessage /*, time*/);

        return (clientMessage == false) ? fmt::format("{}(You): {}", username, decryptedMessage /*, time*/) : fmt::format("{}: {}", username, decryptedMessage /*, time*/);
    }

public:
    static void ReceiveMessages(SSL *clientSocketSSL, WINDOW *subwin, EVP_PKEY *privateKey, EVP_PKEY *receivedPublicKey, WINDOW *inputWindow)
    {
        try
        {
            while (true)
            {
                std::string receivedMessage = Receive::ReceiveMessageSSL(clientSocketSSL);
                char messageType;

                SignalType anySignalReceive = SignalHandling::getSignalType(Decode::Base64Decode(receivedMessage));
                SignalHandling::handleSignal(anySignalReceive, receivedMessage, clientSocketSSL, receivedPublicKey);

                lineTrack++;

                if (receivedMessage.find('|') != std::string::npos)
                {
                    messageType = 'C';
                    ClientMessageExtract(receivedMessage);
                    receivedMessage = clientInfo[0]; // set to the extracted cipher text in vector
                }

                std::string decodedMessage = Decode::Base64Decode(receivedMessage);
                std::string decryptedMessage = Decrypt::DecryptData(privateKey, decodedMessage);

                std::string message = GetFormattedMessage(decryptedMessage, (messageType == 'C') ? clientInfo[2] : "");

                message.append(fmt::format(" signal is {} | ", (int)anySignalReceive));
                message += Decode::Base64Decode(receivedMessage).size() > 20 ? "" : Decode::Base64Decode(receivedMessage);

                clientInfo.clear();
                messageType = '\0';
                printAndRefreshWindow(subwin, inputWindow, message);
            }
        }
        catch (const std::exception &e)
        {
            ErrorHandling::LOGERROR<LINE>(ErrorTypes::EXCEPTION, e.what(), FILE, FUNC);
        }
    }

    static void HandleInput(const std::string &username, EVP_PKEY *receivedPublicKey, SSL *clientSocketSSL, WINDOW *subwindow, WINDOW *inputWindow)
    {
        std::string message;
        int character;

        while (true)
        {
            character = wgetch(inputWindow);
            if (character == 13) // enter button
            {
                if (message.empty())
                {
                    continue;
                }
                if (TrimWhitespaces(message) != SignalHandling::GetSignalAsString(SignalType::QUIT))
                {
                    lineTrack++;

                    curs_set(0);
                    wmove(subwindow, lineTrack, 0);
                    curs_set(1);

                    message = TrimWhitespaces(message);

                    std::string encryptedMessage = Encrypt::EncryptData(receivedPublicKey, message);
                    Send::SendMessage(clientSocketSSL, Encode::Base64Encode(encryptedMessage));

                    std::string formattedMessage = GetFormattedMessage(message, username, false);
                    printAndRefreshWindow(subwindow, inputWindow, formattedMessage);
                    redrawWindow(inputWindow);

                    message.clear();
                }
                else if (TrimWhitespaces(message) != SignalHandling::GetSignalAsString(SignalType::QUIT))
                {
                    break;
                }
            }
            else
            {
                message += character;
                wprintw(inputWindow, "%c", character);
                threadSafeWrefresh(inputWindow);
            }
        }
    }

    static std::string GetServerIp()
    {
        std::string serverIp;
        std::cout << "Enter the server ip to connect to (Leave empty for local ip): ";
        std::getline(std::cin, serverIp);

        if (serverIp.empty())
            serverIp = "127.0.0.1";

        return TrimWhitespaces(serverIp);
    }

    static int GetPort()
    {
        std::cout << "Enter the port to connect to: ";

        std::string port;
        std::getline(std::cin, port);

        return atoi(port.c_str());
    }
};

class Authentication
{
public:
    static void ServerValidation(SSL *clientSocketSSL)
    {
        try
        {
            // get message to see if you are rate limited or the server is full or other signals
            std::string initMsg = Receive::ReceiveMessageSSL(clientSocketSSL);

            SignalType signal = SignalHandling::getSignalType(initMsg);
            SignalHandling::handleSignal(signal, initMsg);

            Send::SendMessage(clientSocketSSL, std::to_string(clientPort));

            std::string requestNeeded = Receive::ReceiveMessageSSL(clientSocketSSL);

            SignalType requestSignal = SignalHandling::getSignalType(requestNeeded);
            SignalHandling::handleSignal(requestSignal, requestNeeded);

            if (requestSignal == SignalType::REQUESTNEEDED)
            {
                // check if you were accepted into the server or not (if request needed to join the server)
                std::string acceptMessage = Receive::ReceiveMessageSSL(clientSocketSSL);

                SignalType acceptedSignal = SignalHandling::getSignalType(acceptMessage);
                SignalHandling::handleSignal(acceptedSignal, acceptMessage);
            }
        }

        catch (const std::exception &e)
        {
            ErrorHandling::LOGERROR<LINE>(ErrorTypes::EXCEPTION, e.what(), FILE, FUNC);
            raise(SIGINT);
        }
    }

    static void HandlePassword(const std::string &serverPubKeyPath, SSL *clientSocketSSL, std::string message)
    {
        SignalType passwordNeededSignal = SignalHandling::getSignalType(message);

        if (passwordNeededSignal == SignalType::PASSWORDNOTNEEDED)
        {
            SignalHandling::handleSignal(passwordNeededSignal, message);
            return;
        }

        EVP_PKEY *serverPublicKey = LoadKey::LoadPublicKey(serverPubKeyPath);

        serverPublicKey ? std::cout << "Server's public key has been loaded" << std::endl : std::cout << "Cannot load server's public key. Exiting." << std::endl;

        if (!serverPublicKey)
            raise(SIGINT);

        SignalHandling::handleSignal(passwordNeededSignal, message);

        std::string password;
        std::getline(std::cin, password);
        std::string encryptedPassword = Encrypt::EncryptData(serverPublicKey, password);
        encryptedPassword = Encode::Base64Encode(encryptedPassword);

        EVP_PKEY_free(serverPublicKey);
        Send::SendMessage(clientSocketSSL, encryptedPassword);

        std::cout << "Verifying password.." << std::endl;

        std::string passwordVerification = Receive::ReceiveMessageSSL(clientSocketSSL);

        SignalType handlePasswordVerification = SignalHandling::getSignalType(passwordVerification);
        SignalHandling::handleSignal(handlePasswordVerification, passwordVerification);
    }

    static EVP_PKEY *receiveKeysAndConnect(SSL *clientSocketSSL, const std::string &username)
    {
        std::lock_guard<std::mutex> lock(handleClientMutex);

        std::string checkErrSignals = Receive::ReceiveMessageSSL(clientSocketSSL);

        SignalType checkingErrSignals = SignalHandling::getSignalType(checkErrSignals);
        SignalHandling::handleSignal(checkingErrSignals, checkErrSignals);

        if (usersConnected < 2)
        {
            std::cout << "You have connected to an empty chat. Waiting for another user to connect to start the chat" << std::endl;
            while (usersConnected < 2)
            {
                std::istringstream(Receive::ReceiveMessageSSL(clientSocketSSL)) >> usersConnected;
            }
            std::cout << "Another user connected, starting chat.." << std::endl;
        }

        std::string clientUsernameKey = Receive::ReceiveMessageSSL(clientSocketSSL);

        std::string formattedClientUsername = clientUsernameKey.substr(clientUsernameKey.find_first_of("/") + 1, (clientUsernameKey.find_last_of("-") - clientUsernameKey.find_first_of("/")) - 1);

        std::cout << fmt::format("Receiving {}'s public key", formattedClientUsername) << std::endl;

        // receive and save user public key
        const std::string saveKeyPath = PublicKeyPathSet(formattedClientUsername);
        std::string userPubKey = Receive::ReceiveMessageSSL(clientSocketSSL);
        SaveFile::saveFile(saveKeyPath, userPubKey, std::ios::binary);

        std::cout << fmt::format("Received {}'s pub key", formattedClientUsername) << std::endl;

        std::cout << fmt::format("Attempting to load {}'s public key", formattedClientUsername) << std::endl;

        EVP_PKEY *receivedPublicKey = LoadKey::LoadPublicKey(saveKeyPath);

        if (!receivedPublicKey)
        {
            std::cout << fmt::format("Could not load {}'s public key", formattedClientUsername) << std::endl;
            raise(SIGINT);
        }

        std::cout << fmt::format("{}'s public key loaded", formattedClientUsername) << std::endl;

        return receivedPublicKey;
    }
};
