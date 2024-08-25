#ifndef _CLIENTHANDLE_
#define _CLIENTHANDLE_

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

#define connectionSignal "C"
#define usersActivePath "txt-files/usersActive.txt"

extern long int lineTrack;
extern int clientPort;
extern short leavePlace;
extern std::string trimWhitespaces(std::string strIp);

std::mutex HandleClientMutex;

pthread_mutex_t nmutex = PTHREAD_MUTEX_INITIALIZER;

void threadSafeWrefresh(WINDOW *win)
{
    pthread_mutex_lock(&nmutex);
    wrefresh(win);
    pthread_mutex_unlock(&nmutex);
}

class handleClient
{
public:
    static void receiveMessages(SSL *tlsSock, WINDOW *subwin, EVP_PKEY *prkey, EVP_PKEY *receivedPublicKey)
    {
        try
        {
            while (true)
            {
                lineTrack++;
                std::string receivedMessage = Receive::ReceiveMessageSSL(tlsSock);
                std::string decodedMessage;

                SignalType anySignalReceive = signalHandling::getSignalType(receivedMessage);
                signalHandling::handleSignal(anySignalReceive, receivedMessage);

                if (receivedMessage.find('|') == std::string::npos)
                {
                    decodedMessage = Decode::Base64Decode(receivedMessage);
                    std::string decryptedMessage = Decrypt::DecryptData(prkey, decodedMessage);

                    curs_set(0);
                    wmove(subwin, lineTrack, 0);
                    decryptedMessage += "\n";
                    wprintw(subwin, decryptedMessage.c_str(), lineTrack);
                    threadSafeWrefresh(subwin);
                    curs_set(1);
                }

                else if (receivedMessage.find('|') != std::string::npos) // for messages from client
                {
                    int firstPipe = receivedMessage.find_first_of("|");
                    int secondPipe = receivedMessage.find_last_of("|");

                    std::string cipher = receivedMessage.substr(secondPipe + 1);
                    std::string time = receivedMessage.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
                    std::string user = receivedMessage.substr(0, firstPipe);
                    decodedMessage = Decode::Base64Decode(cipher);

                    std::string messageFromUser = fmt::format("{}: {}", user, Decrypt::DecryptData(prkey, decodedMessage));

                    curs_set(0);
                    wmove(subwin, lineTrack, 0);
                    messageFromUser += "\n";
                    wprintw(subwin, messageFromUser.c_str(), lineTrack);
                    threadSafeWrefresh(subwin);
                    curs_set(1);
                }
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "Exception caught in receiveMessages function: " << e.what() << std::endl;
        }
    }

    static void handleInput(const std::string &userStr, EVP_PKEY *receivedPublicKey, SSL *tlsSock, WINDOW *subaddr, WINDOW *inputaddr)
    {
        std::string message;
        int ch;

        while (true)
        {
            ch = wgetch(inputaddr);
            if (ch == 13)
            {
                if (trimWhitespaces(message) == "/quit")
                {
                    break;
                }
                else if (!message.empty() && trimWhitespaces(message) != "/quit")
                {
                    lineTrack++;
                    curs_set(0);

                    wmove(subaddr, lineTrack, 0);

                    message = trimWhitespaces(message);

                    // encrypt and send message
                    std::string cipherText = Encrypt::EncryptData(receivedPublicKey, message);
                    cipherText = Encode::Base64Encode(cipherText);
                    Send::SendMessage(tlsSock, cipherText);

                    // print message on your screen
                    std::string messageFormat = fmt::format("{}(You): {}", userStr, message);
                    wprintw(subaddr, messageFormat.c_str(), lineTrack);
                    threadSafeWrefresh(subaddr);

                    wclear(inputaddr);
                    box(inputaddr, 0, 0);
                    threadSafeWrefresh(inputaddr);
                    message.clear();
                    wmove(inputaddr, 1, 1);
                    curs_set(1);
                }
            }
            else
            {
                message += ch;
                wprintw(inputaddr, "%c", ch);
                threadSafeWrefresh(inputaddr);
            }
        }
        return;
    }

    static void
    initCheck(SSL *tlsSock)
    {
        try
        {
            std::string initMsg = Receive::ReceiveMessageSSL(tlsSock); // get message to see if you are rate limited or the server is full

            SignalType signal = signalHandling::getSignalType(initMsg);
            signalHandling::handleSignal(signal, initMsg);

            // send connection signal and port your ping server is running on
            Send::SendMessage(tlsSock, (std::string)connectionSignal);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            Send::SendMessage(tlsSock, std::to_string(clientPort));

            std::string requestNeeded = Receive::ReceiveMessageSSL(tlsSock);

            SignalType requestSignal = signalHandling::getSignalType(requestNeeded);
            signalHandling::handleSignal(requestSignal, requestNeeded);

            if (requestSignal == SignalType::REQUESTNEEDED)
            {
                // check if you were accepted into the server or not (if request needed to join the server)
                std::string acceptMessage = Receive::ReceiveMessageSSL(tlsSock);

                SignalType acceptedSignal = signalHandling::getSignalType(acceptMessage);
                signalHandling::handleSignal(acceptedSignal, acceptMessage);
            }
        }

        catch (const std::exception &e)
        {
            std::cerr << "Exception in initCheck: " << e.what() << std::endl;
            raise(SIGINT);
        }
    }

    static void handlePassword(const std::string &serverPubKeyPath, SSL *tlsSock)
    {
        EVP_PKEY *serverPublicKey = LoadKey::LoadPublicKey(serverPubKeyPath);

        serverPublicKey ? std::cout << "Server's public key has been loaded" << std::endl : std::cout << "Cannot load server's public key. Exiting." << std::endl;

        if (!serverPublicKey)
            raise(SIGINT);

        std::cout << "This server is password protected. Enter the password to join: " << std::endl;

        std::string password;
        std::getline(std::cin, password);
        std::string encryptedPassword = Encrypt::EncryptData(serverPublicKey, password);
        encryptedPassword = Encode::Base64Encode(encryptedPassword);

        EVP_PKEY_free(serverPublicKey);
        Send::SendMessage(tlsSock, encryptedPassword);

        std::cout << "Verifying password.." << std::endl;

        std::string passwordVerification = Receive::ReceiveMessageSSL(tlsSock);

        SignalType handlePasswordVerification = signalHandling::getSignalType(passwordVerification);
        signalHandling::handleSignal(handlePasswordVerification, passwordVerification);
    }

    static EVP_PKEY *receiveKeysAndConnect(SSL *tlsSock, EVP_PKEY *receivedPublicKey, const std::string &userStr, int &activeUsers)
    {
        std::lock_guard<std::mutex> lock(HandleClientMutex);

        std::string checkErrSignals = Receive::ReceiveMessageSSL(tlsSock);

        SignalType checkingErrSignals = signalHandling::getSignalType(checkErrSignals);
        signalHandling::handleSignal(checkingErrSignals, checkErrSignals);

        if (activeUsers < 2)
        {
            std::cout << "You have connected to an empty chat. Waiting for another user to connect to start the chat" << std::endl;
            leavePlace = 0;

            while (true)
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                activeUsers = ReadFile::readActiveUsers(usersActivePath);
                if (activeUsers > 1)
                {
                    break;
                }
            }

            std::cout << "Another user connected, starting chat.." << std::endl;
        }

        std::string userPublicKey = Receive::ReceiveMessageSSL(tlsSock);

        std::string userName = userPublicKey.substr(userPublicKey.find_first_of("/") + 1, (userPublicKey.find_last_of("-") - userPublicKey.find_first_of("/")) - 1);

        std::cout << fmt::format("Recieving {}'s public key", userName) << std::endl;

        // receive and save user public key
        std::string userPubKeyEncodedData = Receive::ReceiveMessageSSL(tlsSock);
        std::string userPubKeyDecodedData = Decode::Base64Decode(userPubKeyEncodedData);
        SaveFile::saveFile(userPublicKey, userPubKeyDecodedData, std::ios::binary);

        std::cout << fmt::format("Recieved {}'s pub key", userName) << std::endl;

        std::cout << fmt::format("Attempting to load {}'s public key", userName) << std::endl;

        receivedPublicKey = LoadKey::LoadPublicKey(userPublicKey);
        receivedPublicKey ? std::cout << fmt::format("{}'s public key loaded", userName) << std::endl : std::cout << fmt::format("Could not load {}'s public key", userName) << std::endl;

        if (!receivedPublicKey)
            raise(SIGINT);

        leavePlace = 1;
        return receivedPublicKey;
    }
};

#endif