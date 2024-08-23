#ifndef SENDANDRECEIVEMESSAGE
#define SENDANDRECEIVEMESSAGE

#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <thread>
#include <netinet/in.h>
#include <csignal>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

struct Send
{
    Send() = default;
    static void SendMessage(SSL *socket, const std::string &message)
    { // send the full message without missing bytes
        try
        {
            unsigned long int totalBytesWritten = 0;
            while (totalBytesWritten < message.length())
            {
                int bytesWritten = SSL_write(socket, message.c_str() + totalBytesWritten, message.length() - totalBytesWritten);

                if (bytesWritten > 0)
                {
                    totalBytesWritten += bytesWritten;
                }
                else
                {
                    int errorCode = SSL_get_error(socket, bytesWritten);
                    std::cout << "Error occured during sending in SendMessage. SSL error: " << errorCode;
                    raise(SIGINT);
                }
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "Exception caught in SendMessage: " << e.what();
            raise(SIGINT);
        }
    }
};

struct Receive
{
    Receive() = default;
    static std::string ReceiveMessage(SSL *socket)
    {
        try
        {
            char buffer[2048] = {0};
            ssize_t bytes = SSL_read(socket, buffer, sizeof(buffer) - 1);
            buffer[bytes] = '\0';
            std::string msg(buffer);

            if (bytes > 0)
            {
                return msg;
            }
            else
            {
                int error = SSL_get_error(socket, bytes);
                std::cout << "Error occured during reading in receiveMessage. SSL error: " << error;
                raise(SIGINT);
            }
        }
        catch (const std::exception &e)
        {
            std::cout << "Exception caught in receiveMessage: " << e.what();
            raise(SIGINT);
        }
        return "";
    }
};

#endif