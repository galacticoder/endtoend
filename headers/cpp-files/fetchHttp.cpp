#include <iostream>
#include <fstream>
#include "../header-files/fetchHttp.h"
#include <curl/curl.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <boost/asio.hpp>
#include <boost/asio/error.hpp>
#include <boost/beast.hpp>
#include <iomanip>
#include <fmt/core.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <thread>

namespace asio = boost::asio;
namespace beast = boost::beast;
using tcp = boost::asio::ip::tcp;

size_t writeCallBack(void *contents, size_t size, size_t nmemb, void *userp)
{
    std::ofstream *outfile = static_cast<std::ofstream *>(userp);
    size_t totalSize = size * nmemb;
    outfile->write(static_cast<char *>(contents), totalSize);
    return totalSize;
}

size_t writePing(void *contents, size_t size, size_t nmemb, void *userp)
{
    std::string *result = static_cast<std::string *>(userp);
    size_t totalSize = size * nmemb;
    result->append(static_cast<char *>(contents), totalSize);
    return totalSize;
}

int fetchAndSave(const std::string &site, const std::string &outfile)
{
    CURL *curl;
    CURLcode request;
    std::ofstream outFile(outfile, std::ios::binary);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init(); // init libcur

    if (curl)
    {
        std::cout << "Curl has started" << std::endl;
        curl_easy_setopt(curl, CURLOPT_URL, site.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallBack);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &outFile);
        request = curl_easy_perform(curl);

        if (request != CURLE_OK)
        {
            curl_easy_strerror(request);
            return 1;
        }
        curl_easy_cleanup(curl);
        outFile.close();
        return 0;
    }
    curl_global_cleanup();
    return 0;
}

void pingServer(const char *host, unsigned short port, std::atomic<bool> &running, unsigned int update_secs)
{
    const auto wait_duration = std::chrono::seconds(update_secs);
    while (1)
    {
        try
        {
            int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
            if (clientSocket < 0)
            {
            }

            sockaddr_in serverAddress;
            serverAddress.sin_family = AF_INET;
            serverAddress.sin_port = htons(port);

            if (inet_pton(AF_INET, host, &serverAddress.sin_addr) <= 0)
            {
                running = false;
            }

            if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
            {
                close(clientSocket);
            }

            const std::string pingMsg = "ping";
            send(clientSocket, pingMsg.c_str(), pingMsg.length(), 0);

            char buffer[8] = {0};
            int valread = read(clientSocket, buffer, 8);
            buffer[valread] = '\0';
            std::string readStr(buffer);

            if (readStr == "pong")
            {
                close(clientSocket);
            }
            else
            {
                close(clientSocket);
                running = false;
            }
            std::this_thread::sleep_for(wait_duration);
        }
        catch (const std::exception &e)
        {
        }
    }
}
// std::string fetchPubIp()
// {
//     CURL *curl;
//     CURLcode request;
//     // std::ofstream outFile(outfile, std::ios::binary);
//     std::string ip;
//     std::string site = "https://api.ipify.org";

//     curl_global_init(CURL_GLOBAL_DEFAULT);
//     curl = curl_easy_init(); // init libcur

//     if (curl)
//     {
//         std::cout << "Curl has started" << std::endl;
//         curl_easy_setopt(curl, CURLOPT_URL, site.c_str());
//         curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallBackIp);
//         curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ip);
//         request = curl_easy_perform(curl);

//         if (request != CURLE_OK)
//         {
//             curl_easy_strerror(request);
//             return "err";
//         }
//         curl_easy_cleanup(curl);
//         ip = hash_data(ip);
//         return ip;
//     }
//     curl_global_cleanup();
//     ip = hash_data(ip);
//     return ip;
// }
