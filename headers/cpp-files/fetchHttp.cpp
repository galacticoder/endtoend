#include <iostream>
#include <fstream>
#include <string>
#include "../header-files/fetchHttp.h"
#include <curl/curl.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <iomanip>

size_t writeCallBack(void *contents, size_t size, size_t nmemb, void *userp)
{
    std::ofstream *outfile = static_cast<std::ofstream *>(userp);
    size_t totalSize = size * nmemb;
    outfile->write(static_cast<char *>(contents), totalSize);
    return totalSize;
}

size_t writeCallBackIp(void *contents, size_t size, size_t nmemb, void *userp)
{
    std::string *result = static_cast<std::string *>(userp);
    size_t totalSize = size * nmemb;
    result->append(static_cast<char *>(contents), totalSize);
    return totalSize;
}

std::string hash_data(const std::string &pt)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lenHash = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr)
    {
        std::cout << "Error creating ctx" << std::endl;
        return "err";
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr) != 1)
    {
        std::cout << "Error initializing digest" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return "err";
    }

    if (EVP_DigestUpdate(mdctx, pt.c_str(), pt.size()) != 1)
    {
        std::cout << "Error updating digest" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return "err";
    }
    if (EVP_DigestFinal_ex(mdctx, hash, &lenHash) != 1)
    {
        std::cout << "Error finalizing digest" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return "err";
    }

    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < lenHash; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str(); // returning hash
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

std::string fetchPubIp()
{
    CURL *curl;
    CURLcode request;
    // std::ofstream outFile(outfile, std::ios::binary);
    std::string ip;
    std::string site = "https://api.ipify.org";

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init(); // init libcur

    if (curl)
    {
        std::cout << "Curl has started" << std::endl;
        curl_easy_setopt(curl, CURLOPT_URL, site.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallBackIp);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ip);
        request = curl_easy_perform(curl);

        if (request != CURLE_OK)
        {
            curl_easy_strerror(request);
            return "err";
        }
        curl_easy_cleanup(curl);
        ip = hash_data(ip);
        return ip;
    }
    curl_global_cleanup();
    ip = hash_data(ip);
    return ip;
}