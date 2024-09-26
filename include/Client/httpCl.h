#ifndef HTTPGET
#define HTTPGET

#include <iostream>
#include <atomic>

namespace http
{
    int fetchAndSave(const std::string &site, const std::string &outfile);
    void pingServer(const char *host, unsigned short port);
    void serverMake();
}

#endif