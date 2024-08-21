#ifndef HTTPGET
#define HTTPGET

#pragma once

#include <iostream>
#include <atomic>

namespace http
{
    // std::string http::hash_data(const std::string &pt);
    int fetchAndSave(const std::string &site, const std::string &outfile);
    void pingServer(const char *host, unsigned short port);
    void serverMake();
}

#endif