#pragma once

#include <iostream>
#include <vector>
#include <queue>
#include <openssl/ssl.h>

class ServerSettings
{
public:
    inline static const unsigned int limitOfUsers = 2;
    inline static thread_local short timeLimit = 90;
    inline static long int totalClientJoins;
    inline static thread_local short exitSignal = 0;
    inline static unsigned long pingCount = 0;
    inline static bool passwordNeeded;
    inline static bool requestNeeded;
};

class ClientResources
{
public:
    inline static bool cleanUpInPing = true;
    // vectors
    inline static std::vector<std::string> clientsKeyContents;
    inline static std::vector<std::string> clientUsernames;
    inline static std::vector<int> passwordVerifiedClients;
    inline static std::vector<int> clientSocketsTcp;
    inline static std::vector<SSL *> clientSocketsSSL;
    // maps
    inline static std::map<std::string, short> amountOfTriesFromIP;
    inline static std::map<std::string, std::chrono::seconds::rep> timeMap;
    inline static std::map<std::string, short> clientServerPorts;
    // queues
    inline static std::queue<std::string> serverJoinRequests;
};