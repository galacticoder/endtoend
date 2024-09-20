#pragma once

#include <iostream>
#include <vector>
#include <queue>
#include <map>
#include <chrono>
#include <openssl/ssl.h>

class ServerSettings
{
public:
    inline static std::string serverHash;
    inline static const unsigned int limitOfUsers = 2;
    inline static short defaultTimeLimit = 90;
    inline static thread_local bool exitSignal = false;
    inline static long int totalClientJoins;
    inline static unsigned long pingCount = 0;
    inline static bool passwordNeeded;
    inline static bool requestNeeded;
    inline static unsigned int minimumNameLength = 4;
    inline static unsigned int maximumNameLength = 12;
    inline static unsigned int minimumPasswordLength = 6;
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
    inline static std::vector<std::string> blackListedClients;
    inline static std::vector<SSL *> clientSocketsSSL;
    // maps
    inline static std::map<std::string, short> amountOfTriesFromIP;
    inline static std::map<std::string, short> clientServerPorts;
    inline static std::map<std::string, unsigned long int> clientTimeLimits;
    // queues
    inline static std::queue<std::string> serverJoinRequests;
};