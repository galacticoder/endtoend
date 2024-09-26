#pragma once

#include <iostream>
#include <atomic>

namespace http
{
    void pingServer(const char *host, unsigned short port);
    void serverMake();
}
