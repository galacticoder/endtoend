#ifndef LEAVE
#define LEAVE

#pragma once

#include <iostream>

#define eraseLine "\033[2K\r"

const std::string fp = "keys-from-server/";
const std::string fp2 = "your-keys/";

void delIt(const std::string &path);
void leave(const std::string &path = fp, const std::string &fPath = fp2);
void leaveFile(const std::string &path);

#endif