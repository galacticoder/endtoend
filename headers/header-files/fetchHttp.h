#ifndef HTTPGET
#define HTTPGET

#pragma once

#include <iostream>

int fetchAndSave(const std::string &site, const std::string &outfile);
std::string fetchPubIp();

#endif