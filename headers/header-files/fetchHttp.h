#ifndef HTTPGET
#define HTTPGET

#pragma once

#include <iostream>

std::string hash_data(const std::string &pt);
int fetchAndSave(const std::string &site, const std::string &outfile);
std::string fetchPubIp();

#endif