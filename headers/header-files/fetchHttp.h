#ifndef HTTPGET
#define HTTPGET

#pragma once

#include <iostream>

void fetch_and_save_certificate(const std::string &host, const std::string &port, const std::string &certFilePath);

#endif