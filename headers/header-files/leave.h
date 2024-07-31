#ifndef LEAVE
#define LEAVE

#pragma once

#include <iostream>
#include <fmt/core.h>
#include <filesystem>
#include "getch_getline.h"
#include "linux_conio.h"

#define eraseLine "\033[2K\r"

void delIt(const string &path);
void leave(const string &path = formatPath, const string &fPath = fpath);
void leaveFile(const string &path);

#endif