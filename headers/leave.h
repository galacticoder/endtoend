#pragma once

#ifndef LEAVE
#define LEAVE

#include <iostream>
#include <fmt/core.h>
#include <filesystem>
#include "getch_getline.h"
#include "linux_conio.h"

#define eraseLine "\033[2K\r"

void delIt(const string& formatpath);
void leave(const string& formatpath = formatPath, const string& fPath = fpath);

#endif