#ifndef FILEHANDLER
#define FILEHANDLER

#include <iostream>
#include <filesystem>
#include <fmt/core.h>

bool createDir(const std::string &dirName)
{
    if (!std::filesystem::create_directories(dirName))
    {
        if (std::filesystem::exists(dirName))
        {
            return true;
        }
        else
        {
            std::cout << fmt::format("Couldnt create directory: {}", dirName) << std::endl;
            return false;
        }
    }
    return true;
}

#endif