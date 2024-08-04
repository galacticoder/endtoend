#ifndef FILEHANDLER
#define FILEHANDLER

#include <iostream>
#include <filesystem>
#include <fstream>
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

int readActiveUsers(const std::string &filepath)
{
    std::string active;
    int activeInt;

    std::ifstream opent(filepath);
    std::getline(opent, active);
    std::istringstream(active) >> activeInt;
    return activeInt;
}

#endif