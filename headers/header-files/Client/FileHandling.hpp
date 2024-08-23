#ifndef FILEHANDLER
#define FILEHANDLER

#include <iostream>
#include <filesystem>
#include <fstream>
#include <csignal>
#include <fmt/core.h>

struct Create
{
    Create() = default;
    static bool createDir(const std::string &dirName)
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
};

struct ReadFile
{
    ReadFile() = default;
    static int readActiveUsers(const std::string &filepath)
    {
        std::string active;
        int activeInt;

        std::ifstream opent(filepath);
        std::getline(opent, active);
        std::istringstream(active) >> activeInt;
        return activeInt;
    }
    static std::string readPemKeyContents(const std::string &pemKeyPath)
    {
        std::ifstream keyFile(pemKeyPath);
        if (keyFile.is_open())
        {
            std::string pemKey((std::istreambuf_iterator<char>(keyFile)), std::istreambuf_iterator<char>());
            keyFile.close();
            return pemKey;
        }
        else
        {
            std::cout << "Could not open pem file" << std::endl;
            return "";
        }
    }
};

class SaveFile
{
public:
    static void saveFile(const std::string &filePath, const std::string &contentsToWrite, std::ios_base::openmode fileMode = std::ios_base::out)
    {
        std::ofstream file(filePath, fileMode);

        if (file.is_open())
        {
            file << contentsToWrite;
            return;
        }
        if (!std::filesystem::is_regular_file(filePath))
        {
            std::cout << fmt::format("Could not open file [{}] to write data: [{}]", filePath, contentsToWrite);
            raise(SIGINT);
        }
    }
};

#endif