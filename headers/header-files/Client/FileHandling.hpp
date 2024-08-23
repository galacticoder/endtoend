#ifndef FILEHANDLER
#define FILEHANDLER

#include <iostream>
#include <filesystem>
#include <fstream>
#include <csignal>
#include <fmt/core.h>

#define ServerKeysPath "server-keys/"
#define UsersActivePath "txt-files/usersActive.txt"
#define KeysReceivedFromServerPath "keys-from-server/"
#define YourKeysPath "your-keys/"

struct Create
{
    Create() = default;
    static void createDirectory(const std::string &directoryName)
    {
        if (!std::filesystem::create_directories(directoryName))
        {
            if (std::filesystem::exists(directoryName))
                return;
            else
                std::cout << fmt::format("Couldnt create directory: {}", directoryName) << std::endl;
            raise(SIGINT);
        }
    }
};

struct Delete
{
    static void DeletePath(const std::string &path)
    {
        std::error_code errorCode;
        if (std::filesystem::is_directory(path)) // check if the path given is a directory
        {
            std::uintmax_t DeleteCounter = std::filesystem::remove_all(path);
            std::filesystem::remove(path);

            if (DeleteCounter == 0)
                std::cout << fmt::format("There was nothing to delete from path [{}]", path) << std::endl;
            else if (DeleteCounter == 1)
                std::cout
                    << fmt::format("{} key in filepath [{}] have been deleted", DeleteCounter, path) << std::endl;
            else if (DeleteCounter > 1)
                std::cout
                    << fmt::format("{} keys in filepath [{}] have been deleted", DeleteCounter, path) << std::endl;

            std::cout << fmt::format("Deleted directory [{}]", path) << std::endl;
        }
        else if (std::filesystem::is_regular_file(path)) // check if the path given is a file
        {
            if (!std::filesystem::remove(path, errorCode))
            {
                errorCode.message();
                return;
            }
            std::cout << fmt::format("Deleted file [{}]", path) << std::endl;
        }
    }
};

struct SaveFile
{
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

#endif