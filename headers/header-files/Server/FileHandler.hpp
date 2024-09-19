#pragma once

#include <iostream>
#include <fmt/core.h>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <csignal>

#define ServerKeysPath "server-keys"
#define ServerReceivedKeysPath "server-recieved-client-keys"
#define PublicPath(username) fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.pem", username)

const std::string ServerPublicKeyPath = (std::string)ServerKeysPath + "/server-pubkey.pem";
const std::string ServerPrivateKeyPath = (std::string)ServerKeysPath + "/server-privkey.pem";
const std::string ServerCertPath = (std::string)ServerKeysPath + "/server-cert.pem";

std::mutex fileHandlerMutex;

struct Create
{
    Create() = default;
    static void CreateDirectory(const std::string &directoryName)
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
                    << fmt::format("{} files in filepath [{}] have been deleted", DeleteCounter, path) << std::endl;
            else if (DeleteCounter > 1)
                std::cout
                    << fmt::format("{} files in filepath [{}] have been deleted", DeleteCounter, path) << std::endl;

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
        else
        {
            return;
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
    static std::string ReadPemKeyContents(const std::string &pemKeyPath)
    {
        std::lock_guard<std::mutex> lock(fileHandlerMutex);
        std::ifstream keyFile(pemKeyPath);
        if (keyFile.is_open())
        {
            std::string pemKey((std::istreambuf_iterator<char>(keyFile)), std::istreambuf_iterator<char>());
            keyFile.close();
            return pemKey;
        }
        else
        {
            std::cout << "Could not open pem file: " << pemKeyPath << std::endl;
            return "";
        }
    }
};