#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>
#include <cstring>
#include <filesystem>
#include <cstdio>
#include <algorithm>
#include "fileserver.h"
#include <mutex>

using namespace std;

mutex st;

bool isPav(int port)
{
    int pavtempsock;
    struct sockaddr_in addr;
    bool available = false;

    pavtempsock = socket(AF_INET, SOCK_STREAM, 0);

    if (pavtempsock < 0)
    {
        std::cerr << "Cannot create socket to test port availability" << std::endl;
        return false;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(pavtempsock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        available = false;
    }
    else
    {
        available = true;
    }

    close(pavtempsock);
    return available;
}

bool recvServer(string& filename) {
    unsigned short PORT = 49152;

    thread t1([&]()
        {
            if (!isPav(PORT)) {
                cout << "Port " << PORT << " is not usable searching for port to use.." << endl;
                for (unsigned short i = 49153; i <= 65535; i++) {
                    if (isPav(i)) {
                        PORT = i;
                        break;
                    }
                }
            }
        });
    t1.join();

    string portfile = "FILEPORT.TXT";
    std::ofstream file(portfile);
    if (file.is_open())
    {
        {
            lock_guard<mutex> lock(st);
            file << PORT;
            file.close();
        }
    }
    else
    {
        cout << "Cannot write file server port to file" << endl;
        return false;
    }

    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = { 0 };

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        return false;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("Setsockopt");
        return false;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        return false;
    }

    cout << "Started file server on port " << PORT << endl;

    if (listen(server_fd, 3) < 0) {
        perror("Listen");
        return false;
    }

    if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Accept");
        return false;
    }

    std::streamsize size;
    valread = read(new_socket, &size, sizeof(size));
    if (valread < 0) {
        perror("Error reading file size");
        return false;
    }

    std::ofstream received_file(filename, std::ios::binary);
    if (!received_file.is_open()) {
        std::cerr << "Could not open file to write" << std::endl;
        return false;
    }

    std::streamsize remaining_bytes = size;
    while (remaining_bytes > 0) {
        valread = read(new_socket, buffer, std::min<std::streamsize>(sizeof(buffer), remaining_bytes));
        if (valread < 0) {
            perror("Error reading file content");
            return false;
        }
        received_file.write(buffer, valread);
        remaining_bytes -= valread;
    }

    cout << "File " << filename << " received from client" << endl;
    received_file.close();

    std::ofstream file2(portfile);
    if (file2.is_open())
    {
        {
            lock_guard<mutex> lock(st);
            file2 << PORT;
            file2.close();
        }
    }
    else
    {
        cout << "Cannot write file server port to file" << endl;
        return false;
    }

    sleep(1);
    close(new_socket);
    close(server_fd);
    return true;
    //delete after client conncetion successfully
    // std::remove(portfile.c_str());
    // cout << "Port file deleted" << endl;
}
