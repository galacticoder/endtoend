#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>
#include <cstring>
#include "filesender.h"
#include <mutex>

using namespace std;

mutex to;

bool sendFile(string& filename) {
    int PORT;
    string portfile = "FILEPORT.TXT";
    ifstream fileport(portfile);
    if (!fileport.is_open()) {
        cerr << "Could not open port file" << endl;
        return false;
    }
    string PORTSTR;
    getline(fileport, PORTSTR);
    istringstream(PORTSTR) >> PORT;

    int client_socket = 0;
    struct sockaddr_in serv_addr;

    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Could not open file '" << filename << "'" << std::endl;
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return false;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address / Address not supported" << std::endl;
        return false;
    }

    cout << "Trying to connect on port " << PORT << endl;

    if (connect(client_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed" << std::endl;
        return false;
    }

    send(client_socket, &size, sizeof(size), 0);

    char buffer[1024] = { 0 };
    while (!file.eof()) {
        {
            lock_guard<mutex> lock(to);
            file.read(buffer, sizeof(buffer));
        }
        send(client_socket, buffer, file.gcount(), 0);
    }

    close(client_socket);
    file.close();
    cout << filename << " sent to server" << endl;
    return true;
}
