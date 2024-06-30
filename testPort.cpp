#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

bool isPortAvailable(int port) {
    int sockfd;
    struct sockaddr_in addr;
    bool available = false;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error opening socket." << std::endl;
        return false;
    }

    // Set up the address structure
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    // Try to bind the socket to the specified port
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        std::cerr << "Port " << port << " is not available." << std::endl;
    } else {
        std::cout << "Port " << port << " is available." << std::endl;
        available = true;
    }

    // Close the socket
    close(sockfd);
    return available;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        return 1;
    }

    int port = std::stoi(argv[1]);
    if (port < 1 || port > 65535) {
        std::cerr << "Invalid port number. Port must be between 1 and 65535." << std::endl;
        return 1;
    }

    if (isPortAvailable(port)) {
        std::cout << "You can use port " << port << " to host your server." << std::endl;
    } else {
        std::cerr << "You cannot use port " << port << " to host your server." << std::endl;
    }

    return 0;
}
