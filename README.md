# Encrypted Chat Server
### **This script only runs on linux and is only meant for linux.**


This project is an encrypted chat server and client application implemented in C++. The communication between the server and the clients is encrypted using AES (Advanced Encryption Standard). The project consists of the following main files:

- `server.cpp`: Implements the server that handles multiple clients and manages encrypted communication.
- `client.cpp`: Implements the client that connects to the server and communicates using encrypted messages.
- `encrypt_traffic.cpp`: Contains utility functions for encrypting and decrypting traffic. You wont use decryption function from here so feel free to remove the function if you want to.
- `encry_to_server.h`: Header file for encryption utilities.

## Requirements

- C++17 or later
- Boost Asio
- Crypto++ library
- fmt library

### Installation on linux

1. **Install required packages:**
   ### **Debian based distros:**
   ```bash
   sudo apt-get update
   sudo apt-get install libboost-all-dev libcrypto++-dev libfmt-dev g++
   ```
   ### **Redhat based distros:**
   ```bash
   sudo yum check-update
   sudo yum install boost-devel crypto++-devel fmt-devel gcc-c++
   ```
      ### **On CentOS/RHEL 8 and Fedora:**
      ```bash
      sudo dnf check-update
      sudo dnf install boost-devel crypto++-devel fmt-devel gcc-c++
      ```

3. **Clone this repo:**
   ```bash
   git clone https://github.com/galacticoder/tcp_using_sockets-in-cpp.git
   ```
4. **Build the project:**
   ```bash
   cd tcp_using_sockets-in-cpp
   g++ -o server server.cpp -lcryptopp -lfmt
   g++ -o client client.cpp encrypt_traffic.cpp -lcryptopp -lfmt
   ```
   This compiles the server and client script so you can use it.
   
## Usage:
### **Running the server:**
   ```
   ./server
   ```
The server will start and listen for incoming connections. It will search for an available port to use if the default port (8080) is not available. The chosen port will be saved to PORT.txt

### **Running client:**
   ```
   ./client
   ```
This will connect to the port where server is running automatically.

## Server and client file descriptions
* `server.cpp`: The server.cpp file implements the main functionality of the server. It handles client connections, manages encrypted communication, and broadcasts messages to all connected clients. Key functionalities include:
    - Checking port availability automatically and selects an available port.
    - Accepting client connections and creating a new thread for each client.
    - Decrypting encrypted messages sent to server from client using AES encryption.
    -Broadcasting messages to all connected clients except the sender.

* `client.cpp`: The client.cpp file implements the client-side functionality. It connects to the server, sends encrypted messages, and receives messages from the server. Key functionalities include:
    - Connecting to the server using the provided IP address and port.(Automatically connects to the port server is running on no need for config)
    - Sending encrypted messages to the server for secure messaging and removes the possibility of someone reading your plaintext message through package interception.
    - Uses AES-256 CBC encryption and pads message before encrypting to ensure the message recieved is the correct length to encrypt messages without errors.
 
If theres an issue with the code or non-compatablility issues on LINUX you can report to this repository's [issues page](https://github.com/galacticoder/tcp_using_sockets-in-cpp/issues) and i or someone else will help.

## **License**

This project is licensed under the MIT License. You are free to use, modify, and distribute this software, but you must include the original license and copyright notice in any significant portions of the software. For more information, refer to the full [MIT License](https://opensource.org/licenses/MIT).
