
# End-to-End Chat Application

This project is a secure and privacy-focused chat application developed in C++. It ensures encrypted communication between users with a focus on security.

## Features

- **End-to-End Encryption**
- **User Authentication**
- **TLS Support**
- **Multithreaded Server**
- **Client-Server Architecture**
- **Multiple options for choosing how server starts**
- **Client ip blacklisting and ratelimiting**
- **Nice chat ui for client**

## Requirements
- Docker (if not on ubuntu version 23.10 or higher)

## Setup

1. Clone the repository:
    ```bash
    git clone https://github.com/galacticoder/endtoend.git
    ```

2. Navigate to the project directory:
    ```bash
    cd endtoend
    ```

3. Build the project using Makefile:
    ```bash
    make
    ```
### If on ubuntu version 23.10 or higher then you can compile and run the server or client by:
First make sure your in the src directory and then compile using the bottom steps

Client:
```
make client
```
Server:
```
make server
```

### Docker Setup (if not on ubuntu version 23.10 or higher)

1. Build the Docker image:
    ```bash
    sudo docker build -t NAME .
    ```

2. Run the Docker image:
    ```bash
    sudo docker run --network host -it NAME /bin/bash
    ```

## Usage

- Run the server:
    ```bash
    ./server
    ```

- Run the client:
    ```bash
    ./client
    ```
## Future goals for this project
#### This project is not fully complete
I want to fix all issues i opened for this project and i want to add alot more features and make it work from one machine to be able to connect to a server on another machine because i would need to figure out how to make the client's server's reachable by the main server for client pinging

## License

This project is licensed under the Creative Commons Zero v1.0 Universal License.
