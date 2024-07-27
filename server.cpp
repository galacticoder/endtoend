// https://github.com/galacticoder
#include <iostream>
#include <vector>
#include <thread>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <fstream>
#include <cstring>
#include <mutex>
#include <fmt/core.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <sstream>
#include <boost/asio.hpp>
#include <ctime>
#include <chrono>
#include <regex>
#include <stdlib.h>
#include <unistd.h>
#include <filesystem>
#include <ncurses.h>
#include <map>
#include <atomic>
#include "headers/header-files/serverMenuAndEncryption.h"

// add certain length of username allow only

// To run: g++ -std=c++20 -o server server.cpp -lcryptopp -lfmt //haha so old

using boost::asio::ip::tcp;

using namespace std;
using namespace CryptoPP;
using namespace std::chrono;
using namespace filesystem;

long pingCount = 0;

vector<int> connectedClients;
vector<int> uids;
vector<string> clientUsernames;
mutex clientsMutex;
vector<int> clientHashVerifiedClients;

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

    if (bind(pavtempsock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
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

void signalHandleServer(int signum)
{
    cout << eraseLine;
    for (auto &sockets : connectedClients)
    {
        close(sockets);
    }
    cout << "Server has been shutdown" << endl;
    if (remove("server-recieved-client-keys") == 1)
    {
        cout << "Deleted directory 'server-recieved-client-keys'" << endl;
    }
    if (remove("Server-Keys") == 1)
    {
        cout << "Deleted directory 'Server-Keys'" << endl;
    }
    exit(signum);
}

static bool createDir(const string &dirName)
{
    if (!create_directories(dirName))
    {
        if (exists(dirName))
        {
            return true;
        }
        cout << fmt::format("Couldnt make directory: {}", dirName) << endl;
        return false;
    }
    return true;
}

void broadcastMessage(const string &message, int senderSocket = -1)
{
    lock_guard<mutex> lock(clientsMutex);
    for (int clientSocket : connectedClients)
    {
        if (clientSocket != senderSocket)
        {
            send(clientSocket, message.c_str(), message.length(), 0);
        }
    }
}

string countUsernames(string &clientsNamesStr)
{ // make the func erase the previous string and make it empty to add all users
    clientsNamesStr.clear();
    if (clientsNamesStr.empty())
    {
        for (int i = 0; i < clientUsernames.size(); ++i)
        {
            if (clientUsernames.size() >= 2)
            {
                // for the last index dont print a comma
                clientsNamesStr.append(clientUsernames[i] + ","); // find the userbname and the before start pos and after end pos should be a comma
            }
            else
            {
                clientsNamesStr.append(clientUsernames[i]);
            }
        }
    }
    if (clientUsernames.size() >= 2)
    {
        clientsNamesStr.pop_back(); // to pop extra comma in the end
    }

    return clientsNamesStr;
}

void updateActiveFile(auto data, const string &userPath)
{
    ifstream read(userPath);
    string active;
    int activeInt;

    ofstream write(userPath);

    if (write.is_open())
    {
        write << data;
        cout << "updated usersActive.txt file: " << data << endl;
    }
    //     getline(read, active);
    //     istringstream(active) >> activeInt;
    //     if (activeInt == 2) {
    //         read.close();
    //         ofstream writeNew(userPath);
    //         writeNew << "1!";
    //         cout << "updated usersActive.txt file: " << "1!";
    //         writeNew.close();
    //     }
    //     else if (active == "1!") {
    //         read.close();
    //         ofstream writeNew2(userPath);
    //         writeNew2 << "2!";
    //         cout << "updated usersActive.txt file: " << "2!";
    //         writeNew2.close();
    //     }
    //     else if (active == "2!") {
    //         read.close();
    //         ofstream writeNew3(userPath);
    //         writeNew3 << "1!";
    //         cout << "updated usersActive.txt file: " << "1!";
    //         writeNew3.close();
    //     }
    //     else if (activeInt == 1) {
    //         read.close();
    //         ofstream writeNew4(userPath);
    //         writeNew4 << 2;
    //         cout << "updated usersActive.txt file: " << 2;
    //         writeNew4.close();
    //     }
    // }
    else
    {
        cout << "Could not open usersActive.txt file to update" << endl;
    }
    // }
}

void handleClient(int clientSocket, int serverSocket, unordered_map<int, string> serverHash, int pnInt, const string serverKeysPath, const string serverPrvKeyPath, const string serverPubKeyPath, const string serverPath, const string userPath)
{
    // end = * == user attempted to join the chat past the limit allowed
    // end = @ == user attempted to join the chat with an already existing username in the chat
    char pingbuf[200] = {0};
    ssize_t pingb = recv(clientSocket, pingbuf, sizeof(pingbuf) - 1, 0);
    pingbuf[pingb] = '\0';
    std::string pingStr(pingbuf);

    if (pingStr == "C")
    {
        try
        {

            cout << "RUNNING HANDLE CLIENT" << endl;
            // send the servers public key
            Send sendServerPubKey;
            vector<uint8_t> serverPubKeyBuff = sendServerPubKey.readFile(serverPubKeyPath);
            string encodedDataPub = sendServerPubKey.b64EF(serverPubKeyBuff);
            sendServerPubKey.sendBase64Data(clientSocket, encodedDataPub);
            cout << "Server pub key sent to client" << endl;
            //-------------
            {
                lock_guard<mutex> lock(clientsMutex);
                connectedClients.push_back(clientSocket);
            }

            for (size_t i = 0; i < connectedClients.size(); ++i)
            {
                std::cout << fmt::format("Client {}: ", i + 1) << connectedClients[i] << std::endl;
            }
            uint8_t limOfUsers = 2;

            const string limReached = "The limit of users has been reached for this chat. Exiting..*";

            if (clientUsernames.size() == limOfUsers)
            {
                send(clientSocket, limReached.c_str(), limReached.length(), 0);
                cout << "client username size: " << clientUsernames.size() << endl;
                cout << fmt::format("client attempted to join past the required limit of users({})", limOfUsers) << endl;
                auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
                connectedClients.erase(it, connectedClients.end());
                cout << "removed client socket of user that attempted to join past limit from vector" << endl;
                cout << "connectedClients vector size: " << connectedClients.size() << endl;

                close(clientSocket);
            }

            int clientHashi = 0;
            string pnS = "1";
            string pnO = "2";
            const string passwordGet = "This server is password protected. Enter the password to join: ";
            const string notVerified = "Wrong password. You have been kicked.#N";
            const string verified = "You have joined the server#V";
            string passGetArg = "";

            unordered_map<int, string> clientHash;

            auto itCl = find(connectedClients.begin(), connectedClients.end(), clientSocket); // find clientSocket index
            int indexClientOut = itCl - connectedClients.begin();
            cout << "IndexClientOut: " << indexClientOut << endl;

            if (clientHashVerifiedClients.size() != 3)
            {
                clientHashVerifiedClients.push_back(0);
            }
            cout << "inserted" << endl;
            cout << "size of clientHashVerifiedClients: " << clientHashVerifiedClients.size() << endl;
            for (size_t i = 0; i < clientHashVerifiedClients.size(); ++i)
            {
                std::cout << fmt::format("CLIENT {} HASH: ", i + 1) << clientHashVerifiedClients[i] << std::endl;
            }

            cout << "OUPUYT: " << clientHashVerifiedClients[indexClientOut] << endl;
            cout << "id up: " << indexClientOut - 1 << endl;

            if (clientHashVerifiedClients.size() < 3)
            {
                if (pnInt == 1 && clientHashVerifiedClients[indexClientOut] != 1)
                {
                    cout << "size of clients hash: " << clientHashVerifiedClients.size() << endl;
                    for (size_t i = 0; i < clientHashVerifiedClients.size(); ++i)
                    {
                        std::cout << fmt::format("CLIENT {} HASH: ", i + 1) << clientHashVerifiedClients[i] << std::endl;
                    }
                    cout << "sending pass verify signal" << endl;
                    sleep(1);
                    send(clientSocket, pnS.c_str(), pnS.length(), 0);

                    Recieve passGetRecv;
                    string passGet = passGetRecv.receiveBase64Data(clientSocket);

                    cout << "Pass cipher recieved from client: " << passGet << endl;

                    LoadKey loadServerKey;
                    RSA::PrivateKey serverPrivate;

                    cout << "Loading server private key" << endl;

                    if (loadServerKey.loadPrv(serverPrvKeyPath, serverPrivate))
                    {
                        cout << "Loaded server private key for decryption of passGet" << endl;
                    }
                    else
                    {
                        cout << "Could not load server private key for decryption. Killing server." << endl;
                        close(serverSocket);
                        leave(serverKeysPath, serverPath);
                    }

                    DecServer decPassGet;
                    string decodedPassGet = decPassGet.Base64Decode(passGet);
                    cout << "Decoded passGet" << endl;
                    passGet = decPassGet.dec(serverPrivate, decodedPassGet);
                    cout << "Decrypted passGet" << endl;

                    passGetArg += passGet;

                    cout << "userp: " << bcrypt::generateHash(passGet) << endl;
                    cout << "serverp: " << serverHash[1] << endl;
                    if (bcrypt::validatePassword(passGet, serverHash[1]) == 1)
                    { // bcrypt::validatePassword(passGet, serverHash[1]) == 1
                        send(clientSocket, verified.c_str(), verified.length(), 0);
                        clientHashVerifiedClients[indexClientOut] = 1;
                        cout << "updatyed: " << clientHashVerifiedClients[indexClientOut] << endl;
                        cout << "size of clients hash: " << clientHashVerifiedClients.size() << endl;
                        cout << "user verified" << endl;
                    }
                    else
                    {
                        send(clientSocket, notVerified.c_str(), notVerified.length(), 0);
                        sleep(1);
                        close(clientSocket);
                        auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
                        connectedClients.erase(it, connectedClients.end());
                        cout << "user not verified. kicked." << endl;
                    }
                }
                else if (pnInt == 2 && clientHashVerifiedClients[indexClientOut] != 1)
                {
                    send(clientSocket, pnO.c_str(), pnO.length(), 0);
                }
            }
            string clientsNamesStr = "";

            char buffer[4096] = {0};
            ssize_t bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            buffer[bytesReceived] = '\0';
            std::string userStr(buffer);

            if (clientHashVerifiedClients.size() < 3)
            {
                if (bcrypt::validatePassword(passGetArg, serverHash[1]) != 1 && pnInt != 2)
                {
                    send(clientSocket, notVerified.c_str(), notVerified.length(), 0);
                    sleep(1); // so they recieve it before closing their socket
                    close(clientSocket);
                    userStr.clear();
                    clientHashVerifiedClients.erase(clientHashVerifiedClients.begin() + indexClientOut);
                    auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
                    connectedClients.erase(it, connectedClients.end());
                    cout << "disconnected not verified user" << endl;
                }
            }

            int index = userStr.find("|");
            string pubkeyseri = userStr.substr(index + 1);
            userStr = userStr.substr(0, index);

            if (clientUsernames.size() > 0 && clientUsernames.size() != limOfUsers)
            {
                const string exists = "Username already exists. You are have been kicked.@"; // detects if username already exists
                for (uint8_t i = 0; i < clientUsernames.size(); i++)
                {
                    if (clientUsernames[i] == userStr)
                    {
                        cout << "client with the same username detected. kicking.." << endl;
                        send(clientSocket, exists.c_str(), exists.length(), 0);

                        auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
                        connectedClients.erase(it, connectedClients.end());
                        cout << "removed client with the same username socket from vector" << endl;
                        cout << "connectedClients vector size: " << connectedClients.size() << endl;

                        close(clientSocket);
                        userStr.clear();
                    }
                }
            }
            if (userStr.find(' '))
            {
                for (int i = 0; i < userStr.length(); i++)
                {
                    if (userStr[i] == ' ')
                    {
                        userStr[i] = '_';
                    } // also check for slashes
                }
                send(clientSocket, userStr.c_str(), userStr.length(), 0);
            }

            if (userStr.empty())
            {
                close(clientSocket);
                cout << "Closed client username empty" << endl;
            }

            else
            {
                clientUsernames.push_back(userStr);
                cout << "username added to client vector usernames" << endl;
                updateActiveFile(clientUsernames.size(), userPath);
                cout << "client SIZE: " << clientUsernames.size() << endl;

                Send usersactive;
                std::vector<uint8_t> activeBuf = usersactive.readFile(userPath); // file path is a string to the file path
                std::string ed = usersactive.b64EF(activeBuf);
                usersactive.sendBase64Data(clientSocket, ed);

                std::string joinMsg = fmt::format("{} has joined the chat", userStr);
                string lenOfUser;
                std::string userJoinMsg = fmt::format("You have joined the chat as {}\n", userStr); // limit of string?????

                const string only = "\nYou are the only user in this chat you cannot send messages until another user joins";

                string pub = fmt::format("keys-server/{}-pubkeyserver.der", userStr);

                Recieve pubrecvserver;

                static string serverRecv;

                if (clientUsernames.size() == 1)
                {
                    serverRecv = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", userStr);
                }
                else if (clientUsernames.size() > 1)
                {
                    serverRecv = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[1]);
                }
                std::string encodedData = pubrecvserver.receiveBase64Data(clientSocket);
                std::vector<uint8_t> decodedData = pubrecvserver.base64Decode(encodedData);
                pubrecvserver.saveFile(serverRecv, decodedData);

                static const string messagetouseraboutpub = "Public key that you sent to server cannot be loaded on server";
                if (is_regular_file(serverRecv))
                {
                    cout << "public key exists" << endl;
                    LoadKey loadpub;
                    if (!loadpub.loadPub(serverRecv))
                    {
                        cout << "CANNOT LOAD USER PUB KEY. KICKING" << endl;
                        send(clientSocket, messagetouseraboutpub.data(), messagetouseraboutpub.length(), 0);
                        close(clientSocket);
                    } // test load the key
                }
                else
                {
                    cout << "PUBLIC KEY FILE DOES NOT EXIST" << endl;
                    send(clientSocket, messagetouseraboutpub.data(), messagetouseraboutpub.length(), 0);
                    close(clientSocket);
                }

                cout << "recv" << endl;
                cout << "Encoded key: " << encodedData << endl;

                // file paths
                string sendToClient2 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[0]); // this path is to send the pub key of client 1 to the client that connects
                string clientSavePathAs = fmt::format("keys-from-server/{}-pubkeyfromserver.der", clientUsernames[0]);

                Send sendtoclient;

                const string con = fmt::format("\nUsers connected: {}\n", clientUsernames.size());
                if (clientUsernames.size() == 2)
                {
                    std::cout << fmt::format("sending {} from user {} to user {}", sendToClient2, clientUsernames[0], userStr) << endl;
                    // send the file path to save as on client side
                    send(clientSocket, clientSavePathAs.data(), clientSavePathAs.length(), 0);
                    cout << "sleeping 1 sec" << endl;
                    std::vector<uint8_t> fi = sendtoclient.readFile(sendToClient2); // file path is a string to the file path
                    std::string encodedData = sendtoclient.b64EF(fi);
                    sendtoclient.sendBase64Data(clientSocket, encodedData); // send encoded key
                }
                else if (clientUsernames.size() == 1)
                {
                    cout << "1 client connected. Waiting for another client to connect to continue" << endl;
                    while (true)
                    {
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        if (clientUsernames.size() > 1)
                        {
                            cout << "Another user connected, proceeding..." << endl;
                            break;
                        }
                    }

                    if (clientUsernames.size() == 2)
                    {
                        string client1toSavePathAs = fmt::format("keys-from-server/{}-pubkeyfromserver.der", clientUsernames[1]);
                        cout << fmt::format("sending to user 1: {}", client1toSavePathAs) << endl;
                        send(clientSocket, client1toSavePathAs.data(), client1toSavePathAs.length(), 0);
                    }
                    cout << "SENDING TO CLIENT 1" << endl;
                    sleep(1);
                    string sendToClient1 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[1]);
                    std::vector<uint8_t> fi2 = sendtoclient.readFile(sendToClient1); // file path is a string to the file path //error when reading the file
                    std::string encodedDataClient = sendtoclient.b64EF(fi2);
                    sendtoclient.sendBase64Data(clientSocket, encodedDataClient); // send encoded key
                    cout << "file to CLIENT 1 SENT" << endl;
                }
                std::cout << "for join" << endl;
                for (int i = 0; i < clientUsernames.size(); i++)
                {
                    if (clientUsernames[i] == userStr)
                    {
                        std::cout << "i: " << clientUsernames[i] << endl;
                        lenOfUser.append(clientUsernames[i]);
                    }
                }
                std::cout << "LENGTH OF USER: " << lenOfUser.length() << endl;
                std::cout << "LENGTH OF USERSTR: " << userStr.length() << endl;
                std::cout << "------------" << endl;

                clientsNamesStr = countUsernames(clientsNamesStr);

                std::cout << "Connected clients: ("; // (sopsijs,SOMEONE,ssjss,)
                std::cout << clientsNamesStr;
                std::cout << ")" << endl;

                std::cout << "Client Username vector size: " << clientUsernames.size() << endl;
                std::cout << "------------" << endl;

                bool isConnected = true;

                while (isConnected)
                {
                    bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
                    if (bytesReceived <= 0 || strcmp(buffer, "quit") == 0)
                    { // the quit word is useless because the quit message doesnt get sent to the user
                        isConnected = false;
                        {
                            std::lock_guard<std::mutex> lock(clientsMutex);
                            std::cout << fmt::format("User client socket deletion: BEFORE: {}", connectedClients.size()) << endl;
                            auto itCl = find(connectedClients.begin(), connectedClients.end(), clientSocket); // find clientSocket index
                            // int indexClientOut = itCl - connectedClients.begin();
                            clientHashVerifiedClients.erase(clientHashVerifiedClients.begin() + indexClientOut);
                            auto it = std::remove(connectedClients.begin(), connectedClients.end(), clientSocket);
                            connectedClients.erase(it, connectedClients.end());
                            std::cout << fmt::format("User client socket deleted: AFTER: {}", connectedClients.size()) << endl;
                            std::cout << "------------" << endl;
                            std::cout << fmt::format("{} has left the chat", userStr) << endl;
                        }

                        std::string exitMsg = fmt::format("{} has left the chat", userStr);
                        if (clientUsernames.size() > 1)
                        {
                            LoadKey loadkeyandsend;
                            if (clientUsernames[0] == userStr)
                            {
                                int index = 0 + 1;
                                string pathpub = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[index]);
                                string op64 = loadkeyandsend.loadPubAndEncrypt(pathpub, exitMsg);
                                cout << "UPDATED OP64: " << op64 << endl;
                                if (lenOfUser.length() == userStr.length() && lenOfUser == userStr && op64 != "err")
                                {
                                    broadcastMessage(op64, clientSocket);
                                }
                            }
                            else if (clientUsernames[1] == userStr)
                            {
                                int index2 = 1 - 1;
                                string pathpub2 = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", clientUsernames[index2]);
                                string op642 = loadkeyandsend.loadPubAndEncrypt(pathpub2, exitMsg);
                                cout << "UPDATED OP642: " << op642 << endl;
                                if (lenOfUser.length() == userStr.length() && lenOfUser == userStr && op642 != "err")
                                {
                                    // send(connectedClients[index2], op642.c_str(), op642.length(), 0);
                                    broadcastMessage(op642, clientSocket);
                                }
                            }
                        }
                        std::cout << "------------" << endl;
                        auto user = find(clientUsernames.rbegin(), clientUsernames.rend(), userStr);
                        if (user != clientUsernames.rend())
                        {
                            clientUsernames.erase((user + 1).base());
                        }
                        updateActiveFile(clientUsernames.size(), userPath);
                        std::cout << "Clients connected: (" << countUsernames(clientsNamesStr) << ")" << endl;
                        std::cout << fmt::format("Clients in chat: {} ", clientUsernames.size()) << endl;
                        cout << "Deleting user pubkey" << endl;
                        string pubfiletodel = fmt::format("server-recieved-client-keys/{}-pubkeyfromclient.der", userStr);

                        remove(pubfiletodel);
                        if (!is_regular_file(pubfiletodel))
                        { // if pub file doesnt exist
                            cout << fmt::format("client pubkey file ({}) has been deleted", pubfiletodel) << endl;
                        }
                        else if (is_regular_file(pubfiletodel))
                        {
                            cout << "client pub key file could not be deleted" << endl;
                        }

                        if (clientUsernames.size() < 1)
                        {
                            close(serverSocket);
                            delIt("server-recieved-client-keys");
                            exit(1);
                        }
                        lenOfUser.clear();
                    }

                    else
                    {
                        buffer[bytesReceived] = '\0';
                        std::string receivedData(buffer);
                        std::cout << "Received data: " << receivedData << std::endl;
                        cout << "ciphertext length on server: " << receivedData.length() << endl;
                        std::string cipherText = receivedData;

                        if (!cipherText.empty() && cipherText.length() > 30)
                        {
                            auto now = std::chrono::system_clock::now();
                            std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
                            std::tm *localTime = std::localtime(&currentTime);

                            bool isPM = localTime->tm_hour >= 12;
                            string stringFormatTime = asctime(localTime);

                            int tHour = (localTime->tm_hour > 12) ? (localTime->tm_hour - 12) : ((localTime->tm_hour == 0) ? 12 : localTime->tm_hour);

                            stringstream ss;
                            ss << tHour << ":" << (localTime->tm_min < 10 ? "0" : "") << localTime->tm_min << " " << (isPM ? "PM" : "AM");
                            string formattedTime = ss.str();

                            std::regex time_pattern(R"(\b\d{2}:\d{2}:\d{2}\b)");
                            std::smatch match;
                            if (regex_search(stringFormatTime, match, time_pattern))
                            {
                                string str = match.str(0);
                                size_t pos = stringFormatTime.find(str);
                                stringFormatTime.replace(pos, str.length(), formattedTime);
                            }
                            string formattedCipher = userStr + "|" + stringFormatTime + "|" + cipherText;
                            broadcastMessage(formattedCipher, clientSocket);
                        }
                    }
                }
            }
        }
        catch (exception &e)
        {
            cout << "Server has been killed due to error: " << e.what() << endl;
            close(serverSocket);
            leave(serverKeysPath, serverPath);
        }
    }
    else
    {
        pingCount++;
        cout << "\x1b[A";
        cout << eraseLine;
        cout << fmt::format("SERVER HAS BEEN PINGED ({})", pingCount) << endl;
    }
}

int main()
{
    const string userPath = "txt-files/usersActive.txt";
    const string path = "server-recieved-client-keys";
    const string serverKeysPath = "Server-Keys";
    signal(SIGINT, signalHandleServer);
    unordered_map<int, string> serverHash;
    initMenu startMenu;
    const string hash = startMenu.initmenu(serverHash);
    if (!hash.empty())
    {
        serverHash[1] = hash;
    }

    string pnStr;
    int pnInt;
    ifstream pn("pn.txt");
    getline(pn, pnStr);
    istringstream(pnStr) >> pnInt;

    cout << "pnInt is: " << pnInt << endl;

    unsigned short PORT = 8080;

    thread t1([&]()
              {
            if (isPav(PORT) == false) {
                cout << fmt::format("Port {} is not usable searching for port to use..", PORT) << endl;
                for (unsigned short i = 49152; i <= 65535; i++) {
                    if (isPav(i) != false) {
                        PORT = i;
                        break;
                    }
                }
            } });

    t1.join();

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (serverSocket < 0)
    {
        std::cerr << "Error opening server socket" << std::endl;
        return 1;
    }

    sockaddr_in serverAddress;
    int opt = 1;

    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        cout << "Chosen port isn't available. Killing server" << endl;
        close(serverSocket);
        exit(true);
    }

    listen(serverSocket, 5);
    std::cout << fmt::format("Server listening on port {}", PORT) << "\n";

    createDir(path);
    createDir(serverKeysPath);

    string server_priv_path = serverKeysPath + "/server-privkey.der";
    string server_pub_path = serverKeysPath + "/server-pubkey.der";

    cout << "Generating server keys.." << endl;
    makeServerKey serverKey(server_priv_path, server_pub_path);
    cout << fmt::format("Saved server keys in path '{}'", serverKeysPath) << endl;

    LoadKey loadServerKeys;
    if (loadServerKeys.loadPub(server_pub_path))
    {
        cout << "Server's public key has been loaded" << endl;
    }
    else
    {
        cout << "Cannot load server's public key. Killing server." << endl;
        close(serverSocket);
        leave(serverKeysPath, path);
    }

    RSA::PrivateKey serverPrivKey;

    if (loadServerKeys.loadPrv(server_priv_path, serverPrivKey))
    {
        cout << "Server's private key has been loaded" << endl;
    }
    else
    {
        cout << "Cannot load server's private key. Killing server." << endl;
        close(serverSocket);
        leave(serverKeysPath, path);
    }

    while (true)
    {
        sockaddr_in clientAddress;
        socklen_t clientLen = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientLen);

        thread(handleClient, clientSocket, serverSocket, serverHash, pnInt, serverKeysPath, server_priv_path, server_pub_path, path, userPath).detach();
        // thread(serverCommands).detach();
    }

    close(serverSocket);
    return 0;
}
