#ifndef SERVERMENUANDENCRYPTION
#define SERVERMENUANDENCRYPTION

#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <ncurses.h>
#include <sys/ioctl.h>
#include <csignal>
#include <unistd.h>
#include <unordered_map>
#include "bcrypt.h"
#include "rsa.h"
#include "getch_getline.h"
#include "leave.h"

#define clearScreen "\033[2J\r"
const unsigned int KEYSIZE = 4096;

using namespace CryptoPP;
using namespace std;

void signalHandleMenu(int signum);

struct initMenu {
    short int getTermSize(int* ptrCols) {
        signal(SIGINT, signalHandleMenu);
        struct winsize w;
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
        *ptrCols = w.ws_col;
        return w.ws_row; //lines
    }

    string hashP(const string& p, unordered_map<int, string>& hashedServerP)
    {
        signal(SIGINT, signalHandleMenu);
        hashedServerP[1] = bcrypt::generateHash(p);
        // bcrypt::validatePassword(p, hashedServerP[1]);
        return bcrypt::generateHash(p);
    }

    string generatePassword(unordered_map<int, string>& hashedServerP, int&& length = 8)
    {
        signal(SIGINT, signalHandleMenu);
        AutoSeededRandomPool random;
        const string charSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()_-+=<>?";

        // make thing for dont include
        string pass;
        for (ssize_t i = 0; i < length; ++i)
        {
            pass += charSet[random.GenerateByte() % charSet.size()];
        }
        cout << "Password: " << pass << endl;
        sleep(2);
        cout << eraseLine;
        cout << "\x1b[A";
        hashP(pass, hashedServerP);
        cout << "Hash: " << hashedServerP[1] << endl;
        return hashedServerP[1];
    }

    void print_menu(WINDOW* menu_win, int highlight)
    {
        signal(SIGINT, signalHandleMenu);
        int x, y, i;
        x = 2;
        y = 2;
        box(menu_win, 0, 0);
        const char* choices[] = { "Set password for server", "Generate password", "Dont set password", "Exit" };
        int n_choices = sizeof(choices) / sizeof(char*);

        for (i = 0; i < n_choices; ++i)
        {
            if (highlight == i + 1)
            {
                wattron(menu_win, A_REVERSE);
                mvwprintw(menu_win, y, x, "%s", choices[i]);
                wattroff(menu_win, A_REVERSE);
            }
            else
                mvwprintw(menu_win, y, x, "%s", choices[i]);
            ++y;
        }
        wrefresh(menu_win);
    }

    string initmenu(unordered_map<int, string> hashServerStore) {
        int minLim = 6;
        signal(SIGINT, signalHandleMenu);
        initscr();
        clear();
        noecho();
        cbreak();
        curs_set(0);
        keypad(stdscr, TRUE);

        int cols;
        int lines = getTermSize(&cols);

        int width = 50;
        int height = 18;
        int starty = lines / 2 - height / 2;
        int startx = cols / 2 - width / 2;

        WINDOW* menu_win = newwin(height, width, starty, startx);
        keypad(menu_win, TRUE);

        const char* choices[] = { "Set password for server", "Generate password", "Dont set password", "Exit" }; // 1==set//2==gen//3==nopass//4==exit
        int n_choices = sizeof(choices) / sizeof(char*);
        int highlight = 1;
        int choice = 0;
        int c;

        print_menu(menu_win, highlight);
        while (choice == 0)
        {
            c = wgetch(menu_win);
            switch (c)
            {
            case KEY_UP:
                if (highlight == 1)
                    highlight = n_choices;
                else
                    --highlight;
                break;
            case KEY_DOWN:
                if (highlight == n_choices)
                    highlight = 1;
                else
                    ++highlight;
                break;
            case 10:
                choice = highlight;
                break;
            default:
                break;
            }
            print_menu(menu_win, highlight);
            if (choice != 0)
            {
                break;
            }
        }

        // make it so you can press esc to go back to options when you click make your own password

        curs_set(1);
        clrtoeol();
        refresh();
        endwin();

        // system("cls");
        // cout << clearScreen;

        string password;

        if (choice == 1) {
            cout << clearScreen;
            cout << "Enter a password: " << endl;
            password = getinput_getch(SERVER_S, MODE_P);
            if (password.length() < minLim) {
                cout << fmt::format("\nServer password must be greater than or equal to {} characters", minLim) << endl;
                exit(1);
            }
            // storeHash[1] = hashP(password, storeHash);
            cout << endl;
            cout << eraseLine;
            cout << "\x1b[A";
            cout << eraseLine;
            cout << "\x1b[A";
            // *pn = 1;
            cout << "Password has been set for server" << endl;
            ofstream file("pn.txt");
            if (file.is_open()) {
                file << "1";
                file.close();
            }
            return bcrypt::generateHash(password);
        }
        else if (choice == 2) {
            cout << clearScreen;
            cout << "Generating password for server..." << endl;
            password = generatePassword(hashServerStore);
            // *pn = 1;
            hashServerStore[1] = password;
            ofstream file("pn.txt");
            if (file.is_open()) {
                file << "1";
                file.close();
            }
            return password;
        }
        else if (choice == 3) {
            cout << clearScreen;
            ofstream file("pn.txt");
            if (file.is_open()) {
                file << "2";
                file.close();
            }
            cout << "Server is starting up without password..." << endl;
            return "";
        }
        else if (choice == 4) {
            exit(1);
        }
        return "";
    }
};

struct makeServerKey {
    makeServerKey(const std::string privateKeyFile, const std::string publicKeyFile, unsigned int keySize = KEYSIZE) {
        AutoSeededRandomPool rng;
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, keySize);

        RSA::PublicKey publicKey(privateKey);

        {
            FileSink file(privateKeyFile.c_str());
            privateKey.DEREncode(file);
        }
        {
            FileSink file(publicKeyFile.c_str());
            publicKey.DEREncode(file);
        }

        cout << "Rsa key pair generated" << endl;
    }
};
struct encServer {
    encServer() = default;
    string Enc(RSA::PublicKey& pubkey, string& plain) {
        // try {
        AutoSeededRandomPool rng; //using diff rng for better randomness
        string cipher;
        RSAES_OAEP_SHA512_Encryptor e(pubkey); //make sure to push rsa.h or you get errors cuz its modified to sha512 instead of sha1 for better security
        StringSource ss1(plain, true, new PK_EncryptorFilter(rng, e, new StringSink(cipher))); //nested for better verification of both key loading
        return cipher;
    }

    std::string Base64Encode(const std::string& input) {
        std::string encoded;
        StringSource(input, true, new Base64Encoder(new StringSink(encoded), false));
        return encoded;
    }
};
struct DecServer {
    DecServer() = default;
    string dec(RSA::PrivateKey& prvkey, string& cipher) {
        AutoSeededRandomPool rng; //using diff rng for better randomness
        string decrypted;
        RSAES_OAEP_SHA512_Decryptor d(prvkey);//modified to decrypt sha512
        StringSource ss2(cipher, true, new PK_DecryptorFilter(rng, d, new StringSink(decrypted)));
        return decrypted;
    }
    std::string Base64Decode(const std::string& input) {
        std::string decoded;
        StringSource(input, true, new Base64Decoder(new StringSink(decoded)));
        return decoded;
    }
    string hexdecode(string& encoded) {
        string decoded;
        CryptoPP::StringSource ssv(encoded, true /*pump all*/, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }
};
struct Send {
    Send() = default;
    //std::vector<uint8_t> buffer = readFile(filePath); file path is a string to the file path
    //std::string encodedData = b64EF(buffer);
    //sendBase64Data(clientSocket, encodedData);
    std::string b64EF(const std::vector<uint8_t>& data)
    {
        std::string encoded;
        CryptoPP::StringSource ss(data.data(), data.size(), true,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(encoded),
                false // do not add line breaks
            ));
        return encoded;
    }

    std::vector<uint8_t> readFile(const std::string& filePath)
    {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open())
        {
            cout << "cannot open file " << filePath << endl;
            throw std::runtime_error("Could not open file");
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
        {
            throw std::runtime_error("Error reading file");
        }

        return buffer;
    }

    void sendBase64Data(int socket, const std::string& encodedData) {
        ssize_t sentBytes = send(socket, encodedData.c_str(), encodedData.size(), 0);
        if (sentBytes == -1)
        {
            cout << "error sending: " << encodedData << endl;
            throw std::runtime_error("Error sending data");
        }
    }
    void broadcastBase64Data(int clientSocket, const std::string& encodedData, vector <int>& connectedClients) {
        for (int clientSocket : connectedClients)
        {
            if (clientSocket != clientSocket)
            {
                send(clientSocket, encodedData.c_str(), encodedData.length(), 0);
            }
        }
    }
};

struct Recieve {
    Recieve() = default;
    //std::string encodedData = receiveBase64Data(clientSocket);
    //std::vector<uint8_t> decodedData = base64Decode(encodedData);
    //saveFile(filePath, decodedData);
    std::vector<uint8_t> base64Decode(const std::string& encodedData)
    {
        std::vector<uint8_t> decoded;
        CryptoPP::StringSource ss(encodedData, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::VectorSink(decoded)));
        return decoded;
    }

    void saveFile(const std::string& filePath, const std::vector<uint8_t>& buffer)
    {
        std::ofstream file(filePath, std::ios::binary);
        if (!file.is_open())
        {
            cout << "couldnt open " << filePath << endl;
            throw std::runtime_error("Could not open file to write");
        }

        file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        if (!file)
        {
            throw std::runtime_error("Error writing to file");
        }
    }
    std::string receiveBase64Data(int clientSocket)
    {
        std::vector<char> buffer(4096);
        std::string receivedData;
        ssize_t bytesRead = recv(clientSocket, buffer.data(), buffer.size(), 0);

        while (bytesRead > 0) //its gonna keep appending without a stop condition
        {
            cout << "Bytes read: " << bytesRead << endl;
            receivedData.append(buffer.data(), bytesRead);
            if (receivedData.size() == bytesRead) {
                break;
            }
        }
        cout << "RECIEVED DATA: " << receivedData.size() << endl;
        cout << "BYTES READ: " << bytesRead << endl;

        if (bytesRead == -1)
        {
            throw std::runtime_error("Error receiving data");
        }

        return receivedData;
    }
};

struct LoadKey {
    LoadKey() = default;
    bool loadPub(const std::string& publicKeyFile) {
        RSA::PublicKey publickey;
        try {
            ifstream fileopencheck(publicKeyFile, ios::binary);
            if (fileopencheck.is_open()) {
                FileSource file(publicKeyFile.c_str(), true); //pumpall
                publickey.BERDecode(file);
                cout << "Loaded RSA Public key file (" << publicKeyFile << ") successfuly" << endl;
            }
            else {
                cout << fmt::format("Could not open file at file path '{}'", publicKeyFile) << endl;
            }
        }
        catch (const Exception& e) {
            std::cerr << fmt::format("Error loading public rsa key from path {}: {}", publicKeyFile, e.what()) << endl;
            return false;
        }

        return true;
    }
    string loadPubAndEncrypt(const std::string& publicKeyFile, string& plaintext) {
        encServer encrypt;
        RSA::PublicKey publickey;
        try {
            ifstream fileopencheck(publicKeyFile, ios::binary);
            if (fileopencheck.is_open()) {
                FileSource file(publicKeyFile.c_str(), true);//pumpAll
                publickey.BERDecode(file);
                cout << "Loaded RSA Public key file (" << publicKeyFile << ") successfuly" << endl;
                string encrypted = encrypt.Enc(publickey, plaintext);
                return encrypt.Base64Encode(encrypted);
            }
            else {
                cout << fmt::format("Could not open public key at file path '{}'", publicKeyFile) << endl;
                return "err";
            }
        }
        catch (const Exception& e) {
            std::cerr << fmt::format("Error loading public rsa key from path {}: {}", publicKeyFile, e.what()) << endl;
            return "err";
        }

        return "success";
    }
    bool loadPrv(const std::string& privateKeyFile, RSA::PrivateKey& privateKey) {
        try {
            FileSource file(privateKeyFile.c_str(), true);
            privateKey.BERDecode(file);
            cout << "Loaded RSA Private key successfuly" << endl;
        }
        catch (const Exception& e) {
            std::cerr << "Error loading private rsa key: " << e.what() << std::endl;
            return false;
        }
        return true;
    }
};

void signalHandleMenu(int signum) {
    endwin();
    disable_conio_mode();
    cout << eraseLine;
    cout << "Server has been shutdown" << endl;
    if (remove(S_PATH) == 1) {
        cout << fmt::format("Deleted directory '{}'", S_PATH) << endl;
    }
    if (remove("Server-Keys") == 1) {
        cout << "Deleted directory 'Server-Keys'" << endl;
    }
    exit(signum);
}

#endif