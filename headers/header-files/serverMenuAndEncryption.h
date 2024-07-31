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
#include <sys/socket.h>
#include <csignal>
#include <unistd.h>
#include <unordered_map>
#include "bcrypt.h"
// #include "rsa.h"
#include "getch_getline.h"
#include "leave.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
// #include <openssl/rsa.h>
// #include <openssl/bn.h>

#define SERVER_KEYPATH "server-keys"
#define SRCPATH "server-recieved-client-keys/"
#define userPath "txt-files/usersActive.txt"
#define clearScreen "\033[2J\r"
const unsigned int KEYSIZE = 4096;

using namespace std;

void signalHandleMenu(int signum);
void passVals(int &sock);

int serverSock;
SSL_CTX *serverCtx;

struct initMenu
{
    short int getTermSize(int *ptrCols)
    {
        signal(SIGINT, signalHandleMenu);
        struct winsize w;
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
        *ptrCols = w.ws_col;
        return w.ws_row; // lines
    }

    string hashP(const string &p, unordered_map<int, string> &hashedServerP)
    {
        signal(SIGINT, signalHandleMenu);
        hashedServerP[1] = bcrypt::generateHash(p);
        // bcrypt::validatePassword(p, hashedServerP[1]);
        return bcrypt::generateHash(p);
    }

    string generatePassword(unordered_map<int, string> &hashedServerP, int &&length = 8)
    {
        signal(SIGINT, signalHandleMenu);
        CryptoPP::AutoSeededRandomPool random;
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

    void print_menu(WINDOW *menu_win, int highlight)
    {
        signal(SIGINT, signalHandleMenu);
        int x, y, i;
        x = 2;
        y = 2;
        box(menu_win, 0, 0);
        const char *choices[] = {"Set password for server", "Generate password", "Dont set password", "Exit"};
        int n_choices = sizeof(choices) / sizeof(char *);

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

    string initmenu(unordered_map<int, string> hashServerStore)
    {
        // serverSock += serverSocket;
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

        WINDOW *menu_win = newwin(height, width, starty, startx);
        keypad(menu_win, TRUE);

        const char *choices[] = {"Set password for server", "Generate password", "Dont set password", "Exit"}; // 1==set//2==gen//3==nopass//4==exit
        int n_choices = sizeof(choices) / sizeof(char *);
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

        if (choice == 1)
        {
            cout << clearScreen;
            cout << "Enter a password: " << endl;
            password = getinput_getch(SERVER_S, MODE_P);
            if (password.length() < minLim)
            {
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
            return bcrypt::generateHash(password);
        }
        else if (choice == 2)
        {
            cout << clearScreen;
            cout << "Generating password for server..." << endl;
            password = generatePassword(hashServerStore);
            // *pn = 1;
            hashServerStore[1] = password;
            return password;
        }
        else if (choice == 3)
        {
            cout << clearScreen;
            cout << "Server is starting up without password..." << endl;
            return "";
        }
        else if (choice == 4)
        {
            exit(1);
        }
        return "";
    }
};

struct LoadKey
{
    LoadKey() = default;
    EVP_PKEY *LoadPrvOpenssl(const std::string &privateKeyFile)
    {
        BIO *bio = BIO_new_file(privateKeyFile.c_str(), "r");
        if (!bio)
        {
            std::cerr << "Error loading private pem key: ";
            ERR_print_errors_fp(stderr);
            return nullptr;
        }

        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey)
        {
            std::cerr << "Error loading private pem key: ";
            ERR_print_errors_fp(stderr);
        }

        cout << "Loaded PEM Private key file (" << privateKeyFile << ") successfuly" << endl;

        return pkey;
    }

    EVP_PKEY *LoadPubOpenssl(const std::string &publicKeyFile)
    {
        BIO *bio = BIO_new_file(publicKeyFile.c_str(), "r");
        if (!bio)
        {
            ERR_print_errors_fp(stderr);
            std::cerr << fmt::format("Error loading public key from path {}", publicKeyFile) << endl;
            return nullptr;
        }

        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey)
        {
            std::cerr << fmt::format("Error loading public key from path {}", publicKeyFile) << endl;
            ERR_print_errors_fp(stderr);
        }
        cout << "Loaded PEM Public key file (" << publicKeyFile << ") successfuly" << endl;

        return pkey;
    }
};

struct makeServerKey
{
    void extractPubKey(const std::string certFile, const std::string &pubKey)
    {
        FILE *certFileOpen = fopen(certFile.c_str(), "r");
        if (!certFileOpen)
        {
            std::cerr << "Error opening cert file: " << certFile << std::endl;
            return;
        }

        X509 *cert = PEM_read_X509(certFileOpen, nullptr, nullptr, nullptr);
        fclose(certFileOpen);
        if (!cert)
        {
            std::cerr << "Error reading certificate" << std::endl;
            return;
        }

        EVP_PKEY *pubkey = X509_get_pubkey(cert);
        if (!pubkey)
        {
            std::cerr << "Error extracting pubkey from cert" << std::endl;
            X509_free(cert);
            return;
        }

        FILE *pubkeyfile = fopen(pubKey.c_str(), "w");
        if (!pubkeyfile)
        {
            std::cerr << "Error opening pub key file: " << pubKey << std::endl;
            EVP_PKEY_free(pubkey);
            X509_free(cert);
            return;
        }

        if (PEM_write_PUBKEY(pubkeyfile, pubkey) != 1)
        {
            std::cerr << "Error writing public key to file" << std::endl;
        }

        fclose(pubkeyfile);
        EVP_PKEY_free(pubkey);
        X509_free(cert);
        ERR_free_strings();
    }
    // change the constructor to make a selfsigned cert
    makeServerKey(const std::string &keyfile, const std::string &certFile, const std::string &pubKey)
    {
        EVP_PKEY *pkey = nullptr;
        X509 *x509 = nullptr;
        EVP_PKEY_CTX *pctx = nullptr;
        BIO *bio = nullptr;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!pctx)
        {
            ERR_print_errors_fp(stderr);
            return;
        }

        if (EVP_PKEY_keygen_init(pctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, KEYSIZE) <= 0 ||
            EVP_PKEY_keygen(pctx, &pkey) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(pctx);
            return;
        }
        EVP_PKEY_CTX_free(pctx);

        x509 = X509_new();
        if (!x509)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_free(pkey);
            return;
        }

        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1year
        X509_set_pubkey(x509, pkey);

        X509_NAME *name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"organization", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"common name", -1, -1, 0);

        X509_set_issuer_name(x509, name);
        if (X509_sign(x509, pkey, EVP_sha3_512()) == 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_free(pkey);
            X509_free(x509);
            return;
        }

        bio = BIO_new_file(keyfile.c_str(), "w");
        if (!bio)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_free(pkey);
            X509_free(x509);
            return;
        }
        if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1)
        {
            ERR_print_errors_fp(stderr);
        }
        BIO_free_all(bio);

        bio = BIO_new_file(certFile.c_str(), "w");
        if (!bio)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_free(pkey);
            X509_free(x509);
            return;
        }
        if (PEM_write_bio_X509(bio, x509) != 1)
        {
            ERR_print_errors_fp(stderr);
        }
        BIO_free_all(bio);

        EVP_PKEY_free(pkey);
        X509_free(x509);
        extractPubKey(certFile, pubKey);
    }
    // makeServerKey(const std::string &privateKeyFile, const std::string &publicKeyFile, int bits = KEYSIZE)
    // {
    //     EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    //     if (!ctx)
    //     {
    //         ERR_print_errors_fp(stderr);
    //         exit(EXIT_FAILURE);
    //     }

    //     if (EVP_PKEY_keygen_init(ctx) <= 0)
    //     {
    //         ERR_print_errors_fp(stderr);
    //         EVP_PKEY_CTX_free(ctx);
    //         exit(EXIT_FAILURE);
    //     }

    //     if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
    //     {
    //         ERR_print_errors_fp(stderr);
    //         EVP_PKEY_CTX_free(ctx);
    //         exit(EXIT_FAILURE);
    //     }

    //     EVP_PKEY *pkey = NULL;
    //     if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    //     {
    //         ERR_print_errors_fp(stderr);
    //         EVP_PKEY_CTX_free(ctx);
    //         exit(EXIT_FAILURE);
    //     }

    //     EVP_PKEY_CTX_free(ctx);

    //     BIO *privateKeyBio = BIO_new_file(privateKeyFile.c_str(), "w+");
    //     PEM_write_bio_PrivateKey(privateKeyBio, pkey, NULL, NULL, 0, NULL, NULL);
    //     BIO_free_all(privateKeyBio);

    //     BIO *publicKeyBio = BIO_new_file(publicKeyFile.c_str(), "w+");
    //     PEM_write_bio_PUBKEY(publicKeyBio, pkey);
    //     BIO_free_all(publicKeyBio);

    //     EVP_PKEY_free(pkey);
    // }
};

struct initOpenSSL
{
    initOpenSSL() = default;
    void InitOpenssl()
    {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
    }

    // creating context
    SSL_CTX *createCtx()
    {
        const SSL_METHOD *method = SSLv23_server_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        if (!ctx)
        {
            ERR_print_errors_fp(stderr);
            raise(SIGINT);
        }
        return ctx;
    }
    // config context
    void configCtx(SSL_CTX *ctx, string &certPath, string &PrvKey)
    {
        const char *cpath = certPath.c_str();
        const char *pkey = PrvKey.c_str();
        std::cout << fmt::format("Private key path passed: {}", pkey) << std::endl;
        std::cout << fmt::format("Cert path passed: {}", cpath) << std::endl;
        if (SSL_CTX_use_certificate_file(ctx, cpath, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            std::cout << "Could not find cert file at path: " << cpath << std::endl;
            // cout << "\n1\n"
            //      << endl;
            // exit(1);
            raise(SIGINT);
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, pkey, SSL_FILETYPE_PEM) <= 0)
        {
            {
                ERR_print_errors_fp(stderr);
                // cout << "\n2\n"
                //      << endl;
                // exit(1);
                raise(SIGINT);
            }
        }
        const char *cipherList = "ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:";

        if (SSL_CTX_set_cipher_list(ctx, cipherList) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }
};
struct encServer
{
    encServer() = default;
    std::string Base64Encode(const std::string &input)
    {
        std::string encoded;
        CryptoPP::StringSource(input, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
        return encoded;
    }

    std::string hexencode(string &cipher)
    {
        string encoded;
        CryptoPP::StringSource(cipher, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(encoded)));
        cout << encoded << endl;
        return encoded;
    }

    std::string Enc(EVP_PKEY *pkey, const std::string &data)
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx)
        {
            ERR_print_errors_fp(stderr);
            return "";
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        size_t out_len;
        if (EVP_PKEY_encrypt(ctx, nullptr, &out_len, reinterpret_cast<const unsigned char *>(data.c_str()), data.size()) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        std::string out(out_len, '\0');
        if (EVP_PKEY_encrypt(ctx, reinterpret_cast<unsigned char *>(&out[0]), &out_len, reinterpret_cast<const unsigned char *>(data.c_str()), data.size()) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "err";
        }

        EVP_PKEY_CTX_free(ctx);
        out.resize(out_len);

        // out = hexencode(out);

        return out;
    }
};
struct DecServer
{
    DecServer() = default;
    string dec(EVP_PKEY *pkey, const std::string &encrypted_data)
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx)
        {
            ERR_print_errors_fp(stderr);
            return "";
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        size_t out_len;
        if (EVP_PKEY_decrypt(ctx, nullptr, &out_len, reinterpret_cast<const unsigned char *>(encrypted_data.c_str()), encrypted_data.size()) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        std::string out(out_len, '\0');
        if (EVP_PKEY_decrypt(ctx, reinterpret_cast<unsigned char *>(&out[0]), &out_len, reinterpret_cast<const unsigned char *>(encrypted_data.c_str()), encrypted_data.size()) <= 0)
        {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        EVP_PKEY_CTX_free(ctx);
        out.resize(out_len); // Adjust the size of the string
        return out;
    }
    std::string Base64Decode(const std::string &input)
    {
        std::string decoded;
        CryptoPP::StringSource(input, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }
    string hexdecode(string &encoded)
    {
        string decoded;
        CryptoPP::StringSource ssv(encoded, true /*pump all*/, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }
};
struct Send
{
    Send() = default;
    // string buffer = struct.readFile(filePath); file path is a string to the file path
    // string encodedData = struct.b64EF(string buffer);
    // struct.sendBase64Data(clientSocket, encodedData);
    std::string b64EF(string &data)
    {
        std::string encoded;
        CryptoPP::StringSource(data, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
        return encoded;
    }

    std::string readFile(const std::string &filePath)
    {
        std::ifstream file(filePath);
        if (!file.is_open())
        {
            throw std::runtime_error(fmt::format("Could not open file: {}", filePath));
        }

        string buffer;
        string line;

        while (getline(file, buffer))
        {
            buffer.push_back('\n');
        }

        file.close();
        return buffer;
    }

    void sendKey(SSL *clientSocket, const std::string pemk)
    {
        SSL_write(clientSocket, pemk.c_str(), pemk.size());
    }

    void sendBase64Data(SSL *socket, const std::string &encodedData)
    {
        ssize_t sentBytes = SSL_write(socket, encodedData.c_str(), encodedData.size());
        if (sentBytes == -1)
        {
            cout << "Error sending: " << encodedData << endl;
            throw std::runtime_error(fmt::format("Error sending data: {}", encodedData));
        }
    }

    void broadcastBase64Data(int clientSocket, const std::string &encodedData, vector<int> &connectedClients, vector<SSL *> &tlsSocks)
    {
        for (int i = 0; i < connectedClients.size(); i++)
        {
            for (int i = 0; i < connectedClients.size(); i++)
            {
                if (connectedClients[i] != clientSocket)
                {
                    SSL_write(tlsSocks[i], encodedData.c_str(), encodedData.length());
                }
            }
        }
    }
};

struct Recieve
{
    Recieve() = default;
    // std::string encodedData = receiveBase64Data(clientSocket);
    // std::vector<uint8_t> decodedData = base64Decode(encodedData);
    // saveFile(filePath, decodedData);
    std::string base64Decode(const std::string &encodedData)
    {
        std::string decoded;
        CryptoPP::StringSource(encodedData, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
        return decoded;
    }

    void saveFile(const std::string &filePath, const string &buffer)
    {
        std::ofstream file(filePath);
        if (!file.is_open())
        {
            throw std::runtime_error(fmt::format("Could not open file to write: ", filePath));
        }

        file << buffer;

        if (!file)
        {
            throw std::runtime_error("Error writing to file");
        }
    }

    void saveFilePem(const std::string &filePath, const string &buffer)
    {
        std::ofstream file(filePath, std::ios::binary);
        if (!file.is_open())
        {
            throw std::runtime_error(fmt::format("Could not open file to write: ", filePath));
        }

        file << buffer;

        if (!file)
        {
            throw std::runtime_error("Error writing to file");
        }
    }

    std::string receiveBase64Data(SSL *clientSocket)
    {
        std::string receivedData;
        std::vector<char> buffer(4096);
        ssize_t bytesRead = SSL_read(clientSocket, buffer.data(), buffer.size());

        // cout << "BT: " << bytesRead << endl;

        while (bytesRead > 0) // its gonna keep appending without a stop condition
        {
            cout << "Bytes read: " << bytesRead << endl;
            receivedData.append(buffer.data(), bytesRead);
            if (receivedData.size() == bytesRead)
            {
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

    std::string read_pem_key(const std::string &path)
    {
        std::ifstream file(path);
        if (!file.is_open())
        {
            std::cout << "Could not open pem file" << std::endl;
        }
        std::string pemKey((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        return pemKey;
    }
};

void signalHandleMenu(int signum)
{
    endwin();
    disable_conio_mode();
    cout << eraseLine;
    cout << "Server has been shutdown" << endl;
    leave(S_PATH, SERVER_KEYPATH);
    leaveFile(userPath);
    close(serverSock);
    SSL_CTX_free(serverCtx);
    EVP_cleanup();
    exit(signum);
}

void passVals(int &sock, SSL_CTX *ctxPass)
{
    serverSock += sock;
    if (serverSock == sock)
    {
        std::cout << fmt::format("Server passed val [{}] to serverMenuAndEncryption.h", sock) << std::endl;
    }
    serverCtx = ctxPass;
    if (serverCtx == ctxPass)
    {
        std::cout << "Server passed val ctx to serverMenuAndEncryption.h" << std::endl;
    }
}

#endif