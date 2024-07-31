#include <iostream>
#include <vector>
#include <algorithm>
#include <sys/ioctl.h>
#include <unistd.h>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <stdexcept>
#include <cryptopp/cryptlib.h>
#include <openssl/ssl.h>
#include "../header-files/leave.h"
#include "../header-files/linux_conio.h"
#include "../header-files/encry.h"
#include "../header-files/getch_getline.h"

#define s_path_getch "server-keys"
#define sk_path_getch "server-recieved-client-keys"
#define active_path "txt-files/usersActive.txt"

using namespace std;
using namespace chrono;
using namespace filesystem;
using namespace boost;

vector<string> message;
vector<char> modeP;

char sC_M = '\0';

using boost::asio::ip::tcp;

// void readUsersActiveFile(const string usersActivePath, std::atomic<bool>& running, unsigned int update_secs) {
//     if (usersActivePath != "NONE") {
//         const auto wait_duration = chrono::seconds(update_secs);
//         ifstream openFile(usersActivePath);
//         string active;
//         while (true) {
//             try {
//                 if (openFile.is_open()) {
//                     getline(openFile, active);
//                 }
//                 if (active == "2!") {
//                     running = false;
//                 }
//                 this_thread::sleep_for(wait_duration);
//             }
//             catch (const exception& e) {
//                 running = false;
//             }
//         }
//     }
// }

std::string ca_cert_content;

std::string read_file(const std::string &filename)
{

    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file)
    {
        throw std::runtime_error("Unable to open file: " + filename);
    }
    std::ifstream::pos_type file_size = file.tellg();
    std::string file_content(file_size, '\0');
    file.seekg(0, std::ios::beg);
    file.read(&file_content[0], file_size);
    return file_content;
};

void isPortOpen(const std::string &address, int port, std::atomic<bool> &running, unsigned int update_secs)
{
    if (address != "-1" && port != 0)
    {
        std::string pingMsg = "PING";
        const auto wait_duration = chrono::seconds(update_secs);
        while (true)
        {
            try
            {

                asio::io_context io_context;
                asio::ssl::context ssl_context(asio::ssl::context::tls_client);

                ssl_context.add_certificate_authority(asio::buffer(ca_cert_content));

                asio::ssl::stream<asio::ip::tcp::socket> ssl_stream(io_context, ssl_context);

                asio::ip::tcp::resolver resolver(io_context);
                asio::ip::tcp::resolver::query query(address, std::to_string(port));
                asio::ip::tcp::resolver::iterator endpoints = resolver.resolve(query);

                asio::connect(ssl_stream.lowest_layer(), endpoints);
                ssl_stream.handshake(asio::ssl::stream_base::client);

                ssl_stream.shutdown();
                ssl_stream.lowest_layer().close();
                this_thread::sleep_for(wait_duration);
            }

            catch (const std::exception &e)
            {
                running = false;
                cout << eraseLine;
                cout << "Server has been shutdown" << endl;
                leave();
                exit(1);
            }
        }
    }
}

short int getTermSizeCols()
{
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    return w.ws_col;
}

void signalhandleGetch(int signum)
{ // for forceful leaving like using ctrl-c
    disable_conio_mode();
    cout << eraseLine;
    if (sC_M == SERVER_S)
    {
        cout << "Server has been shutdown" << endl;
        leave(s_path_getch, sk_path_getch);
        leaveFile(active_path);
        exit(signum);
    }
    else if (sC_M == CLIENT_S)
    {
        cout << "You have left the chat.\n";
        leave();
        leaveFile(active_path);
        exit(signum);
    }
}

bool findIn(const char &find, const string &In)
{
    for (int i = 0; i < In.length(); i++)
    {
        if (In[i] == find)
        {
            return true;
        }
    }
    return false;
}

int readActiveUsers(const string &filepath)
{
    string active;
    int activeInt;

    ifstream opent(filepath);
    getline(opent, active);
    istringstream(active) >> activeInt;
    return activeInt;
}

string getinput_getch(char sC, char &&MODE, const std::string certPath, const string &&unallowed, const int &&maxLimit, const string &serverIp, int PORT)
{ // N==normal//P==Password
    // causing closing ssl connections when pinging?
    ca_cert_content = certPath;
    sC_M = sC;
    setup_signal_interceptor();
    enable_conio_mode();
    int cursor_pos = 0;
    short int cols_out = getTermSizeCols();

    // std::atomic<bool> running{true};
    // const unsigned int update_interval = 2; // update every 2 seconds
    // std::thread pingingServer(isPortOpen, serverIp, PORT, std::ref(running), update_interval);
    // pingingServer.detach();

    while (true)
    {
        // if (running == false)
        // {
        //     disable_conio_mode();
        //     modeP.clear();
        //     message.clear();
        //     message.push_back("\u2702");
        //     break;
        // }
        // run a funciton here so its better and faster ig
        // detect if users active.txt is equal to "2!"
        //  else if (runningFile == false) {
        //      Recieve recievePub;
        //      LoadKey loadp;
        //      char name[4096] = { 0 };
        //      ssize_t bt = recv(clientSocket, name, sizeof(name), 0);
        //      name[bt] = '\0';
        //      string pub(name);
        //      const string keyPath = "keys-from-server/";

        //     int indexInt = pub.find_first_of("/") + 1;
        //     pub = pub.substr(indexInt);
        //     pub = pub.insert(0, formatPath, 0, keyPath.length());
        //     int firstPipe = pub.find_last_of("/");
        //     int secondPipe = pub.find_last_of("-");
        //     string pubUser = pub.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);
        //     // nameRecv += pubUser;

        //     cout << fmt::format("Recieving {}'s public key", pubUser) << endl;
        //     // recvServer(pub);
        //     string ec = recievePub.receiveBase64Data(clientSocket);
        //     vector<uint8_t> dc = recievePub.base64Decode(ec);
        //     recievePub.saveFile(pub, dc);

        //     if (is_regular_file(pub)) {
        //         cout << fmt::format("Recieved {}'s pub key", pubUser) << endl;
        //     }
        //     else {
        //         cout << "Public key file does not exist. Exiting.." << endl;
        //         close(clientSocket);
        //         leave();
        //     }

        //     cout << fmt::format("Attempting to load {}'s public key", pubUser) << endl;

        //     RSA::PublicKey receivedPublicKey2;

        //     if (loadp.loadPub(pub, receivedPublicKey2) == true) {
        //         cout << fmt::format("{}'s public key loaded", pubUser) << endl;
        //     }
        //     else {
        //         cout << fmt::format("Could not load {}'s public key", pubUser) << endl;
        //         close(clientSocket);
        //         leave();
        //     }
        // }
        // do not break at the end
        // run it only once till it changes again to "1!"
        signal(SIGINT, signalhandleGetch);
        short int cols = getTermSizeCols();
        if (message.size() < cols)
        {
            // cout << "\x1b[C";
            cout << saveCursor;
            cout << eraseLine;
            // cout << saveCursor;
            if (MODE == 'P')
            {
                // cout << saveCursor;
                // cursor_pos++;
                for (int i : modeP)
                {
                    cout << '*';
                }
            }
            else if (MODE == 'N')
            {
                // cout << ">";
                // cout << "\x1b[C";
                // cout << saveCursor;
                // cursor_pos++;
                for (string i : message)
                {
                    cout << i;
                }
            }
            // cout << "\x1b[C";
            // cout << saveCursor;

            cout << restoreCursor;
        }
        else if (message.size() + 1 == cols)
        {
        }
        cout << boldMode;
        if (_kbhit())
        { // do other keys ignore like page up and stuff
            char c = _getch();
            if (c == '\n')
            { // break on enter
                break;
            }
            else if (c == '\033')
            { // page and stuff keys
                continue;
                char next1 = _getch();
                char next2 = _getch();
                if (next1 == '[')
                {
                    if (next2 == '6')
                    {                          // page down
                        char next3 = _getch(); // discard the tilde character
                        if (next3 == '~')
                        {
                            continue;
                        }
                    }
                }
            }

            else if (int(c) == 65)
            { // up
                continue;
            }
            else if (int(c) == 66)
            { // down
                continue;
            }
            else if (int(c) == 67)
            { // right
                if (cursor_pos != message.size())
                {
                    cout << "\x1b[C";
                    cursor_pos++;
                    cout << saveCursor;
                }
            }
            else if (int(c) == 68)
            { // left
                if (cursor_pos > 0)
                {
                    cout << "\x1b[D";
                    cursor_pos--;
                    cout << saveCursor;
                }
            }
            else if (int(c) == 70)
            { // end
                continue;
            }
            else if (int(c) == 126)
            { // page down
                continue;
            }
            else if (int(c) == 127)
            { // backspace
                if (cursor_pos < message.size())
                {
                    if (cursor_pos < 1)
                    {
                        if (message.size() + 1 != cols_out)
                        {
                            cout << saveCursor;
                            cout << eraseLine;
                            for (string i : message)
                            {
                                cout << i;
                            }
                            cout << restoreCursor;
                            continue;
                        }
                    }
                    else
                    {
                        cout << saveCursor;
                        if (message.size() + 1 == cols_out)
                        {
                            // exit(1);
                            cout << eraseLine;
                            for (string i : message)
                            {
                                cout << i;
                            }
                            cout << restoreCursor;
                        }
                        else
                        {
                            cout << restoreCursor;
                            cout << "\b \b";
                            message.erase(message.begin() + cursor_pos - 1);
                            modeP.erase(modeP.begin() + cursor_pos - 1);
                            modeP.shrink_to_fit();
                            message.shrink_to_fit();
                            cursor_pos--;
                        }
                    }
                }
                else if (cursor_pos == message.size())
                {
                    if (cursor_pos == 0)
                    {
                        continue;
                    }
                    else
                    {
                        cout << "\b \b";
                        message.pop_back();
                        message.shrink_to_fit();
                        modeP.pop_back();
                        modeP.shrink_to_fit();
                        cursor_pos--;
                    }
                }
            }
            else
            {
                if (unallowed == " MYGETCHDEFAULT'|/")
                {
                    cout << "\x1b[C";
                    if (c != '[')
                    {
                        if (message.size() < maxLimit)
                        {
                            if (MODE == MODE_P)
                            {
                                string s(1, c);
                                // c = '*';
                                message.insert(message.begin() + cursor_pos, s);
                                modeP.insert(modeP.begin() + cursor_pos, c);
                                // cout << c;
                                cout << "*";
                                cursor_pos++;
                            }
                            else if (MODE == MODE_N)
                            {
                                string s(1, c);
                                message.insert(message.begin() + cursor_pos, s);
                                cout << c;
                                cursor_pos++;
                            }
                        }
                    }
                }
                else if (unallowed != " MYGETCHDEFAULT'|/")
                {
                    string notAllowed = "";

                    if (unallowed.length() != 0)
                    {
                        for (int i = 0; i < unallowed.length(); i += 2)
                        {
                            notAllowed += unallowed[i];
                            // continue;
                        }
                    }
                    if (findIn(c, notAllowed) == true)
                    {
                        continue;
                    }
                    else if (findIn(c, notAllowed) == false)
                    {
                        // cout << "\x1b[C";
                        if (c != '[')
                        {
                            if (message.size() < maxLimit)
                            {
                                if (MODE == MODE_P)
                                {
                                    string s(1, c);
                                    message.insert(message.begin() + cursor_pos, s);
                                    modeP.insert(modeP.begin() + cursor_pos, c);
                                    // cout << c;
                                    cout << "*";
                                    cursor_pos++;
                                }
                                else if (MODE == MODE_N)
                                {
                                    string s(1, c);
                                    message.insert(message.begin() + cursor_pos, s);
                                    cout << c;
                                    cursor_pos++;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // running = false;
    disable_conio_mode();

    string message_str;

    for (string i : message)
    {
        cout << boldMode;
        message_str += i;
    }

    cout << boldModeReset;
    message.clear();
    modeP.clear();
    // unallowed.clear();
    // cout << endl;

    return message_str;
}