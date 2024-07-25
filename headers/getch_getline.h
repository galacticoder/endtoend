#ifndef IGETLINE
#define IGETLINE

#include "linux_conio.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <sys/ioctl.h>
#include <unistd.h>
#include "leave.h"
#include <chrono>
#include <fstream>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <thread>
#include <chrono>
#include <atomic>

#define eraseLine "\033[2K\r"
#define boldMode "\033[1m"
#define boldModeReset "\033[22m"
#define saveCursor "\033[s"
#define restoreCursor "\033[u"
#define clearScreen "\033[2J\r"

#define MODE_P 'P'
#define MODE_N 'N'
#define CLIENT_S 'C'
#define SERVER_S 'S'
#define S_PATH "server-recieved-client-keys"

using namespace std;
using namespace chrono;

vector <string> message;
vector <char> modeP;

char sC_M = '\0';

using boost::asio::ip::tcp;

void isPortOpen(const string& address, int port, std::atomic<bool>& running, unsigned int update_secs) {
    if (address != "-1" && port != 0) {
        const auto wait_duration = chrono::seconds(update_secs);
        while (true) {
            try {
                boost::system::error_code ecCheck;
                boost::asio::ip::address::from_string(address, ecCheck);
                if (ecCheck) {
                    cout << "invalid ip address: " << address << endl;
                }
                boost::asio::io_service io_service;
                tcp::socket socket(io_service);
                tcp::endpoint endpoint(boost::asio::ip::address::from_string(address), port);
                socket.connect(endpoint);

                if (ecCheck) {
                    disable_conio_mode();
                    cout << eraseLine;
                    leave();
                }

                this_thread::sleep_for(wait_duration);
            }
            catch (const exception& e) {
                running = false;
                cout << eraseLine;
                cout << "Server has been shutdown" << endl;
                leave();
            }
        }
    }
}

short int getTermSizeCols() {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    return w.ws_col;
}

void signalhandleGetch(int signum) { //for forceful leaving like using ctrl-c
    disable_conio_mode();
    cout << eraseLine;
    if (sC_M == SERVER_S) {
        cout << "Server has been shutdown" << endl;
        delIt(S_PATH);
        exit(signum);
    }
    else if (sC_M == CLIENT_S) {
        cout << "You have left the chat.\n";
        leave();
        exit(signum);
    }
}

bool findIn(const char& find, const string& In) {
    for (int i = 0; i < In.length(); i++) {
        if (In[i] == find) {
            return true;
        }
    }
    return false;
}

int readActiveUsers(const string& filepath) {
    string active;
    int activeInt;

    ifstream opent(filepath);
    getline(opent, active);
    istringstream(active) >> activeInt;
    return activeInt;
}


string getinput_getch(char sC = CLIENT_S, char&& MODE = MODE_N, const string& serverIp = "-1", int PORT = 0, const string&& unallowed = " MYGETCHDEFAULT'|", const int&& maxLimit = getTermSizeCols()) {//N==normal//P==Password
    sC_M = sC;
    setup_signal_interceptor();
    enable_conio_mode();
    int cursor_pos = 0;
    short int cols_out = getTermSizeCols();

    std::atomic<bool> running{ true };
    const unsigned int update_interval = 2; // update after every 50 milliseconds
    std::thread pingingServer(isPortOpen, serverIp, PORT, std::ref(running), update_interval);
    pingingServer.detach();

    while (true) {
        if (running == false) {
            modeP.clear();
            message.clear();
            message.push_back("\u2702");
            break;
        }
        signal(SIGINT, signalhandleGetch);
        short int cols = getTermSizeCols();
        if (message.size() < cols) {
            cout << saveCursor;
            cout << eraseLine;
            if (MODE == 'P') {
                for (int i : modeP) {
                    cout << '*';
                }
            }
            else if (MODE == 'N') {
                for (string i : message) {
                    cout << i;
                }
            }
            cout << restoreCursor;
        }
        else if (message.size() + 1 == cols) {
        }
        cout << boldMode;
        if (_kbhit()) { //do other keys ignore like page up and stuff
            char c = _getch();
            if (c == '\n') { //break on enter
                break;
            }
            else if (c == '\033') { //page and stuff keys
                continue;
                char next1 = _getch();
                char next2 = _getch();
                if (next1 == '[') {
                    if (next2 == '6') { // page down
                        char next3 = _getch(); // discard the tilde character
                        if (next3 == '~') {
                            continue;
                        }
                    }
                }
            }

            else if (int(c) == 65) { //up
                continue;
            }
            else if (int(c) == 66) { //down
                continue;
            }
            else if (int(c) == 67) { //right
                if (cursor_pos != message.size()) {
                    cout << "\x1b[C";
                    cursor_pos++;
                    cout << saveCursor;
                }
            }
            else if (int(c) == 68) { //left
                if (cursor_pos > 0) {
                    cout << "\x1b[D";
                    cursor_pos--;
                    cout << saveCursor;
                }
            }
            else if (int(c) == 70) { //end
                continue;
            }
            else if (int(c) == 126) { //page down 
                continue;
            }
            else if (int(c) == 127) { //backspace
                if (cursor_pos < message.size()) {
                    if (cursor_pos < 1) {
                        if (message.size() + 1 != cols_out) {
                            cout << saveCursor;
                            cout << eraseLine;
                            for (string i : message) {
                                cout << i;
                            }
                            cout << restoreCursor;
                            continue;
                        }
                    }
                    else {
                        cout << saveCursor;
                        if (message.size() + 1 == cols_out) {
                            // exit(1);
                            cout << eraseLine;
                            for (string i : message) {
                                cout << i;
                            }
                            cout << restoreCursor;

                        }
                        else {
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
                else if (cursor_pos == message.size()) {
                    if (cursor_pos == 0) {
                        continue;
                    }
                    else {
                        cout << "\b \b";
                        message.pop_back();
                        message.shrink_to_fit();
                        modeP.pop_back();
                        modeP.shrink_to_fit();
                        cursor_pos--;
                    }
                }
            }
            else {
                if (unallowed == " MYGETCHDEFAULT'|/") {
                    if (c != '[') {
                        if (message.size() < maxLimit) {
                            if (MODE == MODE_P) {
                                string s(1, c);
                                // c = '*';
                                message.insert(message.begin() + cursor_pos, s);
                                modeP.insert(modeP.begin() + cursor_pos, c);
                                // cout << c;
                                cout << "*";
                                cursor_pos++;
                            }
                            else if (MODE == MODE_N) {
                                string s(1, c);
                                message.insert(message.begin() + cursor_pos, s);
                                cout << c;
                                cursor_pos++;
                            }
                        }
                    }
                }
                else if (unallowed != " MYGETCHDEFAULT'|/") {
                    string notAllowed = "";
                    for (int i = 0; i < unallowed.length(); i += 2) {
                        notAllowed += unallowed[i];
                        // continue;
                    }
                    if (findIn(c, notAllowed) == true) {
                        continue;
                    }
                    else if (findIn(c, notAllowed) == false) {
                        if (c != '[') {
                            if (message.size() < maxLimit) {
                                if (MODE == MODE_P) {
                                    string s(1, c);
                                    message.insert(message.begin() + cursor_pos, s);
                                    modeP.insert(modeP.begin() + cursor_pos, c);
                                    // cout << c;
                                    cout << "*";
                                    cursor_pos++;
                                }
                                else if (MODE == MODE_N) {
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

    running = false;
    disable_conio_mode();

    string message_str;

    for (string i : message) {
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

#endif