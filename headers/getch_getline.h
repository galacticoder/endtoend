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

#define eraseLine "\033[2K\r"
#define boldMode "\033[1m"
#define boldModeReset "\033[22m"
#define saveCursor "\033[s"
#define restoreCursor "\033[u"

using namespace std;
using namespace chrono;

vector <char> message;


short int getTermSizeCols() {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    return w.ws_col;
}

void signalhandleGetch(int signum) { //for forceful leaving like using ctrl-c
    disable_conio_mode();
    cout << "You have left the chat.\n";
    leave();
    exit(signum);
}

string getinput_getch(const int&& limit = getTermSizeCols()) {
    setup_signal_interceptor();
    enable_conio_mode();
    int cursor_pos = 0;
    short int cols_out = getTermSizeCols();

    while (true) {
        signal(SIGINT, signalhandleGetch);
        short int cols = getTermSizeCols();
        if (message.size() < cols) {
            cout << saveCursor;
            cout << eraseLine;
            for (int i : message) {
                cout << char(i);
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
                            for (int i : message) {
                                cout << char(i);
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
                            for (int i : message) {
                                cout << char(i);
                            }
                            cout << restoreCursor;

                        }
                        else {
                            cout << restoreCursor;
                            cout << "\b \b";
                            message.erase(message.begin() + cursor_pos - 1);
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
                        cursor_pos--;
                    }
                }
            }
            else {
                if (c != '[') {
                    if (message.size() < limit) {
                        message.insert(message.begin() + cursor_pos, c);
                        cout << c;
                        cursor_pos++;
                    }
                }
            }
        }
    }

    string message_str;
    disable_conio_mode();

    for (char i : message) {
        cout << boldMode;
        message_str += i;
    }

    cout << boldModeReset;
    message.clear();

    return message_str;
}

#endif