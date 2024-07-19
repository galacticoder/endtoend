#include "linux_conio.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <sys/ioctl.h>
#include <unistd.h>

#define delLineFromCursor "\033[0K"
#define eraseLine "\033[2K\r"
#define boldMode "\033[1m"
#define boldModeReset "\033[22m"
#define saveCursor "\033[s"
#define restoreCursor "\033[u"
#define eraseFromStart "\033[1K"
#define linewrapping  "\033[7h"
#define eraseScreen  "\033[J"
// #define diffCursor "\033[q"

using namespace std;

vector <char> message;

string t_w(string strIp) {
    strIp.erase(strIp.begin(), find_if(strIp.begin(), strIp.end(), [](unsigned char ch) {
        return !isspace(ch);
        }));
    strIp.erase(find_if(strIp.rbegin(), strIp.rend(), [](unsigned char ch) {
        return !isspace(ch);
        }).base(), strIp.end());
    return strIp;
}

short int getTermSizeCols() {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

    // cout << "lines: " << w.ws_row << endl;
    // cout << "columns: " << w.ws_col << endl;
    return w.ws_col;
}

int main() {
    // cout << linewrapping;
    setup_signal_interceptor();
    enable_conio_mode();
    // string message_str;
    int cursor_pos = 0;

    // cout << "Taking input with kbhit + getch... Press Enter to stop" << endl;
    while (true) {
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
            cout << '\n' << endl;
            // cout << eraseLine;
            for (int i : message) {
                cout << char(i);
            }
            cout << restoreCursor;
            // int restoreId = message.size() - cursor_pos;

            // for (int i = 0; i <= restoreId; i++) {
            //     cout << "\x1b[D";
            // }
        }
        // cout << diffCursor;
        cout << boldMode;
        if (_kbhit()) { //do other keys ignore like page up and stuff
            char c = _getch();
            if (c == '\n') { //break on enter
                break;
            }
            // else if (c == '^') { //control keys
            //     continue;
            // }
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

            // else if (c == '1') { //shift keys
            //     continue;
            //     char next1 = _getch();
            //     char next2 = _getch();
            //     if (next1 == ';') {
            //         continue;
            //         if (next2 == '2') { // page down
            //             continue;
            //         }
            //     }
            // }

            else if (int(c) == 65) { //up
                continue;
                // printf("\033%zuC", message.size());
                // cout << fmt::format("\033{}C", message.size());
                // cout << restoreCursor;
            }
            else if (int(c) == 66) { //down
                continue;
            }
            else if (int(c) == 67) { //right
                // cout << "csize: " << cursor_pos << endl;
                // cout << "msize: " << message.size() << endl;
                if (cursor_pos != message.size()) {
                    cout << "\x1b[C";
                    cursor_pos++;
                    cout << saveCursor;
                    // cout << eraseLine;
                    // for (int i : message) {
                    //     cout << char(i);
                    //     // cout << "s: ";
                    //     // cout << message[char(i)];
                    // }
                    // cout << restoreCursor;
                }
            }
            else if (int(c) == 68) { //left
                if (cursor_pos > 0) {
                    cout << "\x1b[D";
                    cursor_pos--;
                    cout << saveCursor;
                    // cout << eraseLine;
                    // for (int i : message) {
                    //     cout << char(i);
                    //     // cout << "s: ";
                    //     // cout << message[char(i)];
                    // }
                    // cout << restoreCursor;
                }
            }
            else if (int(c) == 70) { //end
                continue;
            }
            else if (int(c) == 126) { //page down 
                continue;
            }
            else if (int(c) == 127) { //backspace
                // cout << "\x1b[C";
                if (cursor_pos < message.size()) {
                    if (cursor_pos < 1) {
                        cout << saveCursor;
                        cout << eraseLine;
                        for (int i : message) {
                            cout << char(i);
                            // cout << "s: ";
                            // cout << message[char(i)];
                        }
                        cout << restoreCursor;
                        // cursor_pos++;
                        // cout << "\x1b[C";
                        // cout << eraseFromStart;
                        continue;
                    }
                    else {
                        // cout << "\x1b[C";
                        cout << saveCursor;
                        // cout << eraseLine;
                        // // cout << restoreCursor;
                        // // cout << eraseLine;
                        // for (int i : message) {
                        //     // cout << "i: " << i << endl;
                        //     // cout << "cursor: " << cursor_pos << endl;
                        //     // if (i == cursor_pos) {
                        //     //     cout << "   ";
                        //     //     // continue;
                        //     // }
                        //     cout << char(i);
                        // }
                        // cursor_pos++;
                        // cout << "\x1b[C";
                        cout << restoreCursor;
                        cout << "\b \b";
                        // cout << delLineFromCursor;
                        // for (int i = cursor_pos; i < message.size() - 1; i++) {
                            // cout << "\ncursor pos: " << cursor_pos << endl;
                            // cout << "\nvec: " << message[i] << "at " << i << endl;
                            // cout << char(i);
                        // }
                        // cout << restoreCursor;
                        // cout << "\x1b[D";
                        // cout << saveCursor;
                        // cout << eraseLine;
                        // for (int i : message) {
                        //     cout << char(i);
                        // }
                        // cout << restoreCursor;
                        // cout << "\x1b[D";
                        message.erase(message.begin() + cursor_pos - 1);
                        message.shrink_to_fit();
                        cursor_pos--;
                        // cout << "\x1b[D";
                    }

                    // cout << eraseLine;
                    // for (int i : message) {
                    //     cout << char(i);
                    //     // cout << "s: ";
                    //     // cout << message[char(i)];
                    // }
                    // cout << restoreCursor;
                }
                else if (cursor_pos == message.size()) {
                    if (cursor_pos == 0) {
                        continue;
                    }
                    else {
                        cout << "\b \b";
                        // message_str.pop
                        message.pop_back();
                        message.shrink_to_fit();
                        cursor_pos--;
                    }
                }
            }
            else {

                // cout << "C: " << cursor_pos << endl;
                // cout << "V: " << message.size() << endl;
                if (c != '[') {
                    // if (cursor_pos != message.size()) {
                    message.insert(message.begin() + cursor_pos, c);
                    // cout << eraseLine;
                    // for (int i : message) {
                    //     cout << char(i);
                    // }
                    // if (cursor_pos != message.size()) {
                    //     cout << restoreCursor;
                    // }
                    cout << c;
                    // message_str += c;
                    cursor_pos++;
                    //     cout << saveCursor;
                    // }
                }
                // update_display(cursor_pos);

                // cout << "C: " << cursor_pos << endl;
                // cout << "V: " << message.size() << endl;
                // if (c != '[') {
                //     // if (cursor_pos != message.size()) {
                //     //     cout << saveCursor;
                //     // }
                //     message.insert(message.begin() + cursor_pos, c);
                //     // cout << eraseLine;
                //     // for (int i : message) {
                //     //     cout << char(i);
                //     // }
                //     // if (cursor_pos != message.size()) {
                //     //     cout << restoreCursor;
                //     // }
                //     cout << c;
                //     cursor_pos++;
            }
        }
    }

    string message_str;

    disable_conio_mode();
    cout << endl;
    cout << boldModeReset;
    cout << "message:";
    for (char i : message) {
        cout << boldMode;
        message_str += i;
    }

    cout << message_str;

    cout << boldModeReset;
    cout << "\nExiting" << endl;
    // message.clear();
    return 0;
}