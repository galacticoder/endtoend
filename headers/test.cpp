#include "linux_conio.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <sys/ioctl.h>
#include <unistd.h>
#include <csignal>
#include "leave.h"


#define delLineFromCursor "\033[0K"
#define eraseLine "\033[2K\r"
#define boldMode "\033[1m"
#define boldModeReset "\033[22m"
#define saveCursor "\033[s"
#define restoreCursor "\033[u"
#define eraseFromStart "\033[1K"
#define linewrapping  "\033[7h"
#define eraseScreen  "\033[J"
#define colorCursor "\033[1;31"
// #define diffCursor "\033[q"

using namespace std;
using namespace chrono;

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

void signalhandleGetch(int signum) {
    // cout << "\nYou have left the chat" << endl;
    disable_conio_mode();
    leave();
    cout << endl;
    exit(signum);
}

string getinput_getch(const int&& limit = getTermSizeCols()) {
    setup_signal_interceptor();
    enable_conio_mode();
    int cursor_pos = 0;
    short int cols_out = getTermSizeCols();

    while (true) {
        // auto start = high_resolution_clock::now();
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

            // else if (int(c) == 3) {
            //     message.emplace_back('w');
            //     message.emplace_back('H');
            //     disable_conio_mode();
            //     string msg;

            //     disable_conio_mode();
            //     // cout << boldModeReset;
            //     // message_str.clear();

            //     for (char i : message) {
            //         // cout << boldMode;
            //         msg += i;
            //     }
            //     // cout << "msg: " << msg << endl;
            //     // message_str.append("\n");
            //     // message.clear();
            //     exit(1);
            //     return msg;
            //     // cout << ;
            // }

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
                // auto end = high_resolution_clock::now();
                // auto duration = duration_cast<milliseconds>(end - start).count();
                // if (duration < 50) {
                //     cout << "thats a paste?" << endl;
                //     continue;
                // }
                if (c == '\n') {
                    continue;
                }
                else if (c != '[') {
                    // if (c == '\n') {
                    //     continue;
                    // }
                    if (message.size() < limit) {
                        // cout << eraseLine;
                        // cout << "duration was: " << duration << endl;
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
    // cout << boldModeReset;
    // message_str.clear();

    for (char i : message) {
        // cout << boldMode;
        message_str += i;
    }
    // message_str.append("\n");
    message.clear();

    // cout << boldModeReset;
    return message_str;
}

int main() {
    string name = getinput_getch();
    cout << "\nname: " << name << endl;
    // cout <<

}

// int main() {
//     // int limit = 12;
//     // cout << linewrapping;
//     setup_signal_interceptor();
//     enable_conio_mode();
//     // string message_str;
//     int cursor_pos = 0;
//     short int cols_out = getTermSizeCols();

//     cout << "Taking input with kbhit + getch... Press Enter to stop: " << endl;
//     while (true) {
//         short int cols = getTermSizeCols();
//         if (message.size() < cols) {
//             cout << saveCursor;
//             cout << eraseLine;
//             for (int i : message) {
//                 cout << char(i);
//             }
//             cout << restoreCursor;
//         }
//         else if (message.size() + 1 == cols) {
//             // exit(1);
//             //     // cout << eraseLine;
//             //     // cout << "newlime" << endl;
//             //     // exit(1);
//             //     cout << '\n' << endl;
//             //     for (int i = cursor_pos;i < message.size();i++) {
//             //         // dsdsf
//             //         cout << char(i);
//             //     }
//             //     cout << restoreCursor;
//             //     // int restoreId = message.size() - cursor_pos;

//             //     // for (int i = 0; i <= restoreId; i++) {
//             //     //     cout << "\x1b[D";
//             //     // }
//         }
//         // cout << diffCursor;
//         cout << boldMode;
//         if (_kbhit()) { //do other keys ignore like page up and stuff
//             char c = _getch();
//             if (c == '\n') { //break on enter
//                 break;
//             }
//             // else if (c == '^') { //control keys
//             //     continue;
//             // }
//             else if (c == '\033') { //page and stuff keys
//                 continue;
//                 char next1 = _getch();
//                 char next2 = _getch();
//                 if (next1 == '[') {
//                     if (next2 == '6') { // page down
//                         char next3 = _getch(); // discard the tilde character
//                         if (next3 == '~') {
//                             continue;
//                         }
//                     }
//                 }
//             }

//             // else if (c == '1') { //shift keys
//             //     continue;
//             //     char next1 = _getch();
//             //     char next2 = _getch();
//             //     if (next1 == ';') {
//             //         continue;
//             //         if (next2 == '2') { // page down
//             //             continue;
//             //         }
//             //     }
//             // }

//             else if (int(c) == 65) { //up
//                 continue;
//                 // printf("\033%zuC", message.size());
//                 // cout << fmt::format("\033{}C", message.size());
//                 // cout << restoreCursor;
//             }
//             else if (int(c) == 66) { //down
//                 continue;
//             }
//             else if (int(c) == 67) { //right
//                 // cout << "csize: " << cursor_pos << endl;
//                 // cout << "msize: " << message.size() << endl;
//                 if (cursor_pos != message.size()) {
//                     cout << "\x1b[C";
//                     cursor_pos++;
//                     cout << saveCursor;
//                     // cout << eraseLine;
//                     // for (int i : message) {
//                     //     cout << char(i);
//                     //     // cout << "s: ";
//                     //     // cout << message[char(i)];
//                     // }
//                     // cout << restoreCursor;
//                 }
//             }
//             else if (int(c) == 68) { //left
//                 if (cursor_pos > 0) {
//                     cout << "\x1b[D";
//                     cursor_pos--;
//                     cout << saveCursor;
//                     // cout << eraseLine;
//                     // for (int i : message) {
//                     //     cout << char(i);
//                     //     // cout << "s: ";
//                     //     // cout << message[char(i)];
//                     // }
//                     // cout << restoreCursor;
//                 }
//             }
//             else if (int(c) == 70) { //end
//                 continue;
//             }
//             else if (int(c) == 126) { //page down 
//                 continue;
//             }
//             else if (int(c) == 127) { //backspace
//                 // cout << "\x1b[C";
//                 if (cursor_pos < message.size()) {
//                     if (cursor_pos < 1) {
//                         if (message.size() + 1 != cols_out) {

//                             cout << saveCursor;
//                             cout << eraseLine;
//                             for (int i : message) {
//                                 cout << char(i);
//                                 // cout << "s: ";
//                                 // cout << message[char(i)];
//                             }
//                             cout << restoreCursor;
//                             // cursor_pos++;
//                             // cout << "\x1b[C";
//                             // cout << eraseFromStart;
//                             continue;
//                         }
//                     }
//                     else {
//                         // cout << "\x1b[C";
//                         cout << saveCursor;
//                         // cout << eraseLine;
//                         // // cout << restoreCursor;
//                         // // cout << eraseLine;
//                         // cursor_pos++;
//                         // cout << "\x1b[C";

//                         if (message.size() + 1 == cols_out) {
//                             // exit(1);
//                             cout << eraseLine;
//                             for (int i : message) {
//                                 cout << char(i);
//                             }
//                             cout << restoreCursor;

//                         }
//                         else {
//                             cout << restoreCursor;
//                             cout << "\b \b";
//                             // cout << delLineFromCursor;
//                             // for (int i = cursor_pos; i < message.size() - 1; i++) {
//                                 // cout << "\ncursor pos: " << cursor_pos << endl;
//                                 // cout << "\nvec: " << message[i] << "at " << i << endl;
//                                 // cout << char(i);
//                             // }
//                             // cout << restoreCursor;
//                             // cout << "\x1b[D";
//                             // cout << saveCursor;
//                             // cout << eraseLine;
//                             // for (int i : message) {
//                             //     cout << char(i);
//                             // }
//                             // cout << restoreCursor;
//                             // cout << "\x1b[D";
//                             message.erase(message.begin() + cursor_pos - 1);
//                             message.shrink_to_fit();
//                             cursor_pos--;
//                             // continue;
//                         }
//                         // cout << "\x1b[D";
//                     }

//                     // cout << eraseLine;
//                     // for (int i : message) {
//                     //     cout << char(i);
//                     //     // cout << "s: ";
//                     //     // cout << message[char(i)];
//                     // }
//                     // cout << restoreCursor;
//                 }
//                 else if (cursor_pos == message.size()) {
//                     if (cursor_pos == 0) {
//                         continue;
//                     }
//                     else {
//                         cout << "\b \b";
//                         // message_str.pop
//                         message.pop_back();
//                         message.shrink_to_fit();
//                         cursor_pos--;
//                     }
//                 }
//             }
//             else {

//                 // cout << "C: " << cursor_pos << endl;
//                 // cout << "V: " << message.size() << endl;
//                 if (c != '[') {
//                     message.insert(message.begin() + cursor_pos, c);
//                     cout << c;
//                     cursor_pos++;
//                     // if (cursor_pos != message.size()) {
//                     // cout << eraseLine;
//                     // for (int i : message) {
//                     //     cout << char(i);
//                     // }
//                     // if (cursor_pos != message.size()) {
//                     //     cout << restoreCursor;
//                     // }
//                     // message_str += c;
//                     //     cout << saveCursor;
//                     // }
//                 }
//                 // update_display(cursor_pos);

//                 // cout << "C: " << cursor_pos << endl;
//                 // cout << "V: " << message.size() << endl;
//                 // if (c != '[') {
//                 //     // if (cursor_pos != message.size()) {
//                 //     //     cout << saveCursor;
//                 //     // }
//                 //     message.insert(message.begin() + cursor_pos, c);
//                 //     // cout << eraseLine;
//                 //     // for (int i : message) {
//                 //     //     cout << char(i);
//                 //     // }
//                 //     // if (cursor_pos != message.size()) {
//                 //     //     cout << restoreCursor;
//                 //     // }
//                 //     cout << c;
//                 //     cursor_pos++;
//             }
//         }
//     }

//     string message_str;

//     disable_conio_mode();
//     cout << endl;
//     cout << boldModeReset;
//     cout << "message:";
//     for (char i : message) {
//         cout << boldMode;
//         message_str += i;
//     }

//     cout << message_str;

//     cout << boldModeReset;
//     cout << "\nExiting" << endl;
//     // message.clear();
//     return 0;
// }