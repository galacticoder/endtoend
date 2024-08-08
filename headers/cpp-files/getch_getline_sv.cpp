#include <iostream>
#include <vector>
#include <sys/ioctl.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <termios.h>
#include <stdexcept>
#include "../header-files/linux_conio.h"
#include "../header-files/getch_getline_sv.h"

#define s_path_getch "server-keys"
#define sk_path_getch "server-recieved-client-keys"
#define active_path "txt-files/usersActive.txt"

std::vector<std::string> message;
std::vector<char> modeP;

void signalHandleServer(int signum);

short getTermSizeCols()
{
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    return w.ws_col;
}

std::string getinput_getch(char &&MODE, const int &&maxLimit, const std::string &sideMsg)
{ // N==normal//P==Password
    std::cout << sideMsg;
    signal(SIGINT, signalHandleServer);
    enable_conio_mode();
    int cursor_pos = 0;
    short cols_out = getTermSizeCols();

    while (true)
    {
        short int cols = getTermSizeCols();
        if (message.size() < cols && message.size() > 1)
        {
            std::cout << saveCursor;
            std::cout << eraseLine;
            std::cout << sideMsg;
            if (MODE == 'P')
            {
                for (int i : modeP)
                {
                    std::cout << '*';
                }
            }
            else if (MODE == 'N')
            {
                for (std::string i : message)
                {
                    std::cout << i;
                }
            }

            std::cout << restoreCursor;
        }
        else if (message.size() + 1 == cols)
        {
        }
        std::cout << boldMode;
        if (_kbhit())
        { // do other keys ignore like page up and stuff
            char c = _getch();
            if (c == '\n')
            { // break on enter
                disable_conio_mode();
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
                            std::cout << sideMsg;

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
                            cout << eraseLine;
                            std::cout << "> ";

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
                            if (MODE == MODE_P)
                            {
                                modeP.erase(modeP.begin() + cursor_pos - 1);
                                modeP.shrink_to_fit();
                            }
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
                        if (MODE == MODE_P)
                        {
                            modeP.pop_back();
                            modeP.shrink_to_fit();
                        }
                        cursor_pos--;
                    }
                }
            }
            else
            {
                if (c != '[')
                {
                    if (message.size() < maxLimit)
                    {
                        if (MODE == MODE_P)
                        {
                            std::string s(1, c);
                            message.insert(message.begin() + cursor_pos, s);
                            modeP.insert(modeP.begin() + cursor_pos, c);
                            cout << "*";
                            cursor_pos++;
                        }
                        else if (MODE == MODE_N)
                        {
                            std::string s(1, c);
                            message.insert(message.begin() + cursor_pos, s);
                            cout << c;
                            cursor_pos++;
                        }
                    }
                }
            }
        }
    }

    disable_conio_mode();

    std::string message_str;

    for (std::string i : message)
    {
        cout << boldMode;
        message_str += i;
    }

    std::cout << boldModeReset;
    message.clear();
    modeP.clear();

    return message_str;
}
