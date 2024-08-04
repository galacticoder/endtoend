#include <iostream>
#include <vector>
#include <sys/ioctl.h>
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <thread>
#include <chrono>
#include <atomic>
#include <stdexcept>
#include "../header-files/linux_conio.h"
#include "../header-files/getch_getline_cl.h"
// #include "../header-files/sigHandler.h"

#define s_path_getch "server-keys"
#define sk_path_getch "server-recieved-client-keys"
#define active_path "txt-files/usersActive.txt"

using namespace std::chrono;

std::vector<std::string> message;
std::vector<char> modeP;

void signalhandle(int signum);
extern int checkExitMsg;
std::string messagePassedClient;

void checkMessage(std::atomic<bool> &running, unsigned int update_secs)
{
    const auto wait_duration = std::chrono::seconds(update_secs);
    while (true)
    {
        try
        {
            if (checkExitMsg == 1)
            {
                running = false;
            }
            std::this_thread::sleep_for(wait_duration);
        }
        catch (const std::exception &e)
        {
            running = false;
        }
    }
}

short int getTermSizeCols()
{
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    return w.ws_col;
}

bool findIn(const char &find, const std::string &In)
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

std::string getinput_getch(char &&MODE, const std::string &&unallowed, const int &&maxLimit)
{ // N==normal//P==Password
    signal(SIGINT, signalhandle);
    enable_conio_mode();
    int cursor_pos = 0;
    short int cols_out = getTermSizeCols();

    std::atomic<bool> running{true};
    const unsigned int update_interval = 1;
    std::thread msgReceived(checkMessage, std::ref(running), update_interval);
    msgReceived.detach();

    while (true)
    {
        short int cols = getTermSizeCols();
        // check if message was receieved here and then print it out before re-enabling conio mode and sleep half a sec after printing
        if (running == false)
        {
            // print msg receieved here
            disable_conio_mode(); // find way to stop getch then print the message if getch detects a message was sent to the client
            set_default_terminal();
            std::cout.flush();
            std::cout << messagePassedClient << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        //-----------------
        if (message.size() < cols)
        {
            // cout << "\x1b[C";
            std::cout << saveCursor;
            std::cout << eraseLine;
            // cout << saveCursor;
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
                    std::cout << "\x1b[C";
                    cursor_pos++;
                    std::cout << saveCursor;
                }
            }
            else if (int(c) == 68)
            { // left
                if (cursor_pos > 0)
                {
                    std::cout << "\x1b[D";
                    cursor_pos--;
                    std::cout << saveCursor;
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
                            std::cout << saveCursor;
                            std::cout << eraseLine;
                            for (std::string i : message)
                            {
                                std::cout << i;
                            }
                            std::cout << restoreCursor;
                            continue;
                        }
                    }
                    else
                    {
                        std::cout << saveCursor;
                        if (message.size() + 1 == cols_out)
                        {
                            // exit(1);
                            std::cout << eraseLine;
                            for (std::string i : message)
                            {
                                std::cout << i;
                            }
                            std::cout << restoreCursor;
                        }
                        else
                        {
                            std::cout << restoreCursor;
                            std::cout << "\b \b";
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
                        std::cout << "\b \b";
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
                if (unallowed == " MYGETCHDEFAULT'|/")
                {
                    std::cout << "\x1b[C";
                    if (c != '[')
                    {
                        if (message.size() < maxLimit)
                        {
                            if (MODE == MODE_P)
                            {
                                std::string s(1, c);
                                // c = '*';
                                message.insert(message.begin() + cursor_pos, s);
                                modeP.insert(modeP.begin() + cursor_pos, c);
                                // cout << c;
                                std::cout << "*";
                                cursor_pos++;
                            }
                            else if (MODE == MODE_N)
                            {
                                std::string s(1, c);
                                message.insert(message.begin() + cursor_pos, s);
                                std::cout << c;
                                cursor_pos++;
                            }
                        }
                    }
                }
                else if (unallowed != " MYGETCHDEFAULT'|/")
                {
                    std::string notAllowed = "";

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
                                    std::string s(1, c);
                                    message.insert(message.begin() + cursor_pos, s);
                                    modeP.insert(modeP.begin() + cursor_pos, c);
                                    // cout << c;
                                    std::cout << "*";
                                    cursor_pos++;
                                }
                                else if (MODE == MODE_N)
                                {
                                    std::string s(1, c);
                                    message.insert(message.begin() + cursor_pos, s);
                                    std::cout << c;
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

    std::string message_str;

    for (std::string i : message)
    {
        std::cout << boldMode;
        message_str += i;
    }

    std::cout << boldModeReset;
    message.clear();
    modeP.clear();
    // unallowed.clear();
    // cout << endl;

    return message_str;
}

void passval(const std::string &messagePassed)
{
    messagePassedClient = messagePassed;
}