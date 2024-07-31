#ifndef TERMCOMMMANDS
#define TERMCOMMMANDS

#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <cstdlib>
#include <signal.h>
#include <fcntl.h>

struct termcmd
{
    void set_inp(int &&op = 1)
    {
        if (op == 0)
        {
            struct termios tty;
            tcgetattr(STDIN_FILENO, &tty);
            tty.c_lflag &= ~(ICANON | ECHO);
            tcsetattr(STDERR_FILENO, TCSANOW, &tty);
        }
        else if (op == 1)
        {
            struct termios tty;
            tcgetattr(STDIN_FILENO, &tty);
            tty.c_lflag |= (ICANON | ECHO);
            tcsetattr(STDERR_FILENO, TCSANOW, &tty);
        }
    }
    void set_curs_vb(int &&visibility = 1) // 1 for on 0 for off
    {
        if (visibility == 0)
        {
            std::cout << "\033[?25l";
            std::cout.flush();
        }
        else if (visibility == 1)
        {
            std::cout << "\033[?25h";
            std::cout.flush();
        }
    }
};

#endif