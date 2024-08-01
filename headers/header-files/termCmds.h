#ifndef TERMCOMMMANDS
#define TERMCOMMMANDS

#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <cstdlib>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>

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
    void curs_pos(int &&x, int &&y)
    {
        std::cout << "\033[" << y << ";" << x << "H\r";
        std::cout.flush();
    }
    short int getTermSize(/*int *ptrCols*/)
    {
        struct winsize w;
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
        //*ptrCols = w.ws_col;
        return w.ws_row; // lines
    }
};

// void call_pgbar(int *ptrvar, int var) // condition where the loop stops
// {
//     termcmd term;
//     while (var == *ptrvar)
//     {
//         if (var != *ptrvar)
//         {
//             std::cout << "\x1b[A";
//             std::cout << "\033[2K\r";
//             break;
//         }
//         std::cout << "." << std::endl;
//         sleep(1);
//         term.curs_pos(0, term.getTermSize() - 1);
//         std::cout << "\033[2K\r";
//         std::cout << ".." << std::endl;
//         sleep(1);
//         term.curs_pos(0, term.getTermSize() - 1);
//         std::cout << "\033[2K\r";
//         std::cout << "..." << std::endl;
//         sleep(1);
//         term.curs_pos(0, term.getTermSize() - 1);
//         std::cout << "\033[2K\r";
//     }
//     // std::cout << "progress bar done" << std::endl;
// };

#endif