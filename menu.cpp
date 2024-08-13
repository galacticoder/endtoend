#include <iostream>
#include <string>
#include <ncurses.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>

short track = 1;

short int getTermSizeCols()
{
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    return w.ws_col;
}

int main()
{
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);

    int height, width;
    height = LINES;
    width = COLS;

    int msg_view_h = height - 3;
    int msg_input_h = 3;

    WINDOW *msg_input_win = newwin(msg_input_h, width, msg_view_h, 0);
    WINDOW *msg_view_win = newwin(msg_view_h, width, 0, 0);

    box(msg_input_win, 0, 0);
    box(msg_view_win, 0, 0);

    wrefresh(msg_input_win);
    wrefresh(msg_view_win);

    std::string msg;
    int ch;

    wmove(msg_input_win, 1, 1);
    while ((ch = wgetch(msg_input_win)) != KEY_UP)
    {
        if (ch == '\n')
        {
            if (!msg.empty())
            {
                curs_set(0);
                wmove(msg_view_win, track, 1);
                wprintw(msg_view_win, "%s", msg.c_str());
                wrefresh(msg_view_win);

                wclear(msg_input_win);
                box(msg_input_win, 0, 0);
                wrefresh(msg_input_win);
                msg.clear();
                wmove(msg_input_win, 1, 1);
                curs_set(1);
                track++;
            }
        }
        else
        {
            msg += ch;
            wprintw(msg_input_win, "%c", ch);
            wrefresh(msg_input_win);
        }
    }

    // sleep(10);

    delwin(msg_view_win);
    delwin(msg_input_win);
    endwin();
    return 0;

    // std::string message;
}