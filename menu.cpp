#include <iostream>
#include <string>
#include <ncurses.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <fmt/core.h>
#include <string>

short track = 0;

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
    box(msg_input_win, 0, 0);

    WINDOW *msg_view_win = newwin(msg_view_h - 1, width - 2, 1, 1);
    box(msg_view_win, 0, 0);

    wrefresh(msg_view_win);
    wrefresh(msg_input_win);

    mvwprintw(msg_view_win, 0, 4, "Chat");
    wrefresh(msg_view_win);

    WINDOW *subwin = derwin(msg_view_win, height - 6, width - 4, 1, 1);
    scrollok(subwin, TRUE);
    idlok(subwin, TRUE);

    std::string msg;
    int ch;

    wmove(msg_input_win, 1, 1);

    // in while loop continuously read and stor cols in var if cols != that var then reprint everything
    while ((ch = wgetch(msg_input_win)) != KEY_UP)
    {
        if (ch == '\n')
        {
            if (!msg.empty())
            {
                track++;
                curs_set(0);

                wmove(subwin, track, 0);

                msg += "\n";
                wprintw(subwin, msg.c_str(), track);
                wrefresh(subwin);

                wclear(msg_input_win);
                box(msg_input_win, 0, 0);
                wrefresh(msg_input_win);
                msg.clear();
                wmove(msg_input_win, 1, 1);
                curs_set(1);
            }
            else
            {
                continue;
            }
        }
        // }
        else
        {
            msg += ch;
            wprintw(msg_input_win, "%c", ch);
            wrefresh(msg_input_win);
        }
    }

    // sleep(10);

    delwin(msg_view_win);
    delwin(subwin);
    delwin(msg_input_win);
    endwin();
    return 0;

    // std::string message;
}