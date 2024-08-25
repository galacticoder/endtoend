#include <iostream>
#include <ncurses.h>

int main()
{

    initscr();
    cbreak();
    nonl();
    // noecho();
    keypad(stdscr, TRUE);

    int x, y;
    getmaxyx(stdscr, y, x);

    WINDOW *passwordWindow = newwin(5, COLS / 2, (LINES - 5) / 2, (COLS - COLS / 2) / 2);
    box(passwordWindow, 0, 0);
    wrefresh(passwordWindow);

    mvwprintw(passwordWindow, 1, 1, "Enter password to set for server:");
    wmove(passwordWindow, 2, 1);
    wrefresh(passwordWindow);

    int ch;
    int CursorPosition = 0;
    std::string message;

    while (ch != '\n')
    {
        ch = wgetch(passwordWindow);
        if (ch == 127)
        {
            delch();
            message.pop_back();
        }
        else
        {
            message += char(ch);
        }
    }

    delwin(passwordWindow);
    endwin();
    std::cout << "Message: " << message;
    return 0;
}
