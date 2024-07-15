#include <ncurses.h>
#include <iostream>
#include <vector>
#include <fmt/core.h>

#define left1 "\033[1D" //move the cursor back to the left once

using namespace std;


vector <char> buffer;

int main()
{

    int ch;

    initscr();			/* Start curses mode 		*/
    raw();				/* Line buffering disabled	*/
    keypad(stdscr, TRUE);		/* We get F1, F2 etc..		*/
    string message = "";
    // noecho();			/* Don't echo() while we do getch */

    // printw("Type any character to see it in bold\n");
    while (true) {
        ch = getch();

        if (ch == 'q') {
            break;
        }			/* If raw() hadn't been called
                         * we have to press enter before it
                         * gets to the program 		*/
        if (ch == KEY_F(1))		/* Without keypad enabled this will */
            printw("F1 Key pressed");/*  not get to us either	*/
        /* Without noecho() some ugly escape
         * charachters might have been printed
         * on screen			*/
        int y, x;

        getyx(stdscr, y, x); //get screen cursor postion
        if (ch == KEY_LEFT) {
            if (x > 0) {
                move(y, x - 1);
            }
            // refresh();
            // printw("\033[1D");
            // cout << left1;
            refresh();
        }

        else if (ch == KEY_RIGHT) {//bathroom break
            int max_x, max_y;

            getmaxyx(stdscr, max_y, max_x);
            if (x < buffer.size()) {
                move(y, x + 1);
            }
            refresh();
        }
        else if (ch == KEY_BACKSPACE) {
            int y, x;
            getyx(stdscr, y, x); //get screen cursor postion
            delch();
        }
        // refresh();
        // printw("\033[1D");
        // cout << left1;

        if (ch == '\n' || ch == '\r') {
            break;
            // cout << "dkd" << endl;
            // break;
            // endwin();	/* End curses mode		  */
            // exit(1);
        }
        else
        {
            // cout << "key pressed: " << endl;
            // attron(A_BOLD);
            buffer.push_back(char(ch));
            message += char(ch);
            string some = "fdsdfsufd";
            // printw("%s: %s %s", some.c_str(), some.c_str(), some.c_str()); //%zu for ssizet %d is int  use %s with .c_str()
            // cout << char(ch);
            // cout << ch << endl; //if cout << ch  << endl is called then the code of the key is printed
            // cout << endl;
            // attroff(A_BOLD);
        }
        // refresh();			/* Print it on to the real screen */

    }
    // getc`h();			/* Wait for user input BEFORE EXITING */
    endwin();			/* End curses mode		  */

    return 0;
}