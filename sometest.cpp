#include <ncurses.h>
#include <iostream>
#include <unistd.h> // For sleep function

int main() {
    // Initialize ncurses for basic terminal control
    setenv("NCURSES_NO_SETBUF", "1", 1); // Disable automatic flushing
    setenv("NCURSES_NO_TINFO", "1", 1); // Disable terminal info

    // Disable line buffering and echoing of input
    cbreak();
    noecho();

    // Move the cursor to a specific position
    move(5, 10);
    printw("Cursor is at (5, 10).");
    refresh();
    sleep(2); // Sleep for 2 seconds

    // Move the cursor up 2 lines
    move(3, 10);
    printw("Cursor moved up 2 lines.");
    refresh();
    sleep(2); // Sleep for 2 seconds

    // Move the cursor right 5 columns
    move(3, 15);
    printw("Cursor moved right 5 columns.");
    refresh();
    sleep(2); // Sleep for 2 seconds

    // Example of handling key presses (using ncurses for special keys)
    int ch;
    printw("Press 'q' to quit.");
    refresh();

    while ((ch = getch()) != 'q') {
        if (ch == KEY_BACKSPACE || ch == 127) {
            move(6, 0); // Move to a new line
            printw("Backspace key detected!");
            refresh();
        } else if (ch == '\n') {
            move(7, 0); // Move to a new line
            printw("Enter key detected!");
            refresh();
        } else {
            move(8, 0); // Move to a new line
            printw("You pressed: %c", ch);
            refresh();
        }
    }

    // End ncurses
    endwin();

    return 0;
}
