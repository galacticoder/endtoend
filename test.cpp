#include <iostream>
#include <unistd.h>
#include <termios.h>
#include <string>

using namespace std;

// Function to move the cursor to a specific position
void moveTo(int row, int col) {
    std::cout << "\033[" << row << ";" << col << "H";
    std::cout.flush();
}

// Function to move the cursor up n lines
void moveUp(int n) {
    std::cout << "\033[" << n << "A";
    std::cout.flush();
}

// Function to move the cursor down n lines
void moveDown(int n) {
    std::cout << "\033[" << n << "B";
    std::cout.flush();
}

// Function to move the cursor right n columns
void moveRight(int n) {
    std::cout << "\033[" << n << "C";
    std::cout.flush();
}

// Function to move the cursor left n columns
void moveLeft(int n) {
    std::cout << "\033[" << n << "D";

    std::cout.flush();
}

char getch() {
    char buf = 0;
    struct termios old = { 0 };
    if (tcgetattr(0, &old) < 0)
        perror("tcsetattr()");
    old.c_lflag &= ~ICANON;
    old.c_lflag &= ~ECHO;
    old.c_cc[VMIN] = 1;
    old.c_cc[VTIME] = 0;
    if (tcsetattr(0, TCSANOW, &old) < 0)
        perror("tcsetattr ICANON");
    if (read(0, &buf, 1) < 0)
        perror("read()");
    old.c_lflag |= ECHO;
    if (tcsetattr(0, TCSADRAIN, &old) < 0)
        perror("tcsetattr ~ICANON");
    return buf;
}

std::string get_sequence() {
    std::string seq;
    char c = getch();
    if (c == '\033') { // if the first character is an escape character
        seq += c;
        c = getch();
        if (c == '[') {
            seq += c;
            c = getch();
            seq += c;
            cout << seq;
        }
    }
    else {
        seq += c;
    }
    return seq;
}

void move_cursor_left(int& cursor_position) {
    if (cursor_position > 0) {
        std::cout << "\033[D"; // Move cursor left
        cursor_position--;
    }
}

void move_cursor_right(int& cursor_position, int length) {
    if (cursor_position < length) {
        std::cout << "\033[C"; // Move cursor right
        cursor_position++;
    }
}

int main() {
    std::string user;
    std::string seq;
    int cursor_position = 0;
    char ch;

    // std::cout << "Enter a username to go by: ";

    while (true) {
        seq = get_sequence();
        if (seq == "\n") {  // End input on Enter key
            break;
        }
        else if (seq == "\033[A" || seq == "\033[B") {
            // Ignore up and down arrow keys
        }
        else if (seq == "\033[C") {  // Right arrow key
            // cout << "" << endl;
            move_cursor_right(cursor_position, user.length());
        }
        else if (seq == "\033[D") {  // Left arrow key
            // cout << "" << endl;
            move_cursor_left(cursor_position);
        }
        else {
            ch = seq[0];
            user.insert(user.begin() + cursor_position, ch);
            // cout << user;
            cursor_position++;
            std::cout << "\033[s"; // Save cursor position
            std::cout << ch;  // Echo character
            std::cout << "\033[u"; // Restore cursor position
            std::cout << "\033[K"; // Clear line from cursor to end
            std::cout << user.substr(cursor_position); // Print the rest of the string
            std::cout << "\033[u"; // Restore cursor position again
            std::cout << "\033[C"; // Move cursor one position to the right
        }
    }

    std::cout << "\nYou entered: " << user << std::endl;

    return 0;
}

// int main() {
    // std::cout << "Start" << std::endl;
    // sleep(1);

    // Move cursor to row 5, column 10
    // moveTo(5, 10);
    // std::cout << "Moved to (5, 10)" << std::endl;
    // sleep(1);

    // Move cursor up 2 lines
    // moveUp(2);
    // std::cout << "Moved up 2 lines" << std::endl;
    // sleep(1);

    // // Move cursor down 3 lines
    // // moveDown(3);
    // std::cout << "Moved down 3 lines" << std::endl;
    // sleep(1);

    // // Move cursor right 5 columns
    // moveRight(5);
    // std::cout << "Moved right 5 columns" << std::endl;
    // sleep(1);

    // // Move cursor left 7 columns
    // moveLeft(7);
    // std::cout << "Moved left 7 columns" << std::endl;
    // sleep(1);

//     return 0;
// }
