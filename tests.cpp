#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <vector>


#define left1 "\033[1D" //move the cursor back to the left once
#define right1 "\033[1C" //move the cursor back to the right once


using namespace std;

void set_conio_terminal_mode() { //set to raw mode
    struct termios new_termios;
    tcgetattr(0, &new_termios);
    new_termios.c_lflag &= ~ICANON; // disable line buffering
    // new_termios.c_lflag &= ~ECHO;   //  disable echo
    tcsetattr(0, TCSANOW, &new_termios);
}


void reset_terminal_mode() { //reset mode
    struct termios old_termios;
    tcgetattr(0, &old_termios);
    old_termios.c_lflag |= ICANON; // enable line buffering
    old_termios.c_lflag |= ECHO;   // enable echo
    tcsetattr(0, TCSANOW, &old_termios);
}

int get_char() {
    int ch;
    if (read(0, &ch, 1) < 0) {
        return -1;
    }
    else {
        return ch;
    }
}

void moveleft() {
    // cout << "\b";
    cout << "\x1b[D";
}

void moveright() {
    // cout << "\x1b[C";
    cout << "\x1b[C";
}

void delete_char() {
    cout << "\b \b";
}


int main() {
    set_conio_terminal_mode(); //raw mode
    int ch;

    // std::cout << "Type characters (press 'q' to quit):\n";
    vector <char> message;
    int cursor_pos = 0;

    while (true) {
        ch = get_char();

        if (ch == '\x1b') {
            int next1 = get_char();
            int next2 = get_char();

            if (next1 == '[') {
                switch (next2) {
                case 'A':
                    // std::cout << "Up arrow key pressed\n";
                    cout << "\x1b[A";
                    break;
                case 'B':
                    std::cout << "Down arrow key pressed\n";
                    break;
                case 'C':
                    // std::cout << "Right arrow key pressed\n";
                    if (cursor_pos < message.size()) {
                        moveright();
                        cursor_pos++;
                    }
                    break;
                case 'D':
                    // std::cout << "Left arrow key pressed\n";
                    if (cursor_pos > 0) {
                        moveleft();
                        cursor_pos--;
                    }
                    break;
                }
            }
        }
        else if (ch == '\n') {
            break;
        }
        else if (ch == 127 || ch == 8) { // 8 is backspace ion ascii
            if (cursor_pos > 0) {
                cursor_pos--;
                message.erase(message.begin() + cursor_pos);
                delete_char();
                for (size_t i = cursor_pos; i < message.size(); ++i) {
                    cout << message[i];
                }
                cout << ' ';
                for (size_t i = message.size(); i > cursor_pos; --i) {
                    moveleft();
                }
            }
        }
        else {
            message.push_back(char(ch));
            for (size_t i = cursor_pos; i < message.size();++i) {
                cout << message[i];
            }
            cursor_pos++;
            for (size_t i = message.size(); i > cursor_pos; --i) {
                moveleft();
            }
        }
    }

    reset_terminal_mode();
    cout << "\nMessage you typed: ";
    for (char c : message) {
        cout << c;
    }
    cout << endl;

    return 0;
}
