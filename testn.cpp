#include <iostream>
#include <string>
#include <ncurses.h>

int main() {
    std::string input;
    char ch;

    std::cout << "Type something (type 'j' to stop): " << std::endl;

    while (true) {
        ch = std::cin.get();  // Read a single character


        if (ch == 'j') {
            exit(1);  // Exit the loop if 'j' is pressed
        }
        input += ch;  // Add the character to the input string
    }

    std::cout << "You typed: " << input << std::endl;
    return 0;
}
