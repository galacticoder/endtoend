#include <iostream>
#include <string>

int main() {
    std::string input;
    char ch;

    std::cout << "Type something (type 'j' to stop): " << std::endl;

    while (true) {
        ch = std::cin.get();  // Read a single character

        input += ch;  // Add the character to the input string

        if (ch == 'j') {
            break;  // Exit the loop if 'j' is pressed
        }
    }

    std::cout << "You typed: " << input << std::endl;
    return 0;
}
