#include <iostream>

int main()
{
    std::cout << "\033[1;31m"; // set color to bold red
    std::cout << "Hello, world!" << std::endl;
    std::cout << "\033[0m"; // reset color to default
    return 0;
}