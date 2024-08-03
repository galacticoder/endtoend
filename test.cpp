#include <iostream>
#include <cstdlib>

int main()
{
    std::string some = "soen";

    std::cout << (std::string)some.c_str() << std::endl;

    return 0;
}