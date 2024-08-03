#include "getch_testing.h"

int main()
{
    std::string name = getinput_getch();

    std::cout << '\n'
              << name << endl;
    return 0;
}
