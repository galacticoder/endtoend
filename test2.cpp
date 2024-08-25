#include <iostream>

int main()
{
    int some = 1;
    while (1)
    {
        if (some == 12)
        {
            continue;
        }
        std::cout << "some" << std::endl;
    }
    return 0;
}