#include <iostream>
#include <chrono>
#include <map>
#include <string>
#include <thread>
#include <unistd.h>

using namespace std;

// std::map<std::string, std::chrono::secon/ds::rep> timeMap;

int main()
{
    int some = 90;
    while (some != 0)
    {
        cout << some << endl;
        sleep(1);
        some--;
    }
    cout << "done" << endl;

    return 0;
}
