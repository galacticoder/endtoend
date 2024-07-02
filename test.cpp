#include <iostream>
#include <filesystem>

using namespace std;
using namespace filesystem;

int main() {
    string some = "|user1 has sent you a file named 'somehting.txt' would you like to recieve it?(y/n): ";
    cout << some.substr(1, some.length() - 1);
    return 0;
}