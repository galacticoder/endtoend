#include <iostream>

using namespace std;


int main() {
    string some = "/sendfile something.txt";
    string clfile = some.substr(8 + 2, some.length());
    cout << clfile;

    return 0;
}