#include <iostream>
#include <filesystem>
#include <vector>
#include <fstream>


using namespace std;
using namespace filesystem;

int main() {
    string receivedMessage = "jghfdgjhdjfgdh|\\\\|2";
    cout << receivedMessage.substr(receivedMessage.length() - 5, 5) << endl;
    return 0;
}