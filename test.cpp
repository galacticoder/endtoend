#include <iostream>

using namespace std;

int main() {
    string receivedMessage = "|=some";
    cout << receivedMessage.substr(0, receivedMessage.length() - receivedMessage.length() + 2) << endl;
    return 0;
}