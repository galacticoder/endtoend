#include <iostream>

using namespace std;


int main() {

    string input = "jhdfjfjdhjquit";
    if (input.find_last_of("quit") == input.length() - 1) {
        cout << "yes";
    }
    cout << input.find_last_of("quit") << endl;
    cout << input.length() - 1 << endl;


    return 0;
}