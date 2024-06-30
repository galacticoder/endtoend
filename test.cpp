#include <iostream>


using namespace std;

string con() {
    cout << "something" << endl;
    return "eys";
}

int main() {
    if (con()) {
        cout << "works";
    }
    return 0;
}