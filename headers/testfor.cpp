#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>

using namespace std;


int readActiveUsers(const string& filepath) {
    ifstream opent(filepath);
    string active;
    getline(opent, active);
    int activeInt;
    istringstream(active) >> activeInt;
    return activeInt;
}

int main() {
    while (true) {
        if (readActiveUsers("usersActive.txt") == 3) {
            cout << "it was 3" << endl;
            ofstream rewrite("usersActive.txt");
            if (rewrite.is_open()) {
                rewrite << "#RD";
            }
            break;
        }
        cout << readActiveUsers("usersActive.txt") << endl;
    }
    cout << "exiting" << endl;
    return 0;
}