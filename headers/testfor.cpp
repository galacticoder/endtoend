#include <iostream>
#include <vector>

using namespace std;


int itVec(const string&& username, vector <string>& vec) {
    int i = 0;
    for (auto& it : vec) {
        // cout << it << ' ';
        i++;
        if (it == username) {
            return i - 1;
        }
    }
    return -1;
}

int main() {
    vector <string> some = { "something", "someone" };

    cout << itVec("something", some) << endl; //returns index

    return 0;
}