#include <iostream>
#include <vector>
#include <algorithm>

using namespace std;

vector<string> client = { "something", "someone" };

int main() {
    string userStr = "something";
    auto user = find(client.rbegin(), client.rend(), userStr);
    // if (user != client.rend());
    //     client.erase((user + 1).base());
    // cout << *user << endl;
    string some;
    for (int i = 0;i < client.size();i++) {
        if (client[i] == userStr) {
            some.append(client[i]);
            cout << "spphjshjs";
        }
        else {
            cout << "somethign";
        }
    }
    cout << "len is: " << some << endl;

    if (some.length() > userStr.length()) {
        cout << "This name is displayed twice" << endl;
    }
    else {
        cout << "This name is only printed once" << endl;
    }
    return 0;
}