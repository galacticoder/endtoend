#include <iostream>
#include <map>
#include <vector>

using namespace std;

vector <int> v;
map<string, int> userAndClSocket;

int main() {

    string userStr = "someopne";
    v.push_back(2);
    cout << "size: " << v.size() + 2 - 1 << endl; //due to no value in it it wqas giving large random number
    // string some = "ghhgd";
    cout << "name: " << userStr + to_string(v.size() - 1);
    cout << endl;
    userAndClSocket[userStr += v.size() - 1] = 1;
    map<string, int>::iterator it = userAndClSocket.begin();

    // Iterate through the map and print the elements

    while (it != userAndClSocket.end()) {
        cout << "Key: " << it->first << ", Value: " << it->second << endl;
        if (it->first == userStr) {
            cout << it->second << endl;
            cout << "yes" << endl;
            break;
        }
        ++it;
    }

    // cout << it->first;
    return 0;
}