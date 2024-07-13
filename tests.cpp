#include <iostream>
#include <map>
#include <vector>

using namespace std;

vector <int> v;
map<string, int> userAndClSocket;

int main() {
    std::string encodedData = "uydfsyudgfsuhdfs|\\|2";
    cout << "ENCODED RECIEVED: " << encodedData << endl; //not recieving anything
    cout << "l: " << encodedData.length() << endl;
    int start = encodedData.length() - 4;
    cout << encodedData.substr(start) << endl;
    if (encodedData.substr(start) == "|\\|2") {
        // int ind = encodedData.find_last_of(strappnd);
        cout << encodedData.substr(0, start) << endl;
        cout << "done" << endl;
    }
    // cout << it->first;
    return 0;
}