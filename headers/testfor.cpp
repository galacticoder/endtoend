#include <iostream>
#include <vector>

using namespace std;

bool findIn(const char& find, const string& In) {
    for (int i = 0; i < In.length(); i++) {
        cout << In[i] << "\t|\t" << find << "|" << endl;
        if (In[i] == find) {
            // cout << "found" << endl;
            return true;
        }
        // else {
            // cout << "not found" << endl;
        // return false;
        // }
    }
    return false;
}

int main() {
    char some = '\\';
    // string some[20] = { "some1", "hello" };

    string unallowed = "/\\";

    // some.push_back(something);
    // some->append(something);

    cout << findIn(some, unallowed) << endl; //1 is true and 0 is false

    return 0;
}