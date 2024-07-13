#include <bits/stdc++.h>
using namespace std;

// Function that using string::npos
// to find the index of the occurrence
// of any string in the given string
void fun(string s1, string s2) {
    // Find position of string s2
    int found = s1.find(s2);

    // Check if position is -1 or not
    if (found != string::npos) {
        cout << found << endl;
    }

    else
        cout << "couldnt format" << endl;
}

int main()
{
    string userstr = "something";
    string userstrmsg = "something fkdskjfdjk f djfsjk";
    if (userstrmsg.substr(0, userstr.length()) == userstr) {
        cout << "yes" << endl;
    }
    return 0;
}
