#include <iostream>
#include<cstdlib>

using namespace std;

int main() {
    srand((unsigned)time(NULL)); //seeds change every second so if gen to fast then random number wont change cuz 1s doesnt change
    string result = "";

    while (result.length() < 6) {
        int random = rand() % 10;
        result.append(to_string(random));
    }

    cout << result << endl;

    return 0;
}