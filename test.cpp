#include <iostream>
#include <filesystem>
#include <vector>


using namespace std;
using namespace filesystem;

vector <string> mp;

int main() {

    mp.push_back("djgfdgd");
    mp.push_back("somehting else second");

    static short int index;
    for (int i = 0; i < mp.size(); i++)
    {
        if (mp[i] == "somehting else second") {
            std::cout << "i: " << i << endl;
            index = i; //append index to str
            break;
        }
    }

    cout << "index is: " << index << endl;

    cout << mp[index - 1] << endl;
    return 0;
}