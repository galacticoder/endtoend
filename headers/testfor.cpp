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
    string clientThreePath = "keys/user3-publickeyfromserver.der";
    int indexInt = clientThreePath.find_first_of("/") + 1;
    // clientThreePath = clientThreePath.substr(indexInt);
    // clientThreePath = clientThreePath.insert(0, formatpath, 0, formatpath.length());
    // int firstPipe = clientThreePath.find_last_of("/");
    int secondPipe = clientThreePath.find_last_of("-");
    string pubUser = clientThreePath.substr(indexInt, secondPipe - 5);
    cout << pubUser << endl;
    return 0;
}