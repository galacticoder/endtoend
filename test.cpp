#include <iostream>
#include <filesystem>

using namespace std;
using namespace filesystem;

int main() {
    string filepath = "/sendfile jdsfhfjdn.dfsdfsfd";
    string fpFormatted = filepath.substr(8 + 2, filepath.length() - 1);
    cout << fpFormatted;
    return 0;
}