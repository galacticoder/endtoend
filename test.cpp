#include <iostream>
#include <filesystem>
#include <vector>
#include <fstream>


using namespace std;
using namespace filesystem;

int main() {

    std::ifstream file("sendtouser.txt");
    std::string str;
    std::string file_contents;
    while (std::getline(file, str)) {
        file_contents += str;
        file_contents.push_back('\n');
    }
    cout << file_contents;
    return 0;
}