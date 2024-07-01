#include <iostream>
#include <filesystem>

using namespace std;
using namespace filesystem;

bool createDir(const string& dirName)
{
    if (!create_directories(dirName))
    {
        if (exists(dirName))
        {
            cout << "The directory already exists" << endl;
            return true;
        }
        cout << "couldnt make directory" << endl;
        return false;
    }
    return true;
}

int main() {

    createDir("lahkjdjhd");
    return 0;
}