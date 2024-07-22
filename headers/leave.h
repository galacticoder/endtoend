#ifndef LEAVE
#define LEAVE

#include <iostream>
// #include <unistd.h>
#include <fmt/core.h>
#include <filesystem>

#define formatPath "keys-from-server/"
#define fpath "your-keys/"

using namespace std;
using namespace filesystem;

void delIt(const string& formatpath) {
    int del1 = 0;
    auto del2 = filesystem::directory_iterator(formatpath);
    int counter = 0;
    for (auto& del1 : del2) {
        if (del1.is_regular_file()) {
            filesystem::remove(del1);
            counter++;
        }
    }

    if (counter == 0) {
        cout << fmt::format("There was nothing to delete from path '{}'", formatpath) << endl;
    }
    if (counter == 1) {
        cout << fmt::format("{} key in filepath ({}) have been deleted", counter, formatpath) << endl;
    }
    else if (counter > 1) {
        cout << fmt::format("{} keys in filepath ({}) have been deleted", counter, formatpath) << endl;
    }
}

void leave(const string& formatpath = formatPath, const string& fPath = fpath) {
    delIt(formatpath);
    delIt(fPath);
    remove("usersActive.txt");
    // cout << endl;
    exit(1);
}


#endif