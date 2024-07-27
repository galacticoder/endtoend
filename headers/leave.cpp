#include <iostream>
#include <fmt/core.h>
#include <filesystem>
#include "getch_getline.h"
#include "linux_conio.h"
#include "leave.h"

#define eraseLine "\033[2K\r"

using namespace std;
using namespace filesystem;

void delIt(const string& formatpath) {
    try {
        int del1 = 0;
        auto del2 = directory_iterator(formatpath);
        int counter = 0;
        for (auto& del1 : del2) {
            if (del1.is_regular_file()) {
                remove(del1);
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
        remove(formatPath);
        cout << "Deleted directory '" << formatPath << "'" << endl;
    }
    catch (const exception& e) {
        cout << "";
    }
}

void leave(const string& formatpath, const string& fPath) {
    disable_conio_mode();
    delIt(formatpath);
    delIt(fPath);
    remove("usersActive.txt");
    exit(1);
}