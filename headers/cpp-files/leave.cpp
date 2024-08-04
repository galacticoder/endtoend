#include <iostream>
#include <fmt/core.h>
#include <filesystem>
#include "../header-files/leave.h"

#define eraseLine "\033[2K\r"

using namespace std;
using namespace filesystem;

void delIt(const string &path)
{
    try
    {
        if (is_directory(path))
        {

            int del1 = 0;
            auto del2 = directory_iterator(path);
            int counter = 0;
            for (auto &del1 : del2)
            {
                if (del1.is_regular_file())
                {
                    remove(del1);
                    counter++;
                }
            }

            if (counter == 0)
            {
                cout << fmt::format("There was nothing to delete from path '{}'", path) << endl;
            }
            if (counter == 1)
            {
                cout << fmt::format("{} key in filepath ({}) have been deleted", counter, path) << endl;
            }
            else if (counter > 1)
            {
                cout << fmt::format("{} keys in filepath ({}) have been deleted", counter, path) << endl;
            }
            remove(path);
            cout << "Deleted directory '" << path << "'" << endl;
        }
        else if (is_regular_file(path))
        {
            try
            {
                remove(path);
                if (!is_regular_file(path))
                {
                    cout << fmt::format("Deleted file '{}'", path) << endl;
                }
                else
                {
                    cout << "Could not delete file: " << path << endl;
                }
            }
            catch (const exception &e)
            {
                cout << "";
            }
        }
    }
    catch (const exception &e)
    {
        cout << "";
    }
}

void leave(const string &path, const string &fPath)
{
    delIt(path);
    delIt(fPath);
}

void leaveFile(const string &path)
{
    delIt(path);
}