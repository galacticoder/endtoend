#include <iostream>
#include <vector>
#include <algorithm>

using namespace std;

int main()
{
    vector<string> some = {"some", "something", "something else"};

    auto it = std::remove(some.begin(), some.end(), "clsock");
    some.erase(it);

    return 0;
}