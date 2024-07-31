#include <iostream>
#include <vector>
#include <algorithm>

using namespace std;

int main()
{
    vector<string> some = {"some", "one"};

    string something = "one";
    auto it = std::find(some.begin(), some.end(), something);
    int indexClientOut = it - some.begin();

    if (int someth = std::find(some.begin(), some.end(), something) - some.begin() != some.size())
    {
        cout << "IndexClientOut: " << indexClientOut << endl;
    }

    return 0;
}