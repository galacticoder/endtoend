#include <queue>
#include <iostream>

using namespace std;

int main()
{
    queue<int> q1;
    q1.push(39);
    q1.push(22);
    q1.push(82173);
    q1.push(654);
    q1.push(123);
    q1.push(423);
    q1.push(83);
    while (!q1.empty())
    {
        cout << "size before: " << q1.size() << endl;
        int val = q1.front();
        cout << "val: " << val << endl;
        q1.pop();
    }
    cout << "size after: " << q1.size() << endl;
    return 0;
}
