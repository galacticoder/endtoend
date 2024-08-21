#include <iostream>

using namespace std;

int main()
{
  string some = "server-kets/sddfdfggsfdsdfg-pfdtgfdgdfuybey.pem";
  cout << some.substr(some.find_first_of("/") + 1, (some.find_last_of("-") - some.find_first_of("/")) - 1) << std::endl; // server-kets/username-puybey.pem
  return 0;
}