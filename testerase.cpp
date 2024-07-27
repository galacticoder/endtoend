#include <iostream>

#define eraseScreen "\033[1J\r"

using namespace std;

int main(){
	cout << eraseScreen;
	return 0;
}
