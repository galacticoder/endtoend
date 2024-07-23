#include <iostream>
#include "headers/getch_getline.h"


using namespace std;

int main(){
	string pass = getinput_getch(MODE_P);
	cout << endl << pass << endl;
	return 0;
}
