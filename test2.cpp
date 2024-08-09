#include <iostream>
#include "headers/header-files/getch_getline_sv.h"

int main(){
	std::string user = getinput_getch(MODE_N,getTermSizeCols(),"Enter username: ");

	std::cout << "\n user name: " << user << std::endl;
	return 0;
}
