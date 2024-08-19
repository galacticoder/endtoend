#include "headers/header-files/getch_getline_sv.h"
#include <iostream>

int main() {
  std::string password =
      getinput_getch(MODE_N, getTermSizeCols(), "Enter your password: ");

  std::cout << "\nPass is: " << password << std::endl;
  return 0;
}
