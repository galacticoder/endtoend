#include "headers/header-files/getch_getline_sv.h"
#include <iostream>

using namespace std;

int main() {
  std::string input =
      getinput_getch(MODE_N, getTermSizeCols(), "Enter your password: ");

  std::cout << "\nInput: " << input << std::endl;
  return 0;
}
