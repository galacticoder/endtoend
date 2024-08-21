#include <functional>
#include <iostream>
#include <csignal>

namespace func
{
  std::function<void(int)> shutdown_handler;
  void signal_handler(int signal)
  {
    shutdown_handler(signal);
  }
}

int main()
{
  int someNum = 32;

  std::signal(SIGINT, func::signal_handler);
  func::shutdown_handler = [&](int signal)
  {
    std::cout << "Server shutdown...\n";
    std::cout << "Some Num is: " << someNum << std::endl;
    someNum = 434;
    std::cout << "Some Num is now: " << someNum << std::endl;
    exit(signal);
  };

  std::cout << "Waiting for Ctrl+c.." << std::endl;
  while (1)
  {
  }
}