#ifndef SERVERSIDEGETCH
#define SERVERSIDEGETCH
// including my own getline function i made for better user input allows arrow keys and stuff

#include <iostream>
#include <atomic>

#define eraseLine "\033[2K\r"
#define boldMode "\033[1m"
#define boldModeReset "\033[22m"
#define saveCursor "\033[s"
#define restoreCursor "\033[u"
#define clearScreen "\033[2J\r"
#define MODE_P 'P'
#define MODE_N 'N'
#define SERVER_S 'S'

short int getTermSizeCols();
std::string getinput_getch(char &&MODE = MODE_N, long unsigned int &&maxLimit = getTermSizeCols(), const std::string &sideMsg = "");

#endif