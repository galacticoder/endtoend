#ifndef GETCHCL
#define GETCHCL
// including my own getline function i made for better user input allows arrow keys and stuff

#include <iostream>
#include <atomic>

#define eraseLine "\033[2K\r"
#define boldMode "\033[1m"
#define boldModeReset "\033[22m"
#define saveCursor "\033[s"
#define restoreCursor "\033[u"
#define MODE_P 'P'
#define MODE_N 'N'
#define S_PATH "server-recieved-client-keys"
#define formatPath "keys-from-server/"
#define fpath "your-keys/"

short int getTermSizeCols();
void checkMessage(std::atomic<bool> &running, unsigned int update_secs);
bool findIn(const char &find, const std::string &In);
std::string getinput_getch(char &&MODE = MODE_N, const std::string &&unallowed = " MYGETCHDEFAULT'|", const int &&maxLimit = getTermSizeCols(), const std::string &sideMsg = "", const char *si = "\0", unsigned int prt = 0);
void passval(const std::string &messagePassed);

#endif