#ifndef IGETLINE
#define IGETLINE

#include <iostream>
#include <atomic>
#include <openssl/ssl.h>

#define eraseLine "\033[2K\r"
#define boldMode "\033[1m"
#define boldModeReset "\033[22m"
#define saveCursor "\033[s"
#define restoreCursor "\033[u"
#define clearScreen "\033[2J\r"
#define MODE_P 'P'
#define MODE_N 'N'
#define CLIENT_S 'C'
#define SERVER_S 'S'
#define S_PATH "server-recieved-client-keys"
#define formatPath "keys-from-server/"
#define fpath "your-keys/"

using namespace std;

// void readUsersActiveFile(const string usersActivePath, std::atomic<bool>& running, unsigned int update_secs);
// void delIterate(const string& keyPath);
void isPortOpen(const string &address, int port, std::atomic<bool> &running, unsigned int update_secs);
short int getTermSizeCols();
void signalhandleGetch(int signum);
bool findIn(const char &find, const string &In);
int readActiveUsers(const string &filepath);
string getinput_getch(char sC = CLIENT_S, char &&MODE = MODE_N, SSL *clientSocket = NULL, const string &&unallowed = " MYGETCHDEFAULT'|", const int &&maxLimit = getTermSizeCols(), const string &serverIp = "-1", int PORT = 0);

#endif