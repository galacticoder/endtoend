#ifndef fileserver
#define fileserver

#include <iostream>

using namespace std;

// const string PORTFILE = ".FILEPORT.TXT";
const string PORTFILED = "FILEPORT.TXT";


bool isPav(int port);
bool recvServer(string& filename);

#endif