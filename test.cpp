#include "headers/header-files/serverMenuAndEncryption.h"

int main()
{
    makeServerKey serverKey("server-key.pem", "server-cert.pem", "server-pub.pem");
    std::cout << "cert and key generated" << std::endl;

    return 0;
}
