#include <iostream>

using namespace std;

int main() {
    string pub = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAwrOXckY0v7GZsb3poDchGpJi+CXsfune4KYCEyLg9CkJiuzkCQ3AcRFw3kgn3jdkFjpb26r6XoGz7WwHtRHgCpmTAnYAzfFhY6NdlwINe0xwWwnUMV42REzFaH5WoFFcyIKd3am2HucNIasyjFbUFGNwMFEEOy7T2oD1oGbzpZvK3XiS2MJScseq5RfqH+hjK7ZkjxQb5PsnpNiSRqbIZYkD1Tqi3cydeke9LOd2VlTPvlmE7PlDqUBbvtqAZP7iLNuYk6ZPY8Oc/Y1BqWoChuDy92s1a1+DBKYSjAv+spj+Bat1wtuoIFHHVAtJ7Q4VjNlm4n/9EAwz9GPkmeImQxPQEurO53M0dJ4Hl+oik/JNZLfAywk+lAmh8AO+zsHhjSX9vapLfDFKk8zYy+NBjmsILJXfkAev8tyjdWxkXipSeMTKj+2YPdUYRzKY/UaNZv1L3DLNUmXHHTpM+OcKH9w/+5nYEfawnhrJTPHZ9wiMdIyRUUTL4J2WleqzWoKcCTAXV47BtOyH75nHoBlHu4iKs72jfQI4Vp5MgN2y9mjytpKJEEuRcRD2unEOxrTJ7YMPNBFLIp3Y/aDd18DFoKoNycwATcZcvQNZuehoZSaqSvO5XH3k6XYlWjq2QN8nd0Dha36riPFU4Tq6T3HBmQRPLL18BXB6TYk1R6KN/hECARE=";

    static const string formatpath = "keys-from-server/";
    int indexInt = pub.find_first_of("/") + 1;
    pub = pub.substr(indexInt);
    pub = pub.insert(0, formatpath, 0, formatpath.length());
    int firstPipe = pub.find_last_of("/");
    int secondPipe = pub.find_last_of("-");
    string pubUser = pub.substr(firstPipe + 1, (secondPipe - firstPipe) - 1);

    cout << "Recieving " << pubUser << "'s public key" << endl;

    return 0;
}