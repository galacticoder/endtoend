#include "serverMenuAndEncry.h"
#include <iostream>
#include <fmt/core.h>
// #include <algorithm>

int main()
{
    DecServer decode;
    std::string store = decode.Base64Decode("someone");
    std::string store2 = "\u1F600";
    std::cout << "Decoded: " << store << std::endl;
    std::cout << "Decoded: " << store2 << std::endl;

    for (int i = 0; i < store2.size(); i++)
    {
        if (char(int(store2[i])) < 128 && char(int(store2[i])) > 0)
        {
            std::cout << "this is a char" << std::endl;
        }
        std::cout << int(store2[i]) << std::endl;
        // else[]
    }
    return 0;
}