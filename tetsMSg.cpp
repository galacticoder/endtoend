#include <iostream>
#include "encry_to_server.h"
#include <cryptopp/osrng.h>

using namespace CryptoPP;

std::string encryptT(std::string &msg) {
    // gen key and iv for encry of msg
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);
    generate_key_iv(key, iv);

    return aes_encrypt(msg, key, iv);
}


#include <iostream>
#include <chrono>
#include <ctime>
#include <regex>
#include <string>
#include <sstream>

using namespace std;
using namespace std::chrono;

int main() {
    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    time_t current = system_clock::to_time_t(now);
    std::tm* localTime = std::localtime(&currentTime);

    // Check if it's PM
    bool isPM = localTime->tm_hour >= 12;

    // Convert hour to 12-hour format
    int tHour = (localTime->tm_hour > 12) ? (localTime->tm_hour - 12) : ((localTime->tm_hour == 0) ? 12 : localTime->tm_hour);

    // Build time string
    stringstream ss;
    ss << tHour << ":" << (localTime->tm_min < 10 ? "0" : "") << localTime->tm_min << " " << (isPM ? "PM" : "AM");
    string formattedTime = ss.str();

    // Print formatted time
    std::cout << "Current local time: " << formattedTime << endl;
    std::cout << "date: " << asctime(localTime) << endl;

    return 0;
}


 std::regex time_pattern(R"(\b\d{2}:\d{2}:\d{2}\b)");

        std::smatch match;
        if (regex_search(stringFormatTime, match, time_pattern)) {
            std::cout << "Found time: " << match.str(0) << std::endl;