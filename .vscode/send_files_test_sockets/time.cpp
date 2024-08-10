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
    string stringFormatTime = asctime(localTime);

    // Convert hour to 12-hour format
    int tHour = (localTime->tm_hour > 12) ? (localTime->tm_hour - 12) : ((localTime->tm_hour == 0) ? 12 : localTime->tm_hour);

    // Build time string
    stringstream ss;
    ss << tHour << ":" << (localTime->tm_min < 10 ? "0" : "") << localTime->tm_min << " " << (isPM ? "PM" : "AM");
    string formattedTime = ss.str();

    // Print formatted time
    std::cout << "Current local time: " << formattedTime << endl;

    // stringstream formattedTimeAsctime;
    // formattedTimeAsctime << setw(2) << setfill('0') << localTime->tm_hour << ":"
    //                      << setw(2) << setfill('0') << localTime->tm_min << ":"
    //                      << setw(2) << setfill('0') << localTime->tm_sec;

    // string stringFormatTime = formattedTimeAsctime.str();

    std::regex time_pattern(R"(\b\d{2}:\d{2}:\d{2}\b)");

    std::smatch match;
    if (regex_search(stringFormatTime, match, time_pattern)) {
        std::cout << "Found time: " << match.str(0) << std::endl;
    }
    string str = match.str(0);
    size_t pos = stringFormatTime.find(str);
    cout <<pos << endl;
    stringFormatTime.replace(pos, str.length(), formattedTime);


    std::cout << "date: " << stringFormatTime << endl;

    return 0;
}


