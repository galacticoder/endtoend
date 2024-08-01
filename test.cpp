#include <iostream>
#include <chrono>
#include <map>
#include <string>
#include <thread>

int main()
{
    // Create a map to store time points as integers
    std::map<std::string, std::chrono::seconds::rep> timeMap;

    // Get the current time as seconds since epoch
    auto now = std::chrono::system_clock::now();
    auto nowTime = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

    // Store the current time in the map with a key
    timeMap["event1"] = nowTime;

    // Simulate some delay
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Get the current time again
    now = std::chrono::system_clock::now();
    auto newNowTime = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

    // Retrieve the stored time from the map
    auto storedTime = timeMap["event1"];
    auto elapsed = newNowTime - storedTime;

    // Compute the elapsed time

    // Output the elapsed time
    std::cout << "Elapsed time: " << elapsed << " seconds\n";

    if (elapsed == 0)
    {
        std::cout << "Cannot join rate limited" << std::endl;
    }

    return 0;
}
