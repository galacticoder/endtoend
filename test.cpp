#include <iostream>
#include <chrono>
#include <map>
#include <string>
#include <thread>

int main()
{
    std::map<std::string, std::chrono::seconds::rep> timeMap;

    auto now = std::chrono::system_clock::now();
    auto nowTime = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

    timeMap["event1"] = nowTime;

    std::this_thread::sleep_for(std::chrono::seconds(1));

    now = std::chrono::system_clock::now();
    auto newNowTime = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

    auto storedTime = timeMap["event1"];
    auto elapsed = newNowTime - storedTime;

    std::cout << "Elapsed time: " << elapsed << " seconds\n";

    if (elapsed == 0)
    {
        std::cout << "Cannot join rate limited" << std::endl;
    }

    return 0;
}
