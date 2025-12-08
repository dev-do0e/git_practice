#include "miscellany.h"
#include "paradox.h"
#include "paranoia.h"
#include "../featherlite.h"
#include <fstream>

#include <curl/curl.h>

using namespace std::string_literals;

// some extern variables
time_t DailyChore::licenseExpiredAt = 0;
int DailyChore::paradoxResultsToMaintain = 2592000; // in seconds - past 30 days
Logger DailyChore::logger("DailyChore"s);

void showRamUsage(const std::string &prefix)
{
    int64_t ramFree, ramTotal;
#ifdef __linux__
    std::ifstream meminfo("/proc/meminfo"s);
    for (std::string line; std::getline(meminfo, line);) {
        if (line.find("MemTotal:"s) == 0) {
            line.erase(line.size() - 3); // remove tailing " kB"
            ramTotal = 1024 * std::stoll(line.substr(line.rfind(' ') + 1));
        } else if (line.find("MemAvailable:"s) == 0) {
            line.erase(line.size() - 3); // remove tailing " kB"
            ramFree = 1024 * std::stoll(line.substr(line.rfind(' ') + 1));
        }
    }
#else
    // get RAM usage
    MEMORYSTATUSEX ramInfo;
    ramInfo.dwLength = sizeof(ramInfo);
    GlobalMemoryStatusEx(&ramInfo);
    ramFree = ramInfo.ullAvailPhys;
    ramTotal = ramInfo.ullTotalPhys;
#endif
    Logger("RAM Usage"s).debug(prefix + ": "s + std::to_string((ramTotal - ramFree) / 1048576)); // in MB
}

std::pair<int, std::string> downloadSynchronously(const std::string &url)
{
    // initialize libcurl
    std::string downloaded;
    CURL *curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    // prepare to download
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, url.data());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, downloadSynchronouslyCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &downloaded);
    res = curl_easy_perform(curl);

    // prepare for result(or error)
    std::pair<int, std::string> result;
    if (res == CURLE_OK) {
        // get HTTP status code
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res);
        result = std::make_pair(static_cast<int>(res), downloaded);
    } else {
        result.first = -1;
        result.second.append(curl_easy_strerror(res));
    }

    // finalize
    curl_easy_cleanup(curl);
    return result;
}

size_t downloadSynchronouslyCallback(void *ptr, size_t size, size_t nmemb, std::string *buffer)
{
    buffer->append((char *) ptr, size * nmemb);
    return size * nmemb;
}

TimerThread::TimerThread(const int intervalInSeconds, std::function<void()> job)
    : interval(std::chrono::seconds(intervalInSeconds))
    , jobToDo(job)
{}

void TimerThread::start()
{
    thread = std::thread([&]() {
        // wait until first timeout
        auto next = std::chrono::steady_clock::now() + interval;
        std::this_thread::sleep_until(next);

        // start job
        while (true) {
            auto next = std::chrono::steady_clock::now() + interval;
            jobToDo();
            std::this_thread::sleep_until(next);
        }
    });
    thread.detach();
}

void DailyChore::initialize(const std::string &expirationString, const nlohmann::json &spin7)
{
    // calculate epoch timestamp for license expiration
    struct tm expirationRaw{};
    expirationRaw.tm_year = std::stoi(expirationString.substr(0, 4)) - 1900;
    expirationRaw.tm_mon = std::stoi(expirationString.substr(5, 2)) - 1;
    expirationRaw.tm_mday = std::stoi(expirationString.substr(8, 2));
    expirationRaw.tm_hour = 23;
    expirationRaw.tm_min = 59;
    expirationRaw.tm_sec = 59;
    expirationRaw.tm_isdst = 0;
    licenseExpiredAt = mktime(&expirationRaw);

    // prepare for how long a Paradox / Paranoia record will remain in the database table
    if (spin7.contains("ParadoxRecordsToMaintain"s))
        paradoxResultsToMaintain = spin7["ParadoxRecordsToMaintain"s].get<int>();
}

void DailyChore::doIt()
{
    logger.log("Do some chores"s);

    // check license expiration
    if (time(nullptr) >= licenseExpiredAt) {
        logger.log("License expired. Exiting Spin7"s);
        exit(1);
    }

    // flush too old records from database tables
    const std::string paradoxResultsToMaintainString = std::to_string(paradoxResultsToMaintain);

    // paradoxresults
    {
        Paradox::devicesMutex.lock();
        FeatherLite feather("paradox.results"s);
        if (!feather.exec("DELETE FROM paradoxresults WHERE testedat < (SELECT MAX(testedat) FROM paradoxresults)-"s + paradoxResultsToMaintainString + ';'))
            logger.log("Failed to clean up Paradox results"s);
        Paradox::devicesMutex.unlock();
    }
    // paranoia
    { // life span of FeatherLite object is limited inside this bracket so that WAL file doesn't exist unnecessarily long
        Paranoia::writerMutex.lock();
        FeatherLite feather("paranoia.results"s);
        feather.exec("DELETE FROM paranoia WHERE testedat < (SELECT MAX(testedat) FROM paranoia)-"s + paradoxResultsToMaintainString + ";VACUUM;"s);
        Paranoia::writerMutex.unlock();
    }
}

time_t DailyChore::next0100am()
{
    time_t tomorrow = time(nullptr) + 86400;
    struct tm at0100;
#ifdef __linux__
    localtime_r(&tomorrow, &at0100); // Linux
#else
    localtime_s(&at0100, &tomorrow); // Windows
#endif
    at0100.tm_hour = 1;
    at0100.tm_min = 0;
    at0100.tm_sec = 0;
    return mktime(&at0100);
}
