#ifndef MISCELLANY_H
#define MISCELLANY_H

#include "../loghandler.h"

#include <string>
#include <utility>
#include <thread>
#include <functional>

#include <civetweb.h>
#include <ankerl/unordered_dense.h>
#include <nlohmann/json.hpp>

// for debug use only: print RAM usage
void showRamUsage(const std::string &prefix);

// CURL wrapper
std::pair<int, std::string> downloadSynchronously(const std::string &url);
size_t downloadSynchronouslyCallback(void *ptr, size_t size, size_t nmemb, std::string *buffer);

// periodically repeated works
class TimerThread
{
public:
    TimerThread(const int intervalInSeconds, std::function<void()> job);
    void start();

private:
    std::thread thread;
    std::chrono::seconds interval;
    std::function<void()> jobToDo;
};

namespace DailyChore {
// environmeltal variables
extern time_t licenseExpiredAt;
extern int paradoxResultsToMaintain;

// API
void initialize(const std::string &expirationString, const nlohmann::json &spin7);
void doIt();
time_t next0100am();

// logger
extern Logger logger;
} // namespace Chore

#endif // MISCELLANY_H
