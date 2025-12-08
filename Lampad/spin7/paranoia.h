#ifndef PARANOIA_H
#define PARANOIA_H

#include "../loghandler.h"

#include <string>
#include <shared_mutex>
#include <mutex>
#include <civetweb.h>
#include <ankerl/unordered_dense.h>
#include <nlohmann/json.hpp>

namespace Paranoia {
// initialize
void initialize();

// device management
extern nlohmann::json devices;
extern std::shared_mutex devicesMutex, latestResultCacheMutex;
extern std::mutex writerMutex;
void saveDeviceList();

// cache for latest results
extern ankerl::unordered_dense::map<std::pair<std::string, std::string>, bool> latestResultCache; // <mac address + test scenario name> + is this test a success?
ankerl::unordered_dense::map<std::pair<std::string, std::string>, bool> newLatestResultCache();

// hidden interfaces to remote devices
void describeStatus(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void storeNewTestResults(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters);

// Spin7 REST API
void enumerateDevices(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void showLatestResults(mg_connection *connection);
void deleteDevice(mg_connection *connection, const std::string &path);
void changeSettings(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void updateTestScenarios(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void postBlob(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void getTestResults(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters);

// miscellany
extern Logger logger;
} // namespace Paranoia

#endif // PARANOIA_H
