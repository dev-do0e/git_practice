#ifndef PARADOX_H
#define PARADOX_H

#include <civetweb.h>
#include <ankerl/unordered_dense.h>
#include <yyjson.h>
#include <nlohmann/json.hpp>
#include <tbb/concurrent_hash_map.h>
#include <shared_mutex>
#include <mutex>

#include "../loghandler.h"
#include "../featherlite.h"

namespace Paradox {
extern Logger logger;
extern std::mutex dbMutex;

// client device management: public interface
void enumerateDevices(mg_connection *connection);
void getResults(mg_connection *connection, const std::string &macAddress, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void getResultsDefault(const std::string &macAddress, FeatherLite &feather, int bindValue, mg_connection *connection);
void getResultsTabSeparated(const std::string &macAddress, FeatherLite &feather, mg_connection *connection);
void getResultsVersionSsh(mg_connection *connection, const std::string &portNumberRaw, const std::string &macAddress, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void getResultsLatest(mg_connection *connection);
void getResultsTopology(mg_connection *connection);
void postResultsLatest(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void getRanking(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void updateDeviceDescription(mg_connection *connection, const std::string &macAddress, const ankerl::unordered_dense::map<std::string, std::string> &parameters, const std::string &sourceIp);
void deleteDeviceOrResults(mg_connection *connection, const std::string &macAddress, const ankerl::unordered_dense::map<std::string, std::string> &parameters);

// client device management: backend
void initialize();
void getLastUpdateTime(mg_connection *connection, const std::string &macAddress);
uint32_t lastUpdateTime(const std::string &macAddress); // check last timestamp. and additionally update last connection and IP address
void updateTestResults(mg_connection *connection, const std::string &macAddress, const ankerl::unordered_dense::map<std::string, std::string> &parameters); // actually shared by both public(register new device / change alias of existing device) and hidden(update test results)
void updateLastConnection(const std::string &macAddress, const char *remoteAddress); // update client connection information, which is used as keep alive checker
extern time_t latestUpdateIntervalInSeconds;

// backend for device management
void updateDeviceDescription2(const std::string &macAddress, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void saveDeviceDescription();
extern tbb::concurrent_hash_map<std::string, nlohmann::json> devices; // MAC address + JSON object for each device(an element in paradoxdevices.json)
extern std::shared_mutex devicesMutex;
extern int reportTimeout; // in seconds
extern unsigned int allowedUnits; // maximum number of allowed LAMPAD-X units

// latest
extern nlohmann::json latest, topology;
extern std::mutex latestMutex;
extern ankerl::unordered_dense::map<std::pair<std::string, std::string>, int> latestIndex; // <MAC address + test name> + index for /paradox/latest. this should be separately managed, since there can be mismatches with test profile list(e.g. new test is added)
extern std::mutex latestIndexMutex;
void updateLatest();
ankerl::unordered_dense::map<std::pair<std::string, std::string>, int> newLatestIndex(const std::string &rawJson); // update index for /paradox/latest
}; // namespace Paradox

#endif // PARADOX_H
