#ifndef SVCD_H
#define SVCD_H

#include "subsystems.h"
#include "../loghandler.h"
#include "../supercodex.h"

#include <civetweb.h>
#include <ankerl/unordered_dense.h>
#include <mutex>
#include <array>

namespace ServiceDashboard {
// startup
void start();

// reading raw SuperCodex
struct DataPackFromRaw
{
    unsigned long long bps[600]{};
    ankerl::unordered_dense::map<std::string, unsigned long long[600]> activeClients;
};
ankerl::unordered_dense::map<std::string, DataPackFromRaw> dataFromRaw(const std::string &feedName, const uint32_t last, const ankerl::unordered_dense::map<std::string, SubSystems::Thresholds> &thresholds, const SuperCodex::IpFilter &clientIpGroups, const SuperCodex::IpFilter &services);

// reading SuperCache
ankerl::unordered_dense::map<std::string, std::array<std::pair<uint64_t, uint64_t>, 5>> readPmpi(const std::string &feedName, const uint32_t last, const int32_t chapter, const SuperCodex::IpFilter &ipFilter);

// generated dashboard data
extern std::vector<std::pair<std::string, std::string>> jsonStrings; // data feed name + current service dashboard data
extern std::mutex jsonStringMutex;
void getSvcd(mg_connection *connection, const std::string &feedName);

// client IP groups
extern std::mutex clientIpGroupsMutex;
void postSvcdCips(mg_connection *connection, ankerl::unordered_dense::map<std::string, std::string> &parameters);
void getSvcdCips(mg_connection *connection);

// miscellany
SuperCodex::IpFilter buildClientIpGroups();
extern Logger logger;
} // namespace ServiceDashboard

#endif
