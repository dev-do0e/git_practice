#ifndef SUBSYSTEMS_H
#define SUBSYSTEMS_H

#include <mutex>
#include <shared_mutex>
#include <civetweb.h>
#include <ankerl/unordered_dense.h>
#include <nlohmann/json.hpp>
#include "../loghandler.h"
#include "../featherlite.h"
#include "../supercodex.h"

// forward declarations
namespace SuperCache {
struct PmpiTriplet;
}

namespace SubSystems {
// extern variable(s)
extern Logger logger;

// initialize
void initialize();

// system management
extern std::string spin4Version, spin7Version;
void getVersion(mg_connection *connection);
void postUpdate(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void getSysInfo(mg_connection *connection);

// remote upgrade backend
void postRupdate(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void getRupdate(mg_connection *connection);
void patchRupdate(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void deleteRupdate(mg_connection *connection, const std::string &path);

// get logs from outside sources
void getSyslog(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void getSyslogDefault(mg_connection *connection, FeatherLite &feather);
void getSyslogSummary(mg_connection *connection, FeatherLite &feather);
void getSyslogTabSeparted(mg_connection *connection, FeatherLite &feather);
void getSnmpTrap(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void getSnmpTrapDefault(mg_connection *connection, FeatherLite &feather);
void getSnmpTrapSummary(mg_connection *connection, FeatherLite &feather);
void getSnmpTrapTabSeparted(mg_connection *connection, FeatherLite &feather);

// application management
struct Thresholds
{
    uint64_t rtt1 = 100000000, rtt2 = 300000000; // in nanoseconds
    uint8_t responseRate1 = 5, responseRate2 = 10, tcpRetransmission1 = 5, tcpRetransmission2 = 10, tcpZeroWindows1 = 5, tcpZeroWindows2 = 10;
};
extern size_t thresholdsSize;
extern std::mutex fqdnMutex;
extern std::shared_mutex userDefinedAppMutex;
extern SuperCodex::IpFilter userDefinedApps;
void initializeAppManagement();
// register / unregister user defined applications
void postApp(mg_connection *connection, const std::string &path, ankerl::unordered_dense::map<std::string, std::string> &parameters);
void getApp(mg_connection *connection, ankerl::unordered_dense::map<std::string, std::string> &parameters);
void deleteApp(mg_connection *connection, const std::string &path);
void updateUserDefinedApp();
// get application names
SuperCodex::IpFilter copyUserDefinedApp();
class FqdnGetter
{
public:
    FqdnGetter();
    std::vector<std::string> get(const std::string_view &ip);

private:
    FeatherLite feather;
};

// import PCAP
extern std::string importPcapPath;
void postImportPcap(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters); // upload individual PCAP file
void patchImportPcap(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters); // flush to specific data feed
void getImportPcap(mg_connection *connection); // enumerate currently uploaded PCAP files
void deleteImportPcap(mg_connection *connection, const std::string &path); // delete a file or all(as needed)

// report generation per working hours
struct WorkingHourCondition
{
    uint32_t from, to;
    bool weekdays[7], toBps = false;
    SuperCodex::ChapterType chapterToOpen;
    int hStartHour, hStartMinute, hEndHour, hEndMinute;
};
struct WorkingHourResult
{
    struct Stat
    {
        uint64_t sum, top;
        uint32_t topAt;
    };
    std::vector<std::pair<std::string, Stat>> records;
};
void getWorkingHoursReport(mg_connection *connection, const std::string feedName, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
WorkingHourResult getWorkingHoursReportByDay(const std::string &feedName, const WorkingHourCondition &condition);
WorkingHourResult getWorkingHoursReportPerTag(const std::string &feedName, const WorkingHourCondition &condition);
WorkingHourResult getWorkingHoursReportPerService(const std::string &feedName, const WorkingHourCondition &condition);
void getWorkingHoursReportReadDatabase(const std::string &feedName, const WorkingHourCondition &condition, std::function<void(const uint32_t, const SuperCache::PmpiTriplet &)> buildRecords);
} // namespace SubSystems

#endif // SUBSYSTEMS_H
