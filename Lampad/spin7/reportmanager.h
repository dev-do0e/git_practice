#ifndef REPORTMANAGER_H
#define REPORTMANAGER_H

#include "feedrefinerabstract.h"
#include "../loghandler.h"
#include "../supercodex.h"

#include <ankerl/unordered_dense.h>
#include <nlohmann/json.hpp>
#include <civetweb.h>
#include <yyjson.h>

#include <shared_mutex>
#include <array>

namespace ReportManager {
// startup
void start();

// create reports
void postReport(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
std::string registerNewJob(const uint32_t id, const int mode, const std::string &username, const std::string &ip, const std::string &filenamePrefix, const std::string &options);
void generateReports();
void registerRepeated();

// report management: enumerate, download, and delete
enum Status { PENDING, ONGOING, REPORTGENERATED, OOPS };
extern std::shared_mutex reportMutex;
void getReport(mg_connection *connection, const std::string &id, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void deleteReport(mg_connection *connection, const std::string &id);

// report data generation
void generateRawData(const std::string &optionsString, const std::string &rawDataFileName);
nlohmann::json generateBps(SuperCodex::Conditions conditions);
nlohmann::json generatePeak(SuperCodex::Conditions conditions);
nlohmann::json generatePps(SuperCodex::Conditions conditions);
nlohmann::json generateIcmp(SuperCodex::Conditions conditions);
nlohmann::json generatePort(SuperCodex::Conditions conditions);
nlohmann::json generateDns(SuperCodex::Conditions conditions);
nlohmann::json generateHttpErrors(SuperCodex::Conditions conditions);
// "usage" and "bps-peak" rely on single Top N Bytes
nlohmann::json generateTopNBytes(SuperCodex::Conditions conditions);

// for Top N for TCP events, we always build data for everything and cherry-pick data as needed
nlohmann::json generateTcpZeroWindows(const SuperCodex::Conditions &conditions);
nlohmann::json generateTcpRetransmissions(const SuperCodex::Conditions &conditions);
nlohmann::json generateTcpDupAcks(const SuperCodex::Conditions &conditions);
nlohmann::json generateTcpResets(const SuperCodex::Conditions &conditions);
nlohmann::json generateTcpOutOfOrders(const SuperCodex::Conditions &conditions);

// utilities for cherry-picking data from Top N ranking for all
nlohmann::json buildTcpPage(const std::array<nlohmann::json, 5> &topNForAll, const SuperCodex::Conditions &conditions, const size_t mainRanking);
nlohmann::json generateFilteredTopN(const nlohmann::json &topNForAll, const SuperCodex::Conditions &conditions);
uint64_t extractCount(const std::string &ip, const std::string &ip2, const nlohmann::json &tcpTopNAll);
nlohmann::json extractOnlyN(const nlohmann::json &source, const int maxRanking);

// refiner control
FeedRefinerAbstract *refine(SuperCodex::Conditions &conditions);
SuperCodex::Conditions conditionsForAll(const SuperCodex::Conditions &originalCondition);
////

// JSON data type conversion
nlohmann::json fromYyjson(yyjson_mut_doc *document);

// miscellany
extern Logger logger;

} // namespace ReportManager

#endif // REPORTMANAGER_H
