#ifndef FEEDREFINERABSTRACT_H
#define FEEDREFINERABSTRACT_H

#include <thread>

#include <nlohmann/json.hpp>
#include <ankerl/unordered_dense.h>
#include <tbb/concurrent_hash_map.h>
#include <tbb/partitioner.h>
#include <yyjson.h>

#include "../loghandler.h"
#include "../supercodex.h"
#include "civetweb.h"
#include "subsystems.h"

using namespace std::string_literals;

class FeedRefinerAbstract
{
public:
    FeedRefinerAbstract(const std::string &messyRoomName, const SuperCodex::Conditions &conditions);
    virtual ~FeedRefinerAbstract();

    // processing SuperCodex files
    SuperCodex::Conditions conditions;
    void consumeCodices(std::vector<SuperCodex::Loader *> &codices, const bool isFinalLap);

    // result delivery and descriptions
    bool isStreaming = false; // is the refiner working as streaming?
    time_t lastAccess = time(nullptr); // used to determine whether this result hasn't been accessed for quite a time beyond timeout
    void resultTimeFrame(uint32_t &from, uint32_t &to);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) = 0;
    virtual void dumpResults(mg_connection *connection) = 0;
    yyjson_mut_doc *lastInterativeResult = nullptr;

    // SuperCache management
    std::vector<std::string> codicesToLoad(SuperCodex::Conditions &conditions);
    std::string superCachePath; // if empty, SuperCache can't be used or target file is not yet determined
    SuperCodex::ChapterType cachedChapter = static_cast<SuperCodex::ChapterType>(0);
    enum PmpiCacheMode { NONE, FULL, FILTERED } pmpiCacheMode = PmpiCacheMode::NONE; // cache mode for SuperCache PMPI

    // interface for HTTP PUT
    virtual void put(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> parameters);

    // some environmental variables
    static size_t maxPayloadSizeForRegex;
    static int64_t trafficThrottle;
    static std::string messyRoom;

    // utility: date manipulation
    static std::string epochToIsoDate(const time_t epochTime, const char *format = "%Y-%m-%dT%H:%M:%S");

    // utility: parsing remarks chapter
    static std::string remarksValue(const std::string_view &remarks, const std::string &key);
    static std::string remarksValueHttpHeader(const std::string_view &remarks, const std::string &key);

    // handling per second statistics
    struct TimeValuePair
    {
        uint32_t second = 0;
        int64_t value = 0;
    };
    static constexpr size_t timeValuePairSize = sizeof(TimeValuePair);

    // handling RTT
    struct ValuesRtt
    {
        uint64_t sessionId;
        uint64_t numerator0 = 0, numerator1 = 0, denominator0 = 0, denominator1 = 0, bytes = 0;
        ValuesRtt &operator+=(const ValuesRtt &b)
        {
            if (b.numerator0 >= 0 && b.numerator1 >= 0) {
                this->numerator0 += b.numerator0;
                this->numerator1 += b.numerator1;
                this->denominator0 += b.denominator0;
                this->denominator1 += b.denominator1;
                this->bytes += b.bytes;
            }
            return *this;
        }
        uint64_t represent() const { return (denominator0 ? numerator0 / denominator0 : 0) + (denominator1 ? numerator1 / denominator1 : 0); }
    };
    static constexpr size_t valuesRttSize = sizeof(ValuesRtt);

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) = 0;
    virtual void finalize() = 0; // run only once in final lap. at least secondStart and secondEnd should be set
    std::string messyRoomName, messyRoomPrefix;
    std::thread mergeFuture;

    // merge session and update refinery time frame: linear / recommended if reading from map is random
    ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session> *sessions = nullptr;
    void updateTimestampAndMergeSessions(const std::vector<SuperCodex::Session> &toMerge);
    void updateTimestampAndMergeIndividualSession(const SuperCodex::Session &sessionToMerge); // used to speed up Top N

    // merge session and update refinery time frame: concurrent / recommended if reading from map is sequential
    tbb::concurrent_hash_map<uint64_t, SuperCodex::Session> sessions2;
    void mergeSession(const SuperCodex::Session *session);
    void updateTimestamp();

    // support members for standard "binding"
    void summarize(mg_connection *connection, const std::string &fileName, const int32_t bindValue);
    void rankingPerSecond(mg_connection *connection, const std::string &fileName, const int32_t ranksToInclude);
    void minAndMax(mg_connection *connection, const std::string &fileName);

    // utilities to describe source and destination(IP, port, tags, port descriptions)
    void describeEdge(SubSystems::FqdnGetter &getter, yyjson_mut_doc *document, yyjson_mut_val *object, const std::string &ip, const uint16_t port = 0);
    void describeEdge(SubSystems::FqdnGetter &getter, std::string &result, const std::string &ip, const uint16_t port = 0);
    SuperCodex::IpFilter userDefinedAppsCopy;

    // miscellany
    bool jobIsDone = false;
    uint32_t secondStart = UINT32_MAX, secondEnd = 0; // used on resultTimeFrame()
    tbb::affinity_partitioner affinityPartitioner;

    // logger
    Logger logger;
};

#endif // FEEDREFINERABSTRACT_H
