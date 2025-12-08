#ifndef SUPERCACHE_H
#define SUPERCACHE_H

#include "../loghandler.h"
#include "feedrefinerbasic.h"
#include "feedrefinertopn.h"
#include "feedrefinermain.h"
#include "feedrefinertrackers.h"
#include <ankerl/unordered_dense.h>

namespace SuperCache {
// environmental variable(s)
extern std::string feedPath;
extern uint32_t tlsDumpRetentionPeriod;

// startup
void start();

// database management
void initializeDatabase(const std::string &feedRoot, const std::vector<std::string> &dbFiles, const std::vector<std::string> &associatedDdls);
void checkpointDatabase(const std::vector<std::string> &dbFiles, const uint32_t dropMargin = 0); // database maintenance
extern std::vector<std::string> dbs, ddls;

// data structures
template<typename T> struct PmpiPack
{
    void reserve(const size_t newCapacity)
    {
        source.reserve(newCapacity);
        destination.reserve(newCapacity);
        ipToService.reserve(newCapacity);
    }

    ankerl::unordered_dense::map<FeedRefinerTopN::KeySingle, T, FeedRefinerTopN::KeySingleHash, FeedRefinerTopN::KeySingleEqual> source, destination;
    ankerl::unordered_dense::map<FeedRefinerTopN::KeyIpToService, T, FeedRefinerTopN::KeyIpToServiceHash, FeedRefinerTopN::KeyIpToServiceEqual> ipToService;
};

struct SingleIp
{
    uint8_t ip[16];
    uint8_t size;
    void fromString(const std::string &ipString) { memcpy(ip, ipString.data(), ipString.size()); };
    std::string toString() { return std::string((const char *) ip, size); };
    SingleIp(const std::string &ipString) { fromString(ipString); };
};
constexpr size_t singleIpSize = sizeof(SingleIp);

struct DnsSessionHeader
{
    uint64_t sessionId;
    uint32_t secondStart, secondEnd; // timestamps
    int64_t latency = 0;
    int32_t queryLength = 0; // to be used on serialization
    FeedRefinerDnsTracker::Status status;
    uint8_t ipLength;
    uint8_t ips[32];

    // utility functions
    static DnsSessionHeader fromDnsTrackerSessionRecord(const FeedRefinerDnsTracker::SessionRecord &record)
    {
        DnsSessionHeader result{record.sessionId, record.secondStart, record.secondEnd, record.latency, static_cast<int32_t>(record.query.size()), record.status, static_cast<uint8_t>(record.sourceIp.size()), {}};
        memcpy(result.ips, record.sourceIp.data(), result.ipLength);
        memcpy(result.ips + result.ipLength, record.destinationIp.data(), result.ipLength);
        return result;
    };
    void extractIps(std::string &sourceIp, std::string &destinationIp) const // source IP + destination IP
    {
        sourceIp = std::string((const char *) ips, ipLength);
        destinationIp = std::string((const char *) (ips + ipLength), ipLength);
    };
    FeedRefinerDnsTracker::SessionRecord toDnsTrackerSessionRecord() const
    {
        FeedRefinerDnsTracker::SessionRecord result{sessionId, secondStart, secondEnd, latency, status, {}, {}, {}, {}};
        extractIps(result.sourceIp, result.destinationIp);
        return result;
    };
};
constexpr size_t dnsSessionHeaderSize = sizeof(DnsSessionHeader);

struct TlsDump
{
    uint64_t sessionId;
    uint32_t timestamp;
    uint16_t clientPort, serverPort;
    std::string ips, sni;
};

struct Intermediate
{
    Intermediate()
    {
        // reserve some memory for better performance
        sessionsInTail.reserve(1000);
        sessionsFromHead.reserve(1000);
        bytes_n.reserve(50000);
        packets_n.reserve(50000);
        timeouts_n.reserve(50000);
        rsts_n.reserve(50000);
        dupAcks_n.reserve(50000);
        retransmissions_n.reserve(50000);
        zeroWindows_n.reserve(50000);
        portReused_n.reserve(50000);
        outOfOrders_n.reserve(50000);
        latencies_n.reserve(50000);
        tlsDumps.reserve(10000);
    }
    uint32_t from, to;

    // per second statistics
    std::vector<int64_t> bps, timeouts, rsts, dupAcks, retransmissions, zeroWindows, portReused, outOfOrders, flowCounts;
    std::vector<FeedRefinerPps::Description> pps;
    std::vector<FeedRefinerAbstract::ValuesRtt> rtts;
    // flow count special
    std::vector<uint64_t> sessionsInTail;
    ankerl::unordered_dense::set<uint64_t> sessionsFromHead;

    // per minute per IP statistics
    PmpiPack<uint64_t> bytes_n, packets_n; // value2 is volume of total transaction (unit: bytes, packets, ......)
    PmpiPack<std::pair<uint64_t, uint64_t>> timeouts_n, rsts_n, dupAcks_n, retransmissions_n, zeroWindows_n, portReused_n, outOfOrders_n; // value + value2 combination. most of the time value2 is just "number of related packets", while `timeouts_n` and `portReused_n` need number of sessions as value2
    PmpiPack<FeedRefinerAbstract::ValuesRtt> latencies_n;

    // per minute per IP: HTTP Errors specific
    std::vector<std::pair<uint64_t, std::string>> httpErrorOrphanedRequests; // session ID + < prefix + HTTP error description >
    std::vector<std::pair<uint64_t, std::string>> httpErrorOrphanedResponses; // session ID + HTTP status code
    ankerl::unordered_dense::map<std::string, uint64_t> httpErrors; // < prefix + HTTP error description > + counts

    // DNS Tracker
    ankerl::unordered_dense::map<uint64_t, FeedRefinerDnsTracker::SessionRecord> dnsRecords;
    std::vector<FeedRefinerDnsTracker::SessionRecord> dnsRequestOnly;
    std::vector<uint64_t> dnsTimeouts; // session IDs for timed out DNS requests

    // ICMP walk
    std::vector<FeedRefinerIcmpWalk::Description> icmps;

    // TLS dump
    ankerl::unordered_dense::map<uint64_t, TlsDump> tlsDumps;
};

struct Final
{
    Final(const uint32_t from)
    {
        this->from = from;
        // reserve some room for faster processing
        bytes_n.reserve(100000);
        packets_n.reserve(100000);
        timeouts_n.reserve(100000);
        rsts_n.reserve(100000);
        dupAcks_n.reserve(100000);
        retransmissions_n.reserve(100000);
        zeroWindows_n.reserve(100000);
        portReused_n.reserve(100000);
        outOfOrders_n.reserve(100000);
        latencies_n.reserve(100000);
    }
    uint32_t from;

    // per second statistics
    struct PerSecondPack
    {
        uint64_t bps[60], timeouts[60], rsts[60], dupAcks[60], retransmissions[60], zeroWindows[60], portReused[60], outOfOrders[60], flowCounts[60];
        FeedRefinerPps::ResultRecord pps[60];
        FeedRefinerAbstract::ValuesRtt rtts[60];
    } perSecondTotal{};

    // per minute per IP statistics
    PmpiPack<uint64_t> bytes_n, packets_n; // value2 is volume of total transaction (unit: bytes, packets, ......)
    PmpiPack<std::pair<uint64_t, uint64_t>> timeouts_n, rsts_n, dupAcks_n, retransmissions_n, zeroWindows_n, portReused_n, outOfOrders_n; // value + value2 combination. most of the time value2 is just "number of related packets", while `timeouts_n` and `tcpportreused_n` need number of sessions as value2
    PmpiPack<FeedRefinerAbstract::ValuesRtt> latencies_n;

    // per minute per IP: HTTP Errors specific
    ankerl::unordered_dense::map<uint64_t, std::string> httpErrorOrphanedRequests; // session ID + < prefix + HTTP error description >
    std::vector<std::pair<uint64_t, std::string>> httpErrorOrphanedResponses; // we need to save this too so that this data can be used to merge with orphaned requests from previous cache records or raw SuperCodex
    ankerl::unordered_dense::map<std::string, uint64_t> httpErrors; // < prefix + HTTP error description > + counts

    // DNS tracker
    struct DnsDescription
    {
        struct Usage
        {
            uint64_t hits, fastest, slowest, sum;
        };
        ankerl::unordered_dense::map<std::string, ankerl::unordered_dense::map<std::string, Usage>> details[5]; // DNS query + <deduplicated client IPs + hits and response times> per status(RESOLVED, ZEROANSWER, ANSWERBROKEN, MULTIPLEQUREIES, TIMEOUT)

        void mergeSessionRecord(const FeedRefinerDnsTracker::SessionRecord record)
        {
            // determine target data pack
            Usage *targetPack;
            switch (record.status) {
            case FeedRefinerDnsTracker::RESOLVED:
                targetPack = &details[0][record.query][record.sourceIp];
                break;
            case FeedRefinerDnsTracker::ZEROANSWER:
                targetPack = &details[1][record.query][record.sourceIp];
                break;
            case FeedRefinerDnsTracker::ANSWERBROKEN:
                targetPack = &details[2][record.query][record.sourceIp];
                break;
            case FeedRefinerDnsTracker::MULTIPLEQUERIES:
                targetPack = &details[3][record.query][record.sourceIp];
                break;
            case FeedRefinerDnsTracker::TIMEOUT:
                targetPack = &details[4][record.query][record.sourceIp];
                break;
            case FeedRefinerDnsTracker::REQUESTONLY:
                return; // ignore
            }

            // update data
            ++targetPack->hits;

            // update latency summary
            if (record.latency >= 0) {
                targetPack->sum += record.latency;
                if (record.latency > targetPack->slowest)
                    targetPack->slowest = record.latency;
                if (record.latency < targetPack->fastest)
                    targetPack->fastest = record.latency;
            }
        }
    };
    ankerl::unordered_dense::map<uint64_t, FeedRefinerDnsTracker::SessionRecord> dnsOrphanedRequests; // orphaned DNS sessions
    ankerl::unordered_dense::map<std::string, DnsDescription> dnsDescriptions; // performance statistics for each DNS server
    std::vector<uint64_t> dnsTimedoutSessions;

    // ICMP walk
    std::vector<FeedRefinerIcmpWalk::Description> icmpWalkDescriptions;

    // TLS dump
    std::vector<TlsDump> tlsDumpsHead, tlsDumps;
};
constexpr int32_t pmpiSizeSingle = sizeof(std::pair<FeedRefinerTopN::KeySingle, uint64_t>);
constexpr int32_t pmpiSizeIpToService = sizeof(std::pair<FeedRefinerTopN::KeyIpToService, uint64_t>);
constexpr int32_t pmpiSizeSingle2 = sizeof(std::pair<FeedRefinerTopN::KeySingle, std::pair<uint64_t, uint64_t>>);
constexpr int32_t pmpiSizeIpToService2 = sizeof(std::pair<FeedRefinerTopN::KeyIpToService, std::pair<uint64_t, uint64_t>>);
constexpr int32_t pmpiSizeSingleRtt = sizeof(std::pair<FeedRefinerTopN::KeySingle, FeedRefinerAbstract::ValuesRtt>);
constexpr int32_t pmpiSizeIpToServiceRtt = sizeof(std::pair<FeedRefinerTopN::KeyIpToService, FeedRefinerAbstract::ValuesRtt>);

struct HttpErrorHeader
{
    uint64_t value; // session ID, number of hits, etc., depending on the application
    int32_t descriptionLength; // by design LZ4 simple API supports up to 2GB (if my memory serves me correctly)
};
static constexpr size_t httpErrorHeaderSize = sizeof(HttpErrorHeader);

// actual cache builder
std::string buildCache(const std::string &feedName, const uint32_t from);
int compressAndFlushPmpi(const std::string &filePath, const PmpiPack<uint64_t> &rawData);
int compressAndFlushPmpi(const std::string &filePath, const PmpiPack<std::pair<uint64_t, uint64_t>> &rawData);
int compressAndFlushPmpi(const std::string &filePath, const PmpiPack<FeedRefinerAbstract::ValuesRtt> &rawData);
int compressAndFlushPmpiHttpErrors(const std::string &filePath, const Final &final);
int compressAndFlushDnsTracker(const std::string &filePath, const Final &final);
int compressAndFlushIcmpWalk(const std::string &filePath, const Final &final);

// utility functions
void addPair(std::pair<uint64_t, uint64_t> &a, const std::pair<uint64_t, uint64_t> &b);
struct PmpiTriplet
{
    char *decompressedRaw;
    std::string_view perSourceRaw, perDestinationRaw, perIpToServiceRaw;
};
SuperCache::PmpiTriplet getPmpiTriplet(const std::string &file, const size_t decompressedSize);

// logging
extern Logger logger;
} // namespace SuperCache

#endif
