#ifndef FEEDREFINERMAIN_H
#define FEEDREFINERMAIN_H

#include <string>
#include <utility>
#include <tbb/concurrent_set.h>

#include "feedrefinerabstract.h"
#include "../fnvhash.h"

class FeedRefinerDataStreams : public FeedRefinerAbstract
{
public:
    FeedRefinerDataStreams(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    size_t itemsCount = -1;
    struct Pack
    {
        std::vector<uint64_t> closedTcpSessions;
        ankerl::unordered_dense::map<uint64_t, std::string> payloads;
    };
    tbb::concurrent_hash_map<uint64_t, std::pair<int64_t, int64_t>> usage; // usage in bytes. session ID + < from small to big + from big to small >
    tbb::concurrent_hash_map<uint64_t, ValuesRtt> rtts; // accumulated RTT. session ID + < from small to big + from big to small >
    tbb::concurrent_set<uint64_t> timeouts; // sessions with declared timeouts. session ID only

    // result record
    struct ResultRecord
    {
        SuperCodex::Session session;
        int64_t fromClientToServer, fromServerToClient, rtt;
    };
    static constexpr size_t resultRecordLength = sizeof(ResultRecord);

    // applying regular expression
    std::string regex;
    bool trackPayload = false;

    // miscellany / internal functions
    void resultsSummary(mg_connection *connection);
};

class FeedRefinerServices : public FeedRefinerAbstract
{
public:
    FeedRefinerServices(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    struct RecordService
    {
        char ip[16];
        uint16_t port;
        int8_t ipLength;
        SuperCodex::Session::L7Protocol detectedL7;
        int64_t hitsOffset, numberOfClients;
    };
    static constexpr size_t recordServiceSize = sizeof(RecordService);
    struct RecordServiceHash
    {
        std::size_t operator()(RecordService const &record) const noexcept { return fnv64a(&record.port, 2, fnv64a(record.ip, record.ipLength)); }
    };
    struct RecordServiceEqual
    {
        bool operator()(const RecordService &a, const RecordService &b) const { return a.ipLength == b.ipLength && memcmp(a.ip, b.ip, a.ipLength) == 0 && a.port == b.port; }
    };

    struct RecordClient
    {
        char ip[16];
        int64_t hitCount;
        int8_t ipLength = 4; //default: IPv4
    };
    static constexpr size_t recordClientSize = sizeof(RecordClient);

    // hints for view
    size_t servicesCount[4]; // IPv4 TCP, IPv4 UDP, IPv6 TCP, IPv6 UDP
};

class FeedRefinerMacsPerIp : public FeedRefinerAbstract
{
public:
    FeedRefinerMacsPerIp(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    ankerl::unordered_dense::map<std::string, ankerl::unordered_dense::set<std::string>> *pairs; // IP + associated MAC addresses
    int64_t ipsFound = 0;
    struct RecordIp
    {
        char ip[16];
        int64_t numberOfMacs;
        int8_t ipLength = 4; //default: IPv4
    };
    static constexpr size_t recordIpSize = sizeof(RecordIp);
};

class FeedRefinerOverview : public FeedRefinerAbstract
{
public:
    FeedRefinerOverview(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;
    int64_t buildResult(const ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session> *sessionsToGo, const ankerl::unordered_dense::segmented_map<uint64_t, std::pair<int64_t, int64_t>> *valuesToGo, std::function<std::string(const SuperCodex::Session &)> extractIp, const std::string &portsFileName, const std::string &descriptionsFileName);
    ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> readSuperCachePmpi(std::function<void(const std::string_view &, ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> &)> insertByteCount, std::function<void(const std::string_view &, ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> &)> insertPacketCount);

private:
    std::string gatherBy;
    // raw data
    struct Pack
    {
        uint32_t secondStart = UINT32_MAX, secondEnd = 0;
        ankerl::unordered_dense::set<uint64_t> tcpSessionsIndex, udpSessionsIndex;
        std::vector<SuperCodex::Session> tcpSessions, udpSessions;
        ankerl::unordered_dense::segmented_map<uint64_t, std::pair<int64_t, int64_t>> tcpValues, udpValues; // bytes + packets
    };

    // data merging
    long long totalBytes = 0, totalPackets = 0;
    ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session> *udpSessions;
    ankerl::unordered_dense::segmented_map<uint64_t, std::pair<int64_t, int64_t>> tcpValues, udpValues; // bytes + packets

    // result
    struct RecordPort
    {
        uint16_t port;
        int64_t ipOffset, numberOfIps;
    };
    static constexpr size_t recordPortSize = sizeof(RecordPort);
    struct RecordDescription
    {
        char ip[32];
        int64_t bytes, packets;
        int64_t ipLength;
    };
    static constexpr size_t recordDescriptionSize = sizeof(RecordDescription);

    // hints for view
    size_t tcpRecords = 0, udpRecords = 0;

    // for summary for reporting
    void resultsInteractiveSummary(mg_connection *connection);
};

class FeedRefinerLowHopLimits : public FeedRefinerAbstract
{
public:
    FeedRefinerLowHopLimits(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    int base = 5;
    struct Pack
    {
        ankerl::unordered_dense::set<uint64_t> sessionsIndex;
        std::vector<SuperCodex::Session> sessions;
        std::vector<SuperCodex::Packet> packets;
    };
    int64_t numberOfItems = 0;

    // result
    struct Record
    {
        SuperCodex::Session session;
        SuperCodex::Packet packet;
    };
    static constexpr size_t recordSize = sizeof(Record);
    struct RecordRanking
    {
        char ip[32];
        int8_t ipLength;
        int64_t hits;
    };
    static constexpr size_t recordRankingSize = sizeof(RecordRanking);
};

class FeedRefinerIcmpWalk : public FeedRefinerAbstract
{
public:
    FeedRefinerIcmpWalk(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;
    // data structure to describe individual ICMP packet. The same structure is used for both this class and SuperCache
    struct Description
    {
        // base packet description
        uint8_t ips[32]; // the direction must be always source->destination, not vice versa. if needed, swap
        uint8_t ipLength, type, code; // length for ipsOriginal should be same as the ICMP packet itself(i.e. ICMP vs. ICMPv6)
        uint32_t timestamp;

        // description for original packet which evoked this ICMP packet(mostly from type 3=destination unreachable)
        uint8_t ipsOriginal[32]; // data starting with 0x0000 is considered invalid = no data for original packet
        uint16_t port, port2;
        uint8_t payloadProtocol;

        // utility functions
        std::string_view sourceIp() const { return std::string_view((const char *) ips, ipLength); }
        std::string_view destinationIp() const { return std::string_view((const char *) (ips + ipLength), ipLength); }
        std::string_view sourceIpOriginal() const { return std::string_view((const char *) ipsOriginal, ipLength); }
        std::string_view destinationIpOriginal() const { return std::string_view((const char *) (ipsOriginal + ipLength), ipLength); }
    };
    static constexpr size_t descriptionSize = sizeof(Description);
    typedef ankerl::unordered_dense::map<std::pair<int8_t, int8_t>, std::vector<Description>> Intermediate; // <type+code> + packet description

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    bool isForV4 = true;
    std::string indexJson;
    ankerl::unordered_dense::map<std::pair<uint8_t, uint8_t>, ankerl::unordered_dense::map<std::pair<std::string, std::string>, uint64_t>> summary;
    Intermediate tails;
    std::function<Intermediate(const SuperCodex::Loader *)> buildIntermediate;
    static Intermediate buildIntermediateV4(const SuperCodex::Loader *codex);
    static Intermediate buildIntermediateV6(const SuperCodex::Loader *codex);
    void writeIntermediate(const std::pair<std::pair<int8_t, int8_t>, std::vector<Description>> &pair);
};

#endif // FEEDREFINERMAIN_H
