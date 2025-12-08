#ifndef FEEDREFINERBASIC_H
#define FEEDREFINERBASIC_H

#include "feedrefinerabstract.h"

class FeedRefinerPerSecondStatistics : public FeedRefinerAbstract
{
public:
    FeedRefinerPerSecondStatistics(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    ~FeedRefinerPerSecondStatistics();
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

    // buffer to save data
    TimeValuePair *buffer = nullptr;
    size_t bufferSize;

    // supercache
    uint32_t superCacheSignature = 0;

private:
    // data extraction
    std::vector<TimeValuePair> (*readData)(const SuperCodex::Loader *) = nullptr;
    static std::vector<TimeValuePair> readBps(const SuperCodex::Loader *codex);
    static std::vector<TimeValuePair> readTimeouts(const SuperCodex::Loader *codex);
    static std::vector<TimeValuePair> readTcpRsts(const SuperCodex::Loader *codex);
    static std::vector<TimeValuePair> readTcpZeroWindows(const SuperCodex::Loader *codex);
    static std::vector<TimeValuePair> readTcpDupAcks(const SuperCodex::Loader *codex);
    static std::vector<TimeValuePair> readTcpRetransmissions(const SuperCodex::Loader *codex);
    static std::vector<TimeValuePair> readTcpPortsReused(const SuperCodex::Loader *codex);
    static std::vector<TimeValuePair> readTcpOutOfOrders(const SuperCodex::Loader *codex);
    std::string mode;
};

class FeedRefinerBps2 : public FeedRefinerAbstract
{
public:
    FeedRefinerBps2(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    struct Stats
    {
        uint32_t second;
        uint64_t ingress, egress, local, other;
        constexpr Stats &operator+=(const Stats &b)
        {
            this->ingress += b.ingress;
            this->egress += b.egress;
            this->local += b.local;
            this->other += b.other;
            return *this;
        };
    };
    SuperCodex::IpFilter internalIps;
    Stats *final;
    size_t finalSize;
};

class FeedRefinerPps : public FeedRefinerPerSecondStatistics
{
public:
    FeedRefinerPps(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

    // data structure, which is also used in SuperCache
    struct Description
    {
        int64_t unknown = 0, broadcast = 0, multicast = 0, unicast = 0;
        Description &operator+=(const Description &b)
        {
            this->unknown += b.unknown;
            this->broadcast += b.broadcast;
            this->multicast += b.multicast;
            this->unicast += b.unicast;
            return *this;
        }
        Description &operator-=(const Description &b)
        {
            this->unknown -= b.unknown;
            this->broadcast -= b.broadcast;
            this->multicast -= b.multicast;
            this->unicast -= b.unicast;
            return *this;
        }
    };
    struct ResultRecord
    {
        uint32_t second = 0;
        Description values;
    } last; // "last" is used to temporarily save value for potentially partial data for last second, whose remaining part can be found in successive codex(e.g. first 0.3 second is saved on the codex before and remaining 0.7 second is saved on the other)
    static constexpr size_t resultRecordSize = sizeof(ResultRecord);

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    // MAC filter
    ankerl::unordered_dense::set<std::string> ignoreMac;
    ResultRecord *buffer;
    size_t bufferSize;

    // supercache
    uint32_t superCacheSignature = 0;
};

class FeedRefinerLatency : public FeedRefinerPerSecondStatistics
{
public:
    FeedRefinerLatency(const std::string messyRoomName, const SuperCodex::Conditions &conditions);

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    // buffer to save data
    std::pair<uint32_t, ValuesRtt> *buffer = nullptr;
    size_t bufferSize;
};

class FeedRefinerFlowCounts : public FeedRefinerPerSecondStatistics
{
public:
    FeedRefinerFlowCounts(const std::string messyRoomName, const SuperCodex::Conditions &conditions);

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    struct Intermediate
    {
        uint32_t from, to;
        std::vector<int64_t> counters;
        std::vector<uint64_t> sessionsInTails;
        ankerl::unordered_dense::set<uint64_t> sessionsFromHeads;
    };
    uint32_t timestampFromLastTail = 0;
    std::vector<uint64_t> sessionsInLastTails;
};

class FeedRefinerMicroBurst : public FeedRefinerAbstract
{
public:
    FeedRefinerMicroBurst(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    struct Intermediate
    {
        ankerl::unordered_dense::map<uint64_t, ankerl::unordered_dense::map<uint64_t, std::pair<long long, long long>>> counters, firsts, lasts; // nanosecond level timestamp + session information + <from small to big + from big to small>
        std::vector<SuperCodex::Session> sessions;
    };
    ankerl::unordered_dense::map<uint64_t, ankerl::unordered_dense::map<uint64_t, std::pair<long long, long long>>> *merged, *partial; // merged: save Intermediate::counters, partial: accumulate Intermediate::firsts and Intermediate::lasts

    // configuration variables
    long long divider = 1000000; // in ms
    long long threshold = 175000; // 1.4Mbits(=1400000/8)

    // for final result
    void flushMerged();
    struct ResultRecord
    {
        char ips[32];
        uint16_t serverPort;
        int8_t ipLength;
        int64_t clientToServer, serverToClient;
    };
    static constexpr size_t resultRecordSize = sizeof(ResultRecord);
    std::vector<std::pair<long long, long long>> burstedTimePoints; // nanosecond level timestamp(=filename) + sum
};

class FeedRefinerRaw : public FeedRefinerAbstract
{
public:
    FeedRefinerRaw(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;
    virtual void put(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    // data structure for packet hashes
    struct PacketHash
    {
        int32_t index;
        uint16_t fromSmallToBig; // fromSmallToBig is originally int8_t. this design is to remove any paddings with garbage values
        enum Status : uint16_t { NORMAL, LOST } status;
        uint64_t hash, sessionId;
        int64_t timestamp;
    };
    static constexpr size_t packetHashSize = sizeof(PacketHash);
    PacketHash packetHash(const SuperCodex::Packet *packet);
    bool buildPacketHash = false;
    std::mutex packetHashMutex;
    struct PacketHashProfile
    {
        uint32_t from, to;
        std::string name;
    };
    std::vector<PacketHashProfile> packetHashFiles;
    void processPacketHash(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> parameters);
    SuperCodex::Glyph decompressPacketHash(const std::string &compressed, int32_t *from = nullptr, int32_t *to = nullptr, std::string *fileName = nullptr);
    std::mutex hashCompareMutex;

    // intermediary data structure(extraction from SuperCodex)
    struct Intermediary
    {
        int32_t from, to;
        std::vector<SuperCodex::Session> sessions;
        std::vector<PacketHash> hashedPackets;
        std::string fileName;
    };

    // read chapters from SuperCodex file
    ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session> sessionStore;
    std::string chapterPackets(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters);
    std::string chapterSessions(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters);
    std::string chapterBpsPerSession(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters);
    std::string chapterPpsPerSession(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters);
    std::string chapterRtts(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters);
    std::string chapterTimeouts(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters);
    std::string chapterRemarks(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters);
    std::string chapterTcpSyns(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters);
    std::string chapterTcpRsts(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters);
    std::string chapterTcpMiscAnomalies(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters);
    std::string chapterTcpRetransmissions(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters);
    std::string chapterTcpDupAcks(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters);
};

#endif // FEEDREFINERBASIC_H
