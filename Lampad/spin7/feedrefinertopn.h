#ifndef FEEDREFINERTOPN_H
#define FEEDREFINERTOPN_H

#include "feedrefinerabstract.h"
#include "../fnvhash.h"

class FeedRefinerTopN : public FeedRefinerAbstract
{
public:
    FeedRefinerTopN(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    yyjson_mut_doc *resultsInteractive(uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters);
    virtual void dumpResults(mg_connection *connection) override;

    // environmental variables
    static int64_t greedFactorProto;

    // data structure for result
    struct Description
    {
        uint64_t value, value2; // there can be things more
        Description &operator+=(const Description &b)
        {
            this->value += b.value;
            this->value2 += b.value2;
            return *this;
        }
    };
    static constexpr size_t descriptionSize = sizeof(Description);

    // data structures for one way(per source or per destination)
    struct KeySingle
    {
        uint16_t port;
        uint8_t ipLength;
        uint8_t ip[16];
    };
    static constexpr size_t oneWaySize = sizeof(KeySingle);
    struct KeySingleHash
    {
        std::size_t operator()(KeySingle const &key) const noexcept { return fnv64a(&key.port, 2, fnv64a(key.ip, key.ipLength)); }
    };
    struct KeySingleEqual
    {
        bool operator()(const KeySingle &a, const KeySingle &b) const { return a.ipLength == b.ipLength && a.port == b.port && memcmp(a.ip, b.ip, a.ipLength) == 0; }
    };
    // data structures for IP-to-service
    struct KeyIpToService
    {
        char ip1[16], ip2[16];
        int8_t ipLength;
        uint16_t port2;
        int8_t direction; // 1: client to server, 0: server to client
        uint8_t payloadProtocol;
        SuperCodex::Session::L7Protocol detectedL7;
    };
    static constexpr size_t keyIpToServiceSize = sizeof(KeyIpToService);
    struct KeyIpToServiceHash
    {
        std::size_t operator()(KeyIpToService const &key) const noexcept { return fnv64a(key.payloadProtocol, fnv64a(key.direction, fnv64a(&key.port2, 2, fnv64a(key.ip2, key.ipLength, fnv64a(key.ip1, key.ipLength))))); }
    };
    struct KeyIpToServiceEqual
    {
        bool operator()(const KeyIpToService &a, const KeyIpToService &b) const { return a.ipLength == b.ipLength && memcmp(a.ip1, b.ip1, a.ipLength) == 0 && memcmp(a.ip2, b.ip2, a.ipLength) == 0 && a.port2 == b.port2 && a.direction == b.direction && a.payloadProtocol == b.payloadProtocol; }
    };

    // utility function to generate keys
    static KeyIpToService keyIpToServiceFromSession(const SuperCodex::Session &session);
    static KeySingle sourceFromIpToService(const KeyIpToService &key);
    static KeySingle destinationFromIpToService(const KeyIpToService &key);

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;
    struct Pack
    {
        ankerl::unordered_dense::map<KeySingle, Description, KeySingleHash, KeySingleEqual> perSource, perDestination;
        ankerl::unordered_dense::map<KeyIpToService, Description, KeyIpToServiceHash, KeyIpToServiceEqual> perIpToService;
    };
    template<typename T> std::vector<T> mergeSuperCache(const int chapterType, std::function<void(const std::string_view &, const std::string_view &, const std::string_view &, T &)> toMerge); // helper for finalize()
    void mergeCacheSingle(const std::string_view &perSourceRaw, const std::string_view &perDestinationRaw, const std::string_view &perIpToServiceRaw, Pack &pack);
    void mergeCachePair(const std::string_view &perSourceRaw, const std::string_view &perDestinationRaw, const std::string_view &perIpToServiceRaw, Pack &pack);
    template<typename T> void processResultFile(const std::string &fileName, std::function<bool(const T &content)> process);

    // hints and descriptions
    size_t sizePerSource, sizePerDestination, sizePerIpToService;
    std::string base;

    // save to and load from disk structure
    template<typename T> void saveRanking(const std::vector<T> &ranking, const std::string &fileName);

    // greed factor
    uint64_t greedFactor;

private:
    // data structure used in both intermediary and final
    Pack *total = nullptr;
    std::vector<std::pair<KeySingle, Description>> buildRanking(const ankerl::unordered_dense::map<KeySingle, Description, KeySingleHash, KeySingleEqual> &map);
    std::vector<std::pair<KeyIpToService, Description>> buildRankingIpToService(const ankerl::unordered_dense::map<KeyIpToService, Description, KeyIpToServiceHash, KeyIpToServiceEqual> &map);

    // data gatherers per "base"
    Pack (FeedRefinerTopN::*gatherData)(const SuperCodex::Loader *) = nullptr;
    Pack gatherBytes(const SuperCodex::Loader *codex);
    Pack gatherPackets(const SuperCodex::Loader *codex);
    Pack gatherTimeouts(const SuperCodex::Loader *codex);
    Pack gatherTcpRsts(const SuperCodex::Loader *codex);
    Pack gatherTcpDupAcks(const SuperCodex::Loader *codex);
    Pack gatherTcpZeroWindows(const SuperCodex::Loader *codex);
    Pack gatherTcpRetransmissions(const SuperCodex::Loader *codex);
    Pack gatherTcpOutOfOrders(const SuperCodex::Loader *codex);
    Pack gatherTcpPortsReused(const SuperCodex::Loader *codex);

    // utility functions to fill "value2" with PPSPERSESSION
    void fillPpsSource(const SuperCodex::Loader *codex, ankerl::unordered_dense::map<KeySingle, Description, KeySingleHash, KeySingleEqual> &map, const bool isSource);
    void fillPpsIpToService(const SuperCodex::Loader *codex, ankerl::unordered_dense::map<KeyIpToService, Description, KeyIpToServiceHash, KeyIpToServiceEqual> &map);
};

class FeedRefinerTopNLatencies : public FeedRefinerTopN
{
public:
    FeedRefinerTopNLatencies(const std::string messyRoomName, const SuperCodex::Conditions &conditions);

    // static variables
    static int64_t rttIgnoreFrom;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    // raw data
    struct Pack
    {
        Pack()
        {
            sessions.reserve(100000);
            values.reserve(100000);
        }
        std::vector<SuperCodex::Session> sessions;
        ankerl::unordered_dense::segmented_map<uint64_t, ValuesRtt> values;
    };
    struct ValuesIpToService
    {
        ValuesRtt values;
        SuperCodex::Session::L7Protocol detectedL7 = SuperCodex::Session::NOL7DETECTED;
    };
    static constexpr size_t valuesIpToServiceSize = sizeof(ValuesIpToService);
    void fillSessions(const SuperCodex::Loader *codex, Pack &pack);

    // ranking utility
    std::vector<std::pair<KeySingle, ValuesRtt>> buildRanking(const ankerl::unordered_dense::map<KeySingle, ValuesRtt, KeySingleHash, KeySingleEqual> &map);
    std::vector<std::pair<KeyIpToService, ValuesIpToService>> buildRankingIpToService(const ankerl::unordered_dense::map<KeyIpToService, ValuesIpToService, KeyIpToServiceHash, KeyIpToServiceEqual> &map);
};

class FeedRefinerTopNHttpErrors : public FeedRefinerTopN
{
public:
    FeedRefinerTopNHttpErrors(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

    // utlity functions
    static std::string buildDescription(const std::string_view &raw, const std::string &h, const uint16_t serverPort); // "description" = 000 + full URL + server IP in human readable format

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;
    void mergeSuperCache(const int chapterType, std::function<void(const std::string_view &, const std::string_view &, const std::string_view &)> toMerge); // specialized for HTTP Errors

private:
    // std::pair<std::string, std::string>: description + source IP
    struct IntermediatePack
    {
        std::vector<std::pair<std::string, std::string>> fullErrors; // "description" + source IP
        std::vector<std::pair<uint64_t, std::pair<std::string, std::string>>> orphanedRequests; // session ID + <"description" + source IP>
        std::vector<std::pair<uint64_t, std::string>> orphanedResopnses; // session ID + 3-digit HTTP status code(=always 3 bytes)
    };
    struct SummaryHeader
    {
        uint64_t totalHits, descriptionHash; // descriptionHash is used as filename for hit details(hits per source IP)
        uint32_t descriptionSize;
    };
    static constexpr size_t summaryHeaderSize = sizeof(SummaryHeader);

    ankerl::unordered_dense::map<uint64_t, std::pair<std::string, std::string>> *orphanedRequests; // session ID + <"description" + source IP>
    ankerl::unordered_dense::map<std::string, ankerl::unordered_dense::map<std::string, uint64_t>> *merged; // "description" + <source IP + hits>
};

class KeyIpToServiceFilter
{
public:
    KeyIpToServiceFilter(const SuperCodex::Conditions &conditions);
    bool isIpFilterOnly;
    bool accept(const FeedRefinerTopN::KeyIpToService &header) const;

private:
    const SuperCodex::Conditions &conditions;
};
#endif // FEEDREFINERTOPN_H
