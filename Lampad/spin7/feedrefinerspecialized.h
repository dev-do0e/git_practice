#ifndef FEEDREFINERSPECIALIZED_H
#define FEEDREFINERSPECIALIZED_H

#include "feedrefinerabstract.h"
#include "../featherlite.h"

#include <optional>
#include <shared_mutex>
#include <thread>
#include <atomic>

class FeedRefinerHttt : public FeedRefinerAbstract
{
public:
    FeedRefinerHttt(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    struct Description
    {
        // metadata
        std::string sourceIp, destinationIp;
        unsigned short destinationPort;
        uint64_t sessionId, requestAt, responseAt;
        // information from request
        std::string method, host, path, referer, userAgent;
        // information from response
        unsigned short statusCode;
        bool isHtml = false;
    };
    struct Intermediate
    {
        std::vector<Description> responsesOnly, requestsOnly, fullDescriptions;
    };
    ankerl::unordered_dense::map<uint64_t, Description> *requestsOnly;
    ankerl::unordered_dense::map<std::string, std::string> *refererChain; // original URL+referer URL without protocol scheme(i.e. http://). only non-HTML URLs are stored
    std::vector<std::string> sourceIps;

    // utility functions
    Description fillRequest(const std::string_view &header, SuperCodex::Session *session);
    static void fillResponse(Description &description, const std::string_view &header);
    static std::string descriptionToRecord(const Description &description);
    static yyjson_mut_val *lineToJsonObject(yyjson_mut_doc *document, const std::string &sourceIp, const std::string &line, std::string &url, std::string &referer, yyjson_mut_val *&entryForChildren);
    static yyjson_mut_val *blankJsonObject(yyjson_mut_doc *document, const std::string &sourceIp, std::string &url, yyjson_mut_val *&entryForChildren);
    std::string root(const Description &description);
    static std::string extractRootUrl(const std::string &rawData);
};

class FeedRefinerJitter : public FeedRefinerAbstract
{
public:
    FeedRefinerJitter(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    // data gathering
    struct Intermediate
    {
        std::vector<SuperCodex::Session> sessions;
        struct RttRecord
        {
            std::vector<int64_t> fromSmallToBig, fromBigToSmall;
            int64_t totalPackets = 0;
            ankerl::unordered_dense::set<std::string> macSmall, macBig;
        };
        ankerl::unordered_dense::map<uint64_t, RttRecord> rtts; // session ID+<timestamps, from small to big + timestamps, from big to small>
    };
    ankerl::unordered_dense::map<uint64_t, Intermediate::RttRecord> *accumulatedRtts; // session ID+<RTTs from small to big + RTTs from big to small>

    // building result
    struct Result
    {
        struct Head
        {
            uint8_t ips[32];
            int32_t ipLength;
            uint16_t clientPort, serverPort;
            uint32_t from, to;
            uint64_t macClientSize, macServerSize;
            struct Statistics
            {
                uint64_t average, count, standardDeviation;
            } csc, scs; // client-server-client, server-client-server
            int64_t totalPackets;
            uint8_t payloadProtocol;
        } head;
        std::string macClient, macServer;
    };
    static constexpr size_t resultHeadSize = sizeof(Result::Head);
    static constexpr size_t indexSize = sizeof(std::pair<int64_t, uint64_t>);
    unsigned long long resultCount = 0;
    static Result::Head::Statistics jitterStatistics(const std::vector<int64_t> &rtts);
    static std::string convertContainer(const ankerl::unordered_dense::set<std::string> &source);
};

class FeedRefinerVoip : public FeedRefinerAbstract
{
public:
    FeedRefinerVoip(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    // more modes for resultsInteractive()
    void showSummary(yyjson_mut_doc *document, const std::string &sipFrom, const std::string &sipTo);
    void showConversationDetails(yyjson_mut_doc *&document, const std::string &sipFrom, const std::string &sipTo);

    // DB used in messy room
    FeatherLite featherSip, featherRtt, featherSdp;

    // message type management
    enum MessageType : uint32_t { UNKNOWN = 0, REGISTER = 1, INVITE = 2, ACK = 4, BYE = 8, CANCEL = 16, UPDATE = 32, REFER = 64, PRACK = 128, SUBSCRIBE = 256, NOTIFY = 512, PUBLISH = 1024, MESSAGE = 2048, INFO = 4096, OPTIONS = 8192, RESPONSE = 16384, ALL = UINT32_MAX };
    static const char *messageTypeString(const MessageType type);

    // description / digest of SIP and SDP
    struct SdpMediaEndpoint
    {
        int64_t sipAt; // timestamp for SIP that delivered this SDP
        enum MediaType { SDPNOTDETERMINED, SDPAUDIO, SDPVIDEO, SDPAPPLICATION, SDPDATA, SDPCONTROL, SDPOTHER } type;
        std::string callId, ip;
        unsigned short port;
    };
    static const char *mediaTypeString(const SdpMediaEndpoint::MediaType type);
    struct SipSummary
    {
        int64_t timestamp;
        int32_t responseCode = 0; // set if type = RESPONSE
        MessageType type;
        std::string raw, callId, from, to, via, cseq, fromIp, toIp;
        std::optional<std::vector<SdpMediaEndpoint>> mediaEndpoints;
    };
    void refineSdp(SipSummary &message);

    // gather RTP jitter
    struct JitterData
    {
        int64_t sipAt;
        std::string from, to, callId;
        SdpMediaEndpoint::MediaType type;
        ankerl::unordered_dense::map<std::pair<std::string, uint16_t>, std::vector<int64_t>> timestamps; // <peer IP + peer port> + timestamp in nanosecond resolution
    };
    ankerl::unordered_dense::map<std::pair<std::string, uint16_t>, JitterData> jitterBagRequest, jitterBagResponse; // <media IP + port> + description
    ankerl::unordered_dense::set<std::string> sdpRequestsRecognized, sdpResponsesRecognized; // saving call IDs to determine duplicate input
    void flushRtpJitter(const JitterData &data, const std::string &ip, const uint16_t &port, const int isReqSide);

    // utility functions
    static void trimRight(std::string &target);
    static std::vector<std::string> split(const std::string &source, const char splitter = '/');
};

class FeedRefinerSessionAudit : public FeedRefinerAbstract
{
public:
    FeedRefinerSessionAudit(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    ~FeedRefinerSessionAudit();
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    // data structures
    struct SessionEvent
    {
        uint32_t second, nanosecond;
        int64_t value;
        enum Type : int8_t { SYN = -3, SYNACK, ACK, NOTHINGSPECIAL = 0, TCPZEROWINDOW, TCPPORTREUSED, TCPOUTOFORDER, TCPDUPACK, TCPRETRANSMISSION, TCPRST, TCPFIN, TIMEOUT } type;
        int8_t direction;
    };
    static constexpr size_t sessionEventSize = sizeof(SessionEvent);
    static std::string eventTypeString(const SessionEvent::Type event);
    struct Intermediate
    {
        std::vector<SuperCodex::Session> sessions;
        ankerl::unordered_dense::map<uint64_t, std::vector<SessionEvent>> eventLogs; // session ID + event logs
    };

    // index
    struct SessionIndex
    {
        uint64_t sessionId;
        uint32_t second, nanosecond;
        unsigned short sourcePort, destinationPort;
        int8_t sourceIsSmall;
        uint8_t payloadProtocol;
        std::string sourceIp, destinationIp;
    };
    std::vector<SessionIndex> indices;
    ankerl::unordered_dense::set<uint64_t> savedSessionIds;
    std::shared_mutex indicesMutex;

    // audit data builder
    std::vector<std::pair<uint64_t, std::pair<SessionIndex, std::vector<SessionEvent>>>> buildAuditLog(SuperCodex::Loader *loader); // session ID + <session index + event log>
    void pushAuditLog(const std::vector<std::pair<uint64_t, std::pair<SessionIndex, std::vector<SessionEvent>>>> &logs);
    std::thread buildAuditLogThread;
    std::atomic<bool> fullyGenerated = false, continueBackgroundThread = true;
};

#endif // FEEDREFINERSPECIALIZED_H
