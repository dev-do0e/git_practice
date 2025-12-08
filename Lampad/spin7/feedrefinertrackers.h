#ifndef FEEDREFINERTRACKERS_H
#define FEEDREFINERTRACKERS_H

#include "feedrefinerabstract.h"
#include <atomic>

#include <ankerl/unordered_dense.h>
#include <yyjson.h>

class FeedRefinerDnsTracker : public FeedRefinerAbstract
{
public:
    FeedRefinerDnsTracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

    // parse remarks and determine status
    enum Status : int8_t {
        REQUESTONLY = 0, // used only to recognize details for timeout. "response only" is not needed, as orphaned response have everything from query to responses as well as RTTs and all
        RESOLVED = 1,
        ZEROANSWER = 2, // DnsException=AnswerCountZero
        ANSWERBROKEN = 4, // DnsException=ReadIndexOutOfBound
        MULTIPLEQUERIES = 8, // DnsException=MultipleQuestions
        TIMEOUT = 16
    };
    static Status determineStatus(const std::string &remarks);
    static std::string extractQuery(const std::string &remarks);

    struct SessionRecord // intermediary result
    {
        uint64_t sessionId;
        uint32_t secondStart, secondEnd; // timestamps
        int64_t latency;
        Status status;
        std::string sourceIp, destinationIp, remarks, query;
    };
    struct Summary
    {
        uint64_t fastest = INT64_MAX, slowest = 0, sum = 0, // statistics for latency
            clientsServed = 0, queriesReceived = 0, resolved = 0, timeout = 0, answerCountZero = 0, answerBroken = 0, multipleQueries = 0; // counts
        Summary &operator+=(const Summary &other)
        {
            // add counters
            this->queriesReceived += other.queriesReceived;
            this->resolved += other.resolved;
            this->timeout += other.timeout;
            this->answerCountZero += other.answerCountZero;
            this->answerBroken += other.answerBroken;
            this->multipleQueries += other.multipleQueries;

            // update latency statistics
            if (this->fastest > other.fastest)
                this->fastest = other.fastest;
            if (this->slowest < other.slowest)
                this->slowest = other.slowest;
            this->sum += other.sum;

            // return result
            return *this;
        }
    };
    struct Description
    {
        Summary summary;
        // details
        ankerl::unordered_dense::map<std::string, ankerl::unordered_dense::map<std::string, unsigned long long>> details[5]; // DNS query + <deduplicated client IPs + number of hits>. each element represents RESOLVED, ZEROANSWER, ANSWERBROKEN, MULTIPLEQUREIES, and TIMEOUT

        void mergeSessionRecord(const SessionRecord record)
        {
            // update statistics and details per status
            switch (record.status) {
            case RESOLVED:
                ++summary.resolved;
                ++summary.queriesReceived;
                ++details[0][record.query][record.sourceIp];
                break;
            case ZEROANSWER:
                ++summary.answerCountZero;
                ++summary.queriesReceived;
                ++details[1][record.query][record.sourceIp];
                break;
            case ANSWERBROKEN:
                ++summary.answerBroken;
                ++summary.queriesReceived;
                ++details[2][record.query][record.sourceIp];
                break;
            case MULTIPLEQUERIES:
                ++summary.multipleQueries;
                ++summary.queriesReceived;
                ++details[3][record.query][record.sourceIp];
                break;
            case TIMEOUT:
                ++summary.timeout;
                ++details[4][record.query][record.sourceIp];
                break;
            case REQUESTONLY:
                break; // ignore
            }

            // update latency summary
            if (record.latency >= 0) {
                summary.sum += record.latency;
                if (record.latency > summary.slowest)
                    summary.slowest = record.latency;
                if (record.latency < summary.fastest)
                    summary.fastest = record.latency;
            }
        }

        void setNumberOfDeduplicatedClients()
        {
            ankerl::unordered_dense::set<std::string> deduplicated;
            for (int i = 0; i < 5; ++i)
                for (const auto &pair : details[i])
                    deduplicated.insert(pair.first);
            summary.clientsServed = deduplicated.size();
        }
    }; // reference for aggretated(total)

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    ankerl::unordered_dense::map<uint64_t, SessionRecord> *orphanedRequests; // DNS sessions, request only(no response found from the session)
    Description descriptionTotal;
    ankerl::unordered_dense::map<std::string, Description> descriptions; // performance statistics for each DNS server. IP + details
    std::vector<uint64_t> timeouts; // unprocessed timed out sessions
    std::vector<std::string> serverListSorted; // list of server IPs
};

class FeedRefinerPop3Tracker : public FeedRefinerAbstract
{
public:
    FeedRefinerPop3Tracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    // data merger
    struct Pack
    {
        std::vector<SuperCodex::Session> sessions;
        struct Description
        {
            std::string remarks;
            long long bytesTransferred = 0;
            int32_t errorCount = 0;
        };
        ankerl::unordered_dense::map<uint64_t, Description> descriptions; // also used as indices for sessions
    };

    // description for raw data in disk
    struct Record
    {
        char sourceIp[16],
            destinationIp[16]; // first 8 bytes of sourceIp is also used as session ID
        int8_t ipLength;
        int32_t errorCount;
        int64_t bytesTransferred, remarksSize;
        uint64_t sessionId() { return *(const uint64_t *) sourceIp; }
        void setSessionId(const uint64_t id) { *(uint64_t *) sourceIp = id; }
    }; // remarks(one error message per line) follows
    static constexpr size_t recordSize = sizeof(Record);

    // list of servers
    std::vector<std::string> servers;
};

class FeedRefinerImapTracker : public FeedRefinerAbstract
{
public:
    FeedRefinerImapTracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    // data merger
    struct Pack
    {
        std::vector<SuperCodex::Session> sessions;
        struct Description
        {
            long long bytesTransferred = 0;
            std::string nos, bads, alerts;
            int32_t noCount = 0, badCount = 0, alertCount = 0;
        };
        ankerl::unordered_dense::map<uint64_t, Description> descriptions; // also used as indices for sessions
    };

    // description for raw data in disk
    struct Record
    {
        char sourceIp[16],
            destinationIp[16]; // first 8 bytes of sourceIp is also used as session ID
        int8_t ipLength;
        int32_t noCount = 0, badCount = 0, alertCount = 0;
        int64_t bytesTransferred, noSize, badSize, alertSize;
        uint64_t sessionId() { return *(const uint64_t *) sourceIp; }
        void setSessionId(const uint64_t id) { *(uint64_t *) sourceIp = id; }
    }; // nos, bads, alerts(one error message per line) follows
    static constexpr size_t recordSize = sizeof(Record);

    // list of servers
    std::vector<std::string> servers;
};

class FeedRefinerHttpTracker : public FeedRefinerAbstract
{
public:
    FeedRefinerHttpTracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual ~FeedRefinerHttpTracker();
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    std::string regex;
    struct Pack
    {
        std::vector<SuperCodex::Session> sessions;
        struct Description
        {
            std::string requestInTail,
                responseInHead; // when if remarks ends with request or starts with response(link to others with same session data)
            std::vector<std::string> completes, noResponses /* requests without response. useful especially in persistent connection */
                ; // responses without requests are ignored
        };
        ankerl::unordered_dense::map<uint64_t, Description> descriptions;
    };
    ankerl::unordered_dense::map<uint64_t, std::string> *orphanedRequests;

    // fill details
    enum Browser : uint8_t { BROWSER_CHROME, BROWSER_FIREFOX, BROWSER_EDGE, BROWSER_MSIE, BROWSER_SAFARI, BROWSER_OTHER };
    std::string browserString(const Browser &browser);
    enum OperatingSystem : uint8_t { OS_WIN10, OS_WIN81, OS_WIN8, OS_WIN7, OS_WINOTHER, OS_ANDROID, OS_MACOSX, OS_IPHONEOS, OS_IPADOS, OS_LINUX, OS_OTHER };
    std::string operatingSystemString(const OperatingSystem &os);
    struct Parsed
    {
        char sourceIp[16], destinationIp[16], country[2];
        uint16_t destinationPort;
        int16_t statusCode = -1;
        uint8_t ipLength;
        Browser browser;
        OperatingSystem os;
        int64_t requestAt = -1, responseAt = -1;
        int32_t hostLength, methodLength, pathLength, refererLength;
        uint64_t sessionId() { return *(const uint64_t *) sourceIp; }
        void setSessionId(const uint64_t id) { *(uint64_t *) sourceIp = id; }
    }; // host, method, path, referer follows
    static constexpr size_t parsedSize = sizeof(Parsed);
    struct ParserPack
    {
        // raw data(input) to parse
        uint64_t sessionId;
        const std::string *remarks, *regex;
        // metadata and helper for parsing result
        bool includeToResult = true; // it becomes false when the remarks fails to hit regex
        std::string host, method, path, referer;
        Parsed parsed;
    };
    static void parseRemarks(ParserPack &rawData);

    // service list(if domain is not set, IP+port pair combination with "(N)" suffix is used instead. e.g. "192.168.1.1:8088(N)")
    std::vector<std::string> services;

    // IP geolocation
    struct GeoLocationIpV4
    {
        uint32_t ipFrom, ipTo;
        std::string country;
    };
    std::vector<GeoLocationIpV4> geoLocationStoreIpV4;
    std::string geoLocationIpV4(const std::string &ip);

    // calculate hash for std::string(ignoring endianness)
    static std::string hashed(const std::string &source);

    // build JSON results(called by FeedRefinerHttpTracker::resultsJson())
    void writeClientProfile(const ankerl::unordered_dense::map<std::string, std::string> &requestParameters, yyjson_mut_doc *document, const std::string &service);
    void writePerformance(const ankerl::unordered_dense::map<std::string, std::string> &requestParameters, yyjson_mut_doc *document, const std::string &service, const int32_t bindValue);
    void writeErrorDetails(const ankerl::unordered_dense::map<std::string, std::string> &requestParameters, yyjson_mut_doc *document, const std::string &service, const std::string &path);
};

class FeedRefinerSmtpTracker : public FeedRefinerAbstract
{
public:
    FeedRefinerSmtpTracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    // structures for merging data
    struct Pack
    {
        std::vector<SuperCodex::Session> sessions;
        struct Description
        {
            int64_t bytesTransferred = 0;
            std::string sender, recipients, errors;
        };
        ankerl::unordered_dense::map<uint64_t, Description> descriptions;
    };
    struct Record
    {
        char destinationIp[16];
        int8_t ipLength;
        int32_t senderLength, recipientsLength, errorsLength;
        int64_t bytesTransferred = 0;
        uint64_t sessionId() { return *(const uint64_t *) destinationIp; }
        void setSessionId(const uint64_t id) { *(uint64_t *) destinationIp = id; }
    }; // sender, recipients, errors follow in that order
    static constexpr size_t recordSize = sizeof(Record);

    // list of servers
    std::vector<std::string> servers;
};

class FeedRefinerFtpTracker : public FeedRefinerAbstract
{
public:
    FeedRefinerFtpTracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    struct Pack
    {
        std::vector<SuperCodex::Session> sessions;
        struct Description
        {
            int64_t fromSmallToBig = 0, fromBigToSmall = 0;
            std::string stored, retrieved, deleted, errors;
        };
        ankerl::unordered_dense::map<uint64_t, Description> descriptions;
    };
    struct Record
    {
        char sourceIp[16], destinationIp[16];
        int8_t ipLength;
        uint32_t first, last;
        int64_t fromClientToServer, fromServerToClient;
        int32_t storedLength, retrievedLength, deletedLength, errorsLength;
        uint64_t sessionId() { return *(const uint64_t *) sourceIp; }
        void setSessionId(const uint64_t id) { *(uint64_t *) sourceIp = id; }
    }; // stored, retrieved, deleted, errors follow in order
    static constexpr size_t recordSize = sizeof(Record);
    std::vector<std::string> servers;

    // utility function
    void lineToArray(yyjson_mut_doc *document, yyjson_mut_val *array, const std::string &source);
};

class FeedRefinerTlsTracker : public FeedRefinerAbstract
{
public:
    FeedRefinerTlsTracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    struct Description
    {
        uint64_t sessions = 1, bytesCs = 0, bytesSc = 0, rttSumCsc = 0, rttHitsCsc = 0, rttSumScs = 0, rttHitsScs = 0,
                 timeoutHits = 0; // CS: Client-to-Server, SC: Server-to-Client, CSC: client-server-client, SCS: server-client-server
        Description &operator+=(const Description &other)
        {
            this->sessions += other.sessions; // sessions are set to 1; by doing this, number of sessions can be automatically calculated
            this->bytesCs += other.bytesCs;
            this->bytesSc += other.bytesSc;
            this->rttSumCsc += other.rttSumCsc;
            this->rttHitsCsc += other.rttHitsCsc;
            this->rttSumScs += other.rttSumScs;
            this->rttHitsScs += other.rttHitsScs;
            this->timeoutHits += other.timeoutHits;
            return *this;
        }
    };
    struct Intermediate
    {
        ankerl::unordered_dense::map<uint64_t, std::string> snis; // session ID + associated SNI
        std::vector<SuperCodex::Session> sessions;
        ankerl::unordered_dense::map<uint64_t, Description> performanceFactors; // session ID + performance descriptors
    };

    // accumulated intermediate results
    ankerl::unordered_dense::map<uint64_t, std::string> *snis; // session ID+associated SNI
    ankerl::unordered_dense::map<uint64_t, Description> *performanceFactors; // session ID + performance descriptors

    // for final results
    struct ResultRecord
    {
        char ip[32];
        int ipLength;
        Description description;
    };
    static constexpr size_t resultRecordSize = sizeof(ResultRecord);
    std::vector<std::string> sniList;
};

class FeedRefinerTlsDump : public FeedRefinerAbstract
{
public:
    FeedRefinerTlsDump(const std::string messyRoomName, const SuperCodex::Conditions &conditions);
    ~FeedRefinerTlsDump();
    virtual void resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) override;
    virtual void dumpResults(mg_connection *connection) override;

protected:
    virtual void processCodices(const std::vector<SuperCodex::Loader *> &codices) override;
    virtual void finalize() override;

private:
    std::string dbPath;
    std::thread buildRecordsThread;
    std::atomic<bool> isComplete = false, continueBackgroundThread = true;
    std::atomic<size_t> recordsAdded=0;
};

#endif // FEEDREFINERTRACKERS_H
