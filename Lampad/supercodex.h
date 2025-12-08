#ifndef SUPERCODEX_H
#define SUPERCODEX_H

// PacketTray::SessionPack::TcpMiscAnomalies error codes, put in variable "tail"
#define MA_TCPZEROWINDOW 0
#define MA_TCPPORTSREUSED 1
#define MA_TCPOUTOFORDER 2
#define MA_TCPKEEPALIVE 3

#include "loghandler.h"

#include <string>
#include <utility>
#include <vector>
#include <string_view>

#include <ankerl/unordered_dense.h>

#ifndef DISABLE_PARALLEL_CONVERT
#include <tbb/parallel_for.h>
#include <tbb/partitioner.h>
#endif

using namespace std::string_literals;

namespace SuperCodex {
struct Packet
{
    int32_t index;
    uint32_t second, nanosecond;
    uint32_t savedLength;
    uint32_t fileOffset;
    uint64_t sessionId;
    int8_t fromSmallToBig; // 1=true, 0=false
    uint16_t payloadDataSize = 0;

    // Layer 2
    uint8_t destinationMac[6], sourceMac[6];
    uint16_t tagQ; // VLAN tag for 802.11Q

    // Layer 3
    uint8_t hopLimit; // IPv4 TTL or IPv6 hop limit

    // TCP specific
    uint32_t tcpSeq, tcpAck; // for UDP, these are used as buffer for RTP(SEQ for first 4 bytes including sequential number, and ACK for SSRC)
    uint16_t tcpWindowSize;

    enum Status : uint16_t {
        NONE = 0,
        // TCP flags(9 bits)
        TCPFIN = 1,
        TCPSYN = 2,
        TCPRST = 4,
        TCPPSH = 8,
        TCPACK = 16,
        TCPURG = 32,
        TCPECE = 64,
        TCPCWR = 128,
        TCPNS = 256,
        // convenience flags for TCP
        TCPSYNACK = TCPSYN + TCPACK,
        TCPFINORRST = TCPFIN + TCPRST,
        TCPSYNFIN = TCPSYN + TCPFIN,
        TCPSTARTOREND = TCPSYN + TCPFIN + TCPRST,
        TCPZEROWINDOW = 512,
        // more
        L3FRAGMENTSTART = 1024,
        L3FRAGMENTFOLLOWING = 2048,
        SLICED = 4096, // packet is sliced =
        TCPSPURIOUSRETRANSMISSION = 8192,
        L3FRAGMENTEND = 16384,
        // convenience flags for IPv4 fragmentataion. Recommended reading for IP fragmentation and reassembly: https://superuser.com/questions/899578/does-a-host-re-order-fragmented-ip-packets-received-out-of-order
        L3FRAGMENTED = L3FRAGMENTSTART + L3FRAGMENTFOLLOWING + L3FRAGMENTEND,
        L3FRAGMENTEDTAILS = L3FRAGMENTFOLLOWING + L3FRAGMENTEND,
        RESERVED32768 = 32768
    } status;
};

struct Session
{
    uint64_t id;
    uint8_t ips[32]; // for IPv4, only first 8 bytes will be used(full 32 bytes for IPv6)
    uint16_t sourcePort, destinationPort;
    uint16_t etherType;
    int8_t sourceIsSmall; // 1=true, 0=false
    uint8_t payloadProtocol;
    struct
    {
        uint32_t second, nanosecond;
    } first, last;
    enum L7Protocol : uint8_t {
        NOL7DETECTED = 0,
        // the sequence must NOT to be changed
        DNS,
        HTTP,
        FTP,
        SMTP,
        IMAP,
        POP3, // first 7
        TLS, // HTTPS
        RTP,
        RTCP,
        RTSP, // AV streaming
        SIP, // VoIP
        // dummy tail to indicate end of the enumeration
        L7PROTOCOLTAIL
    } detectedL7;
    enum Status : uint8_t { NONE = 0, HASTCPFIN = 1, HASTCPSYN = 2, HASTCPRST = 4, STREAMCLOSED = HASTCPFIN + HASTCPRST, RESERVED8 = 8, RESERVED16 = 16, RESERVED32 = 32, RESERVED64 = 64, RESERVED128 = 128 } status;
};

class IpFilter
{
public:
    void registerNetwork(const std::string &raw, const uint16_t port = 0, const std::string &alias = ""s);
    bool contains(const std::string_view &ip) const;
    std::string getAlias(const std::string_view &ip, const uint16_t port) const;
    bool isEmpty = true;

    // utility funcitons
    uint32_t signature();
    std::pair<size_t, size_t> registeredAddresses() const;

private:
    // store
    template<typename T> struct IpStore
    {
        T ip, netmask; // IP description, netmask in '11111111.11111111.11111111.00000000' format
        uint16_t port;
        std::string alias;
    };
    std::vector<IpStore<uint32_t>> v4Filters;
    std::vector<IpStore<std::pair<uint64_t, uint64_t>>> v6Filters;
    // internal functions for registering new IP or CIDR
    bool registerV4WithMask(const std::string_view &ip, const uint16_t port, const std::string &alias);
    bool registerV6WithMask(const std::string_view &ip, const uint16_t port, const std::string &alias);
    uint8_t lastByte(const size_t bitCount);
    // helper functions to filter IP addresses
    bool isRegisteredV4(const std::string_view &ip) const;
    bool isRegisteredV6(const std::string_view &ip) const;
    // helper forunctions to find alias
    std::string getAliasV4(const std::string_view &ip, const uint16_t port) const;
    std::string getAliasV6(const std::string_view &ip, const uint16_t port) const;
};

struct Conditions
{
    // request description
    unsigned int jobId = 0;
    ankerl::unordered_dense::map<std::string, std::string> parameters;
    std::string dataFeed; // name of the data feed
    std::vector<std::string> codicesToGo;

    // target time duration
    uint32_t from = 0, to = UINT32_MAX, cacheFrom = 0, cacheTo = 0;

    // layer 3: IP addresses
    IpFilter allowedIps;

    // layer 4: port number
    ankerl::unordered_dense::set<uint16_t> ports;
    uint8_t payloadProtocol = 0; // value from IPv4 or IPv6 header

    // layer 7 protocol filters
    SuperCodex::Session::L7Protocol l7Protocol = SuperCodex::Session::NOL7DETECTED;

    // Schrodinger: optional filters, which may or may not exist depending on the target network environment
    ankerl::unordered_dense::set<uint16_t> vlanQTags, mplsLabels;

    // miscellany
    bool includeExternalTransfer = true;
    ankerl::unordered_dense::map<std::string, std::vector<std::string>> ipToTags;
};
unsigned int conditionsId(SuperCodex::Conditions &conditions);

// helper variables and functions
constexpr int sessionSize = sizeof(SuperCodex::Session);
constexpr int packetSize = sizeof(SuperCodex::Packet);
struct Glyph
{
    char *data;
    int32_t size;
    bool startsWith(const std::string &compareTo) const;
};

// data extraction and recognition
std::string sourceIp(const Session &session);
std::string destinationIp(const Session &session);
std::string service(const Session &session);
int ipLength(const unsigned short etherType);
enum CastType { UNKNOWN, UNICAST, MULTICAST, BROADCAST };
CastType castType(const Session &session);

// utility functions
bool isValidHexadecimal(const std::string &stringInHex);
bool isPast(const uint32_t second1, const uint32_t nanosecond1, const uint32_t second2, const uint32_t nanosecond2);
bool isPastOrPresent(const uint32_t second1, const uint32_t nanosecond1, const uint32_t second2, const uint32_t nanosecond2);
void swapIpPortPair(Session &session);
std::string humanReadableIp(const std::string_view &ipRaw);
std::string computerReadableIp(const std::string &humanReadableIp);
std::string l7ProtocolToString(const Session::L7Protocol protocol);
std::string stringToHex(const std::string_view &source);
std::string stringFromHex(const std::string &source);

// record type
enum ChapterType : uint32_t {
    PACKETS = 1,
    SESSIONS = 2,
    BPSPERSESSION = 4,
    PPSPERSESSION = 8,
    RTTS = 16, // 5th
    TIMEOUTS = 32,
    REMARKS = 64,
    TCPSYNS = 128,
    TCPRSTS = 256,
    TCPMISCANOMALIES = 512, // 10th
    TCPRETRANSMISSIONS = 1024,
    TCPDUPACKS = 2048,
    EVENTS = 4096, // obsolete as chapter type: used as representing "no data source associated"
    SCHRODINGER = 8192
};
enum SchrodingerPart : uint32_t { SCHRODINGERSUMMARY, VLANQ, MPLS }; // I think at most only one byte will be used, but with this we can reuse SuperCodex::Loader::ChapterHeader

struct PacketMarker
{
    uint64_t sessionId;
    uint32_t second, nanosecond;
    int8_t fromSmallToBig;
    int64_t tail;
};
constexpr int packetMarkerSize = sizeof(SuperCodex::PacketMarker);

struct Timeout
{
    Session session;
    PacketMarker marker;
};
constexpr int timeoutSize = sizeof(SuperCodex::Timeout);

// data compression
extern int compressionLevel;
Glyph compress(const char *data, const size_t size);
char *decompress(const Glyph compressed, const int compressedSize, const int originalSize);

// simple utility functions for SuperCodex files
std::pair<uint32_t, uint32_t> durationContained(const std::string &file); // return value: from, to

// loader
class Loader
{
public:
    Loader(const std::string &file, const ChapterType chaptersToLoad, const Conditions &filter = Conditions());
    ~Loader();

    // codex description
    const std::string fileName;
    uint32_t secondStart, secondEnd;
    bool isSane = true;
    Conditions conditions;

    // helper structs to read data
    struct ChapterHeader
    {
        ChapterType type;
        int32_t compressedSize, originalSize;
    };
    struct SchrodingerHeader
    {
        SchrodingerPart type;
        int32_t compressedSize, originalSize;
    };
    struct BpsPpsItem
    {
        uint64_t sessionId;
        uint32_t second;
        int64_t fromSmallToBig, fromBigToSmall;
    };
    static constexpr int bpsPpsItemSize = sizeof(SuperCodex::Loader::BpsPpsItem);
    struct Remarks
    {
        uint64_t sessionId;
        int32_t size;
        const char *content = nullptr;
    };

    // session management
    ankerl::unordered_dense::map<uint64_t, Session *> sessions; // session ID+pointer to the core object
    ankerl::unordered_dense::map<uint64_t, Session *> allSessions(); // returns all the sessions this SuperCodex file contains regardless of fliters. This is to be used to apply "custom" filters by swapping "sessions"

    // chapter readers - first item
    const Packet *firstPacket() const;
    const BpsPpsItem *firstBpsPerSession() const;
    const BpsPpsItem *firstPpsPerSession() const;
    const Remarks firstRemarks() const;
    const PacketMarker *firstRtt() const;
    const Timeout *firstTimeout() const;
    const PacketMarker *firstTcpRst() const;
    const PacketMarker *firstTcpMiscAnomaly() const;
    const PacketMarker *firstTcpSyn() const;
    const PacketMarker *firstTcpRetransmission() const;
    const PacketMarker *firstTcpDupAck() const;

    // chapter readers - successive item
    const Packet *nextPacket(const Packet *packet) const;
    const BpsPpsItem *nextBpsPerSession(const BpsPpsItem *bps) const;
    const BpsPpsItem *nextPpsPerSession(const BpsPpsItem *pps) const;
    const Remarks nextRemarks(const Remarks remarks) const;
    const PacketMarker *nextRtt(const PacketMarker *rtt) const;
    const Timeout *nextTimeout(const Timeout *timeout) const;
    const PacketMarker *nextTcpRst(const PacketMarker *tcpRst) const;
    const PacketMarker *nextTcpMiscAnomaly(const PacketMarker *tcpMiscAnomaly) const;
    const PacketMarker *nextTcpSyn(const PacketMarker *tcpSyn) const;
    const PacketMarker *nextTcpRetransmission(const PacketMarker *tcpRetransmission) const;
    const PacketMarker *nextTcpDupAck(const PacketMarker *tcpDupAck) const;

    // public utility
    bool sessionAccepted(const SuperCodex::Session *session) const;
    std::vector<const Packet *> allPackets(); // to be used in Rewind, in case session chapter doesn't exist

    // schrodinger optional filters
    struct SchrodingerSummary
    {
        std::vector<uint16_t> vlanQs, mplsLabels;
    };
    static SchrodingerSummary schrodingerSummary(const std::string &file);
    struct SchrodingerDump
    {
        std::vector<std::pair<uint16_t, std::vector<std::uint64_t>>> vlanQTags, mplsLabels;
    };
    static SchrodingerDump dumpSchrodinger(const std::string &file);

    // global IP exclusion filter: public interface
    static void addToExclusion(const std::string &condition);

private:
    // chapter reader backend
    const Packet *_nextPacket(const Packet *packet) const;
    const BpsPpsItem *_nextBpsPerSession(const BpsPpsItem *bps) const;
    const BpsPpsItem *_nextPpsPerSession(const BpsPpsItem *pps) const;
    const Remarks _nextRemarks(const char *cursor) const;
    const PacketMarker *_nextRtt(const PacketMarker *rtt) const;
    const Timeout *_nextTimeout(const Timeout *timeout) const;
    const PacketMarker *_nextTcpRst(const PacketMarker *tcpRst) const;
    const PacketMarker *_nextTcpMiscAnomaly(const PacketMarker *tcpMiscAnomaly) const;
    const PacketMarker *_nextTcpSyn(const PacketMarker *tcpSyn) const;
    const PacketMarker *_nextTcpRetransmission(const PacketMarker *tcpRetransmission) const;
    const PacketMarker *_nextTcpDupAck(const PacketMarker *tcpDupAck) const;

    // decompressed raw data and cursors
    Session *sessionCursor = nullptr, *sessionCursorEnd = nullptr; // sessions are not const(the only exception): the client-server direction may be corrected according to the service information
    const Packet *packetStart = nullptr, *packetEnd = nullptr;
    std::string packetRaw, sessionRaw, bpsPerSessionRaw, ppsPerSessionRaw, remarksRaw, rttRaw, timeoutRaw, tcpRstRaw, tcpMiscAnomalyRaw, tcpRetransmissionRaw, tcpDupAckRaw, tcpSynRaw;
    const BpsPpsItem *bpsPerSessionStart = nullptr, *bpsPerSessionEnd = nullptr;
    const BpsPpsItem *ppsPerSessionStart = nullptr, *ppsPerSessionEnd = nullptr;
    const char *remarksStart = nullptr, *remarksEnd = nullptr;
    const PacketMarker *rttStart = nullptr, *rttEnd = nullptr;
    Timeout *timeoutStart = nullptr, *timeoutEnd = nullptr;
    const PacketMarker *tcpRstStart = nullptr, *tcpRstEnd = nullptr;
    const PacketMarker *tcpMiscAnomalyStart = nullptr, *tcpMiscAnomalyEnd = nullptr;
    const PacketMarker *tcpSynStart = nullptr, *tcpSynEnd = nullptr;
    const PacketMarker *tcpRetransmissionStart = nullptr, *tcpRetransmissionEnd = nullptr;
    const PacketMarker *tcpDupAckStart = nullptr, *tcpDupAckEnd = nullptr;

    // filtering helpers
    void filterSessions();
    bool inDuration(const int32_t timestamp) const;
    void fillSchrodinger(char *data, const size_t size);
    ankerl::unordered_dense::set<uint64_t> allowed8021qTags, allowedMplsLabels;

    // miscellany
    static ankerl::unordered_dense::set<std::string> globalExclusionSingleIp, globalExclusionPair; // Single IP: single IP for either source or destination, Pair: IP pair(for convenience, the pair contains pair for both direction, A->B and B->A)
    Logger logger;
};

// parallel_convert
#ifndef DISABLE_PARALLEL_CONVERT
template<typename InType, typename OutType> std::vector<OutType> parallel_convert(const std::vector<InType> &source, std::function<OutType(const InType &)> convert);
template<typename InType, typename OutType> std::vector<OutType> parallel_convert(const std::vector<InType> &source, std::function<OutType(const InType &)> convert, tbb::affinity_partitioner &partitioner);
template<typename InType, typename OutType> std::vector<OutType> parallel_convert(const std::vector<InType> &source, std::function<OutType(const InType &)> convert)
{
    std::vector<OutType> results(source.size());
    std::mutex mutex;
    tbb::parallel_for(tbb::blocked_range<size_t>(0, source.size()), [&](tbb::blocked_range<size_t> r) {
        for (int i = r.begin(); i != r.end(); ++i) {
            auto converted = convert(source[i]);
            mutex.lock();
            results[i] = std::move(converted);
            mutex.unlock();
        }
    });

    return results;
}

template<typename InType, typename OutType> std::vector<OutType> parallel_convert(const std::vector<InType> &source, std::function<OutType(const InType &)> convert, tbb::affinity_partitioner &partitioner)
{
    std::vector<OutType> results(source.size());
    std::mutex mutex;
    tbb::parallel_for(
        tbb::blocked_range<size_t>(0, source.size()),
        [&](tbb::blocked_range<size_t> r) {
            for (int i = r.begin(); i != r.end(); ++i) {
                auto converted = convert(source[i]);
                mutex.lock();
                results[i] = std::move(converted);
                mutex.unlock();
            }
        },
        partitioner);

    return results;
}
#endif // DISABLE_PARALLEL_CONVERT

} // namespace SuperCodex

#endif // SUPERCODEX_H
