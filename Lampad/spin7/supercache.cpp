#include "supercache.h"
#include "datafeed.h"
#include "datafeedrefinery.h"
#include "codexindex.h"
#include "../featherlite.h"
#include "../supercodex.h"

#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>

#include <yyjson.h>

using namespace std::string_literals;

// extern variables
std::string SuperCache::feedPath;
uint32_t SuperCache::tlsDumpRetentionPeriod = 1296000; // default: 15 days
std::vector<std::string> SuperCache::dbs = {
    "/supercache.ps"s, // per second
    "/supercache.pmpi"s, // per minute per IP
    // LAST TABLE: TLS dump
    "/supercache.tls"s,
};
std::vector<std::string> SuperCache::ddls = {
    // table 0: per second
    "CREATE TABLE rows(timestamp INTEGER, chapter INTEGER, value BLOB);"
    "CREATE UNIQUE INDEX idx1 ON rows(timestamp,chapter);"s,
    // table 1: per minute per minute per IP. Actual BLOB fields are saved as files in each hour directory with naming convention of `pmpi.{timestamp}.{chapter in integer}`
    "CREATE TABLE rows(timestamp INTEGER, chapter INTEGER, originalsize, filepath INTEGER);" // originalsize: size of original decompressed stream
    "CREATE UNIQUE INDEX idx1 ON rows(timestamp,chapter);"s,
    // LAST TABLE: TLS dump - the connection time and SNI of TLS connections
    "CREATE TABLE rows(sessionid BLOB, timestamp INTEGER, ips BLOB, clientport INTEGER, serverport INTEGER, sni TEXT);"
    "CREATE UNIQUE INDEX idx1 ON rows(timestamp, sessionid);"s,
};

Logger SuperCache::logger("SuperCache"s);

void SuperCache::start()
{
    // separate DB list for separate checkpointing
    std::vector<std::string> dbs1 = dbs, dbs2;
    dbs2.push_back(dbs1.back());
    dbs1.pop_back();

    // startup
    logger.log("Startup"s);
    auto nextCheckpoint = std::chrono::steady_clock::now() + std::chrono::hours(1);
    while (true) {
        // calculate time until next minute
        std::chrono::steady_clock::time_point nextStart = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        feedPath.clear();

        // for each data feed
        for (const auto &feed : DataFeed::describeFeeds()) {
            // initialize variables and database
            feedPath = CodexIndex::feedRoot + feed.name;
            initializeDatabase(feedPath, dbs, ddls);

            // determine starting timestamp from per second statistics records, which must have the least records by design
            uint32_t lastStartingPoint;
            {
                FeatherLite feather(feedPath + dbs[0], SQLITE_OPEN_READONLY);
                if (!feather.prepare("SELECT MAX(timestamp) FROM rows;")) {
                    logger.oops("Failed to prepare for statement on getting last starting point. Details: "s + feather.lastError());
                    continue;
                }
                if (feather.next() == SQLITE_ROW)
                    lastStartingPoint = feather.getInt(0);
                else {
                    logger.oops("Failed to fetch timestamp to build cache for "s + feed.name + ". Details: "s + feather.lastError());
                    continue;
                }
            }
            if (lastStartingPoint < feed.from)
                lastStartingPoint = feed.from / 60 * 60;

            // build cache
            for (uint32_t i = lastStartingPoint + 60; i + 60 < feed.to; i += 60) { // condition: remaining lookback window should be bigger than 60 seconds
                const std::string encounteredError = buildCache(feed.name, i);
                if (!encounteredError.empty()) { // if an error is found, stop generating SuperCache
                    logger.oops(encounteredError);
                    break;
                }
            }
        }

        // cleanup and finalize
        if (std::chrono::steady_clock::now() >= nextCheckpoint) { // in next period(now per an hour)
            // checkpoint database and remove too old records
            checkpointDatabase(dbs1);
            checkpointDatabase(dbs2, tlsDumpRetentionPeriod);
            nextCheckpoint = std::chrono::steady_clock::now() + std::chrono::hours(1);
        }
        std::this_thread::sleep_until(nextStart);
    }
}

void SuperCache::initializeDatabase(const std::string &feedRoot, const std::vector<std::string> &dbFiles, const std::vector<std::string> &associatedDdls)
{
    // check integrity of each database file
    bool isCorrupt = false;
    for (size_t i = 0, iEnd = dbFiles.size(); i < iEnd; ++i) {
        std::filesystem::path dbPath = feedRoot + dbFiles[i];
        if (!std::filesystem::exists(dbPath) || std::filesystem::file_size(dbPath) == 0) { // check existence and size
            isCorrupt = true;
            break;
        }
    }

    // if database is corrupt, wipe out the entire database
    if (isCorrupt) {
        logger.log("Wiping out database at "s + feedRoot);
        for (size_t i = 0, iEnd = dbFiles.size(); i < iEnd; ++i) {
            std::string dbPath = feedRoot + dbFiles[i];
            if (std::filesystem::exists(dbPath))
                std::filesystem::remove(dbPath);
            if (std::filesystem::exists(dbPath + "-shm"s))
                std::filesystem::remove(dbPath + "-shm"s);
            if (std::filesystem::exists(dbPath + "-wal"s))
                std::filesystem::remove(dbPath + "-wal"s);
        }
    }

    // create database file(s) if the file does not exist
    for (size_t i = 0, iEnd = dbFiles.size(); i < iEnd; ++i) {
        std::string dbPath = feedRoot + dbFiles[i];
        if (!std::filesystem::exists(dbPath)) {
            logger.log("Create "s + dbPath);
            FeatherLite feather(dbPath);
            feather.useWal();
            feather.exec(associatedDdls[i]);
        }
    }
}

void SuperCache::checkpointDatabase(const std::vector<std::string> &dbFiles, const uint32_t dropMargin)
{
    for (const auto &feed : DataFeed::describeFeeds()) {
        for (const auto &db : dbFiles) {
            std::string dbPath = CodexIndex::feedRoot + feed.name + db;
            FeatherLite feather(dbPath);

            // delete too old records
            feather.prepare("DELETE FROM rows WHERE timestamp<?;"s);
            feather.bindInt(1, feed.from - dropMargin);
            feather.next();

            // checkpoint database
            feather.checkpoint();
        }
    }
}

std::string SuperCache::buildCache(const std::string &feedName, const uint32_t from)
{
    logger.log("Build cache: "s + feedName + " from " + std::to_string(from));
    // query list of SuperCodex files
    SuperCodex::Conditions conditions;
    conditions.from = from;
    conditions.to = from + 59;
    conditions.dataFeed = feedName;
    conditions.codicesToGo = DataFeed::codexIndex->codices(conditions);
    if (conditions.codicesToGo.empty()) {
        logger.oops("No SuperCodex files to process: "s + std::to_string(conditions.from) + " -> "s + std::to_string(conditions.to));
        return ""; // there can be missing SuperCodex files in the middle(e.g. packet capture was stopped for some time, i.e. 1~2 hours, due to some external reason)
    }

    // prepare for a few variables to read and store stuff
    SuperCodex::ChapterType chaptersToOpen = static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::PACKETS | SuperCodex::BPSPERSESSION | SuperCodex::PPSPERSESSION | SuperCodex::RTTS | SuperCodex::TIMEOUTS | SuperCodex::REMARKS | SuperCodex::TCPRSTS | SuperCodex::TCPMISCANOMALIES | SuperCodex::TCPRETRANSMISSIONS | SuperCodex::TCPDUPACKS);
    std::thread mergeThread;
    Final final(from);
    std::vector<uint64_t> sessionsInLastTail;
    uint32_t timestampForLastTail = 0;
    const std::string savePmpiPrefix = std::filesystem::path(conditions.codicesToGo.front()).parent_path().string() + "/pmpi."s + std::to_string(from) + '.';

    logger.log("Read SuperCodex files: "s + conditions.codicesToGo.front() + " -> "s + conditions.codicesToGo.back());
    // read SuperCodex files in parallel and refine intermediate results
    FeedConsumer::consumeByChunk(conditions, chaptersToOpen, std::thread::hardware_concurrency(), [&](std::vector<SuperCodex::Loader *> &codicesLoaded, const bool isFinal) -> bool {
        std::vector<Intermediate> intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, Intermediate>(codicesLoaded, [&](const SuperCodex::Loader *loader) -> Intermediate {
            // initialize variables
            Intermediate intermediate{};
            intermediate.from = std::max(loader->secondStart, conditions.from);
            intermediate.to = std::min(loader->secondEnd, conditions.to);
            const auto from = intermediate.from, to = intermediate.to; // for faster access

            // for ICMP walk
            struct IcmpSessionSummary
            {
                std::string sourceIp, destinationIp;
                int8_t sourceIsSmall;
            };
            ankerl::unordered_dense::map<uint64_t, IcmpSessionSummary> icmpSessionSummary;
            icmpSessionSummary.reserve(loader->sessions.size() / 10); // who knows...... :P
            ankerl::unordered_dense::map<int32_t, FeedRefinerIcmpWalk::Description> icmpsToMerge;

            // simple sanity check
            if (to < from) {
                logger.oops("Corrupt lookback window: "s + loader->fileName + ' ' + std::to_string(from) + " -> "s + std::to_string(to));
                return intermediate;
            }

            // prepare for storage for per second statistics
            const size_t duration = to - from + 1;
            intermediate.pps.resize(duration, {});
            intermediate.rtts.resize(duration, {});
            intermediate.bps.resize(duration, 0);
            intermediate.timeouts.resize(duration, 0);
            intermediate.rsts.resize(duration, 0);
            intermediate.dupAcks.resize(duration, 0);
            intermediate.retransmissions.resize(duration, 0);
            intermediate.zeroWindows.resize(duration, 0);
            intermediate.portReused.resize(duration, 0);
            intermediate.outOfOrders.resize(duration, 0);
            intermediate.flowCounts.resize(duration, 0);

            // declare quick references for Top N intermediates
            auto &bps_ps = intermediate.bps;
            auto &bytes_n = intermediate.bytes_n;
            auto &pps_ps = intermediate.pps;
            auto &packets_n = intermediate.packets_n;
            auto &rtt_ps = intermediate.rtts;
            auto &latencies_n = intermediate.latencies_n;
            auto &timeouts_ps = intermediate.timeouts;
            auto &timeouts_n = intermediate.timeouts_n;
            auto &rsts_ps = intermediate.rsts;
            auto &rsts_n = intermediate.rsts_n;
            auto &dupAcks_ps = intermediate.dupAcks;
            auto &dupAcks_n = intermediate.dupAcks_n;
            auto &retransmissions_ps = intermediate.retransmissions;
            auto &retransmissions_n = intermediate.retransmissions_n;
            auto &zeroWindows_ps = intermediate.zeroWindows;
            auto &zeroWindows_n = intermediate.zeroWindows_n;
            auto &portReused_ps = intermediate.portReused;
            auto &portReused_n = intermediate.portReused_n;
            auto &outOfOrders_ps = intermediate.outOfOrders;
            auto &outOfOrders_n = intermediate.outOfOrders_n;
            auto &httpErrors = intermediate.httpErrors;
            auto &httpErrorOrphanedRequests = intermediate.httpErrorOrphanedRequests;
            auto &httpErrorOrphanedResponses = intermediate.httpErrorOrphanedResponses;
            auto &tlsDump = intermediate.tlsDumps;

            // build keys from sessions, count number of flows per second, and do some more
            struct Keys
            {
                int8_t sourceIsSmall;
                FeedRefinerTopN::KeyIpToService keyIpToService;
                FeedRefinerTopN::KeySingle keySource, keyDestination;
            };
            ankerl::unordered_dense::map<uint64_t, Keys> ipToServiceKeys; // session ID + keys for each category
            ipToServiceKeys.reserve(loader->sessions.size());
            for (const auto &pair : loader->sessions) {
                const SuperCodex::Session &session = *pair.second;
                // build keys
                auto keyIpToService = FeedRefinerTopN::keyIpToServiceFromSession(session);
                Keys keys{session.sourceIsSmall, keyIpToService, FeedRefinerTopN::sourceFromIpToService(keyIpToService), FeedRefinerTopN::destinationFromIpToService(keyIpToService)};
                ipToServiceKeys[pair.first] = keys;

                // count flow per second
                for (size_t i = std::max(session.first.second, conditions.from) - from, iEnd = std::min(session.last.second, conditions.to) - from + 1; i < iEnd; ++i)
                    ++intermediate.flowCounts[i];
                if (session.first.second == from)
                    intermediate.sessionsFromHead.insert(session.id);
                if (session.last.second == to)
                    intermediate.sessionsInTail.push_back(session.id);

                // session counts for value2 (timeouts_n, tcpportreused_n)
                ++timeouts_n.source[keys.keySource].second;
                ++timeouts_n.destination[keys.keyDestination].second;
                ++timeouts_n.ipToService[keys.keyIpToService].second;
                ++portReused_n.source[keys.keySource].second;
                ++portReused_n.destination[keys.keyDestination].second;
                ++portReused_n.ipToService[keys.keyIpToService].second;

                /* ===== specialized treatements ===== */
                // generate DNS session record
                if (session.detectedL7 == SuperCodex::Session::DNS) {
                    FeedRefinerDnsTracker::SessionRecord &targetRecord = intermediate.dnsRecords[session.id]; // since we have no idea about the status of the session(full, request only, response only), we store the session information tentatively inside full record
                    targetRecord.sessionId = session.id;
                    targetRecord.secondStart = session.first.second;
                    targetRecord.secondEnd = session.last.second;
                    targetRecord.sourceIp = SuperCodex::sourceIp(session);
                    targetRecord.destinationIp = SuperCodex::destinationIp(session);
                }

                // prepare for TLS dump
                else if (session.detectedL7 == SuperCodex::Session::TLS)
                    tlsDump[session.id] = TlsDump{session.id, session.first.second, session.sourcePort, session.destinationPort, std::string((const char *) session.ips, SuperCodex::ipLength(session.etherType) * 2), {}};

                // session summary for ICMP walk
                else if (session.etherType == 0x0800 && session.payloadProtocol == 1) // ICMPv4
                    icmpSessionSummary[session.id] = IcmpSessionSummary{SuperCodex::sourceIp(session), SuperCodex::destinationIp(session), session.sourceIsSmall};
            }

            // individual packets
            for (auto packet = loader->firstPacket(); packet; packet = loader->nextPacket(packet))
                if (icmpSessionSummary.contains(packet->sessionId)) { // ICMP
                    const auto &sessionSummary = icmpSessionSummary.at(packet->sessionId);
                    auto &target = icmpsToMerge[packet->index];
                    const auto ipLength = sessionSummary.sourceIp.size();
                    // determine direction of IP for given "session"
                    if (sessionSummary.sourceIsSmall == packet->fromSmallToBig) { // from source to destination
                        memcpy(target.ips, sessionSummary.sourceIp.data(), ipLength);
                        memcpy(target.ips + ipLength, sessionSummary.destinationIp.data(), ipLength);
                    } else { // opposite direction
                        memcpy(target.ips, sessionSummary.destinationIp.data(), ipLength);
                        memcpy(target.ips + ipLength, sessionSummary.sourceIp.data(), ipLength);
                    }
                    target.timestamp = packet->second;
                    target.ipLength = ipLength;
                    target.type = packet->tcpSeq;
                    target.code = packet->tcpAck;
                }

            // BPS
            for (auto bps = loader->firstBpsPerSession(); bps; bps = loader->nextBpsPerSession(bps)) {
                auto sum = bps->fromSmallToBig + bps->fromBigToSmall;

                // per second
                bps_ps[bps->second - from] += sum * 8; // change byte to bit

                // per minute per IP
                auto &keys = ipToServiceKeys[bps->sessionId];
                auto &key = keys.keyIpToService;
                auto &keyS = keys.keySource, &keyD = keys.keyDestination;
                if (keys.sourceIsSmall) {
                    keys.keyIpToService.direction = 1;
                    bytes_n.ipToService[key] += bps->fromSmallToBig;
                    key.direction = 0;
                    bytes_n.ipToService[key] += bps->fromBigToSmall;
                } else {
                    key.direction = 1;
                    bytes_n.ipToService[key] += bps->fromBigToSmall;
                    key.direction = 0;
                    bytes_n.ipToService[key] += bps->fromSmallToBig;
                }
                bytes_n.source[keyS] += sum;
                bytes_n.destination[keyD] += sum;
                // value2 for latencies
                latencies_n.source[keyS].bytes += sum;
                latencies_n.destination[keyD].bytes += sum;
                latencies_n.ipToService[key].bytes += sum;
            }

            // PPS
            for (auto pps = loader->firstPpsPerSession(); pps; pps = loader->nextPpsPerSession(pps)) {
                auto sum = pps->fromSmallToBig + pps->fromBigToSmall;
                const auto &session = loader->sessions.at(pps->sessionId);

                // per second
                switch (SuperCodex::castType(*session)) {
                case SuperCodex::UNICAST:
                    pps_ps[pps->second - from].unicast += sum;
                    break;
                case SuperCodex::MULTICAST:
                    pps_ps[pps->second - from].multicast += sum;
                    break;
                case SuperCodex::BROADCAST:
                    pps_ps[pps->second - from].broadcast += sum;
                    break;
                case SuperCodex::UNKNOWN:
                    pps_ps[pps->second - from].unknown += sum;
                    break;
                }

                // per minute per IP
                auto keys = ipToServiceKeys[pps->sessionId];
                auto &key = keys.keyIpToService;
                auto &keyS = keys.keySource, &keyD = keys.keyDestination;
                // IP to service
                if (keys.sourceIsSmall) {
                    key.direction = 1;
                    packets_n.ipToService[key] += pps->fromSmallToBig;
                    rsts_n.ipToService[key].second += sum;
                    dupAcks_n.ipToService[key].second += sum;
                    retransmissions_n.ipToService[key].second += sum;
                    zeroWindows_n.ipToService[key].second += sum;
                    portReused_n.ipToService[key].second += sum;
                    outOfOrders_n.ipToService[key].second += sum;
                    key.direction = 0;
                    packets_n.ipToService[key] += pps->fromBigToSmall;
                    rsts_n.ipToService[key].second += sum;
                    dupAcks_n.ipToService[key].second += sum;
                    retransmissions_n.ipToService[key].second += sum;
                    zeroWindows_n.ipToService[key].second += sum;
                    portReused_n.ipToService[key].second += sum;
                    outOfOrders_n.ipToService[key].second += sum;
                } else {
                    key.direction = 1;
                    packets_n.ipToService[key] += pps->fromBigToSmall;
                    rsts_n.ipToService[key].second += sum;
                    dupAcks_n.ipToService[key].second += sum;
                    retransmissions_n.ipToService[key].second += sum;
                    zeroWindows_n.ipToService[key].second += sum;
                    portReused_n.ipToService[key].second += sum;
                    outOfOrders_n.ipToService[key].second += sum;
                    key.direction = 0;
                    packets_n.ipToService[key] += pps->fromSmallToBig;
                    rsts_n.ipToService[key].second += sum;
                    dupAcks_n.ipToService[key].second += sum;
                    retransmissions_n.ipToService[key].second += sum;
                    zeroWindows_n.ipToService[key].second += sum;
                    portReused_n.ipToService[key].second += sum;
                    outOfOrders_n.ipToService[key].second += sum;
                }
                // per source
                packets_n.source[keyS] += sum;
                rsts_n.source[keyS].second += sum;
                dupAcks_n.source[keyS].second += sum;
                retransmissions_n.source[keyS].second += sum;
                zeroWindows_n.source[keyS].second += sum;
                portReused_n.source[keyS].second += sum;
                outOfOrders_n.source[keyS].second += sum;
                // per destination
                packets_n.destination[keyD] += sum;
                rsts_n.destination[keyD].second += sum;
                dupAcks_n.destination[keyD].second += sum;
                retransmissions_n.destination[keyD].second += sum;
                zeroWindows_n.destination[keyD].second += sum;
                portReused_n.destination[keyD].second += sum;
                outOfOrders_n.destination[keyD].second += sum;
            }

            // RTT / latency
            for (auto rtt = loader->firstRtt(); rtt; rtt = loader->nextRtt(rtt))
                if (rtt->tail < 10000000000) {
                    // simple sanity check
                    if (rtt->tail < 0) {
                        logger.log("Skipping negative RTT tail at "s + std::to_string(rtt->second) + ' ' + std::to_string(rtt->tail));
                        continue;
                    }

                    auto &keys = ipToServiceKeys[rtt->sessionId];
                    auto &key = keys.keyIpToService;
                    auto &keyS = keys.keySource, &keyD = keys.keyDestination;
                    // per second + Per IP-to-service
                    auto &target = rtt_ps[rtt->second - from];
                    if (keys.sourceIsSmall == rtt->fromSmallToBig) {
                        // per second
                        target.numerator0 += rtt->tail;
                        ++target.denominator0;

                        // per minute per IP: key preparation
                        key.direction = 1;
                    } else {
                        // per second
                        target.numerator1 += rtt->tail;
                        ++target.denominator1;

                        // per minute per IP: key preparation
                        key.direction = 0;
                    }
                    auto &topNTarget = latencies_n.ipToService[key];
                    auto &sourceTarget = latencies_n.source[keyS];
                    auto &detinationTarget = latencies_n.destination[keyD];
                    if (key.direction == 1) {
                        topNTarget.numerator0 += rtt->tail;
                        ++topNTarget.denominator0;
                        sourceTarget.numerator0 += rtt->tail;
                        ++sourceTarget.denominator0;
                        detinationTarget.numerator0 += rtt->tail;
                        ++detinationTarget.denominator0;
                    } else {
                        topNTarget.numerator1 += rtt->tail;
                        ++topNTarget.denominator1;
                        sourceTarget.numerator1 += rtt->tail;
                        ++sourceTarget.denominator1;
                        detinationTarget.numerator1 += rtt->tail;
                        ++detinationTarget.denominator1;
                    }

                    // RTT for DNS tracker is filled here
                    if (intermediate.dnsRecords.contains(rtt->sessionId))
                        intermediate.dnsRecords[rtt->sessionId].latency = rtt->tail;
                }

            // timeout
            for (auto timeout = loader->firstTimeout(); timeout; timeout = loader->nextTimeout(timeout)) {
                // per second
                ++timeouts_ps[timeout->marker.second - from];

                // per minute per IP
                const auto &key = FeedRefinerTopN::keyIpToServiceFromSession(timeout->session);
                ++timeouts_n.ipToService[key].first;
                ++timeouts_n.source[FeedRefinerTopN::sourceFromIpToService(key)].first;
                ++timeouts_n.destination[FeedRefinerTopN::destinationFromIpToService(key)].first;

                // recognized timed out DNS sessions for DNS trackers
                if (timeout->session.detectedL7 == SuperCodex::Session::DNS)
                    intermediate.dnsTimeouts.push_back(timeout->session.id);
            }

            // TCP RSTs
            for (auto rst = loader->firstTcpRst(); rst; rst = loader->nextTcpRst(rst)) {
                // per second
                ++rsts_ps[rst->second - from];

                // per minute per IP
                auto &keys = ipToServiceKeys[rst->sessionId];
                auto &key = keys.keyIpToService;
                auto &keyS = keys.keySource, &keyD = keys.keyDestination;
                if (keys.sourceIsSmall == rst->fromSmallToBig)
                    key.direction = 1;
                else
                    key.direction = 0;
                ++rsts_n.ipToService[key].first;
                ++rsts_n.source[keyS].first;
                ++rsts_n.destination[keyD].first;
            }

            // TCP DUP ACKs
            for (auto dupAck = loader->firstTcpDupAck(); dupAck; dupAck = loader->nextTcpDupAck(dupAck)) {
                // per second
                ++dupAcks_ps[dupAck->second - from];

                // per minute per IP
                auto &keys = ipToServiceKeys[dupAck->sessionId];
                auto &key = keys.keyIpToService;
                auto &keyS = keys.keySource, &keyD = keys.keyDestination;
                if (keys.sourceIsSmall == dupAck->fromSmallToBig)
                    key.direction = 1;
                else
                    key.direction = 0;
                ++dupAcks_n.ipToService[key].first;
                ++dupAcks_n.source[keyS].first;
                ++dupAcks_n.destination[keyD].first;
            }

            // TCP retransmissions
            for (auto retransmission = loader->firstTcpRetransmission(); retransmission; retransmission = loader->nextTcpRetransmission(retransmission)) {
                // per second
                ++retransmissions_ps[retransmission->second - from];

                // per minute per IP
                auto &keys = ipToServiceKeys[retransmission->sessionId];
                auto &key = keys.keyIpToService;
                auto &keyS = keys.keySource, &keyD = keys.keyDestination;
                if (keys.sourceIsSmall == retransmission->fromSmallToBig)
                    key.direction = 1;
                else
                    key.direction = 0;
                ++intermediate.retransmissions_n.ipToService[key].first;
                ++retransmissions_n.source[keyS].first;
                ++retransmissions_n.destination[keyD].first;
            }

            // TCP Miscellaneous Anomalies
            for (auto miscAnomaly = loader->firstTcpMiscAnomaly(); miscAnomaly; miscAnomaly = loader->nextTcpMiscAnomaly(miscAnomaly)) {
                // prepare for keys
                auto &keys = ipToServiceKeys[miscAnomaly->sessionId];
                auto &key = keys.keyIpToService;
                auto &keyS = keys.keySource, &keyD = keys.keyDestination;
                if (keys.sourceIsSmall == miscAnomaly->fromSmallToBig)
                    key.direction = 1;
                else
                    key.direction = 0;
                switch (miscAnomaly->tail) {
                case MA_TCPZEROWINDOW:
                    // per second
                    ++zeroWindows_ps[miscAnomaly->second - from];
                    // per minute per IP
                    ++zeroWindows_n.ipToService[key].first;
                    ++zeroWindows_n.source[keyS].first;
                    ++zeroWindows_n.destination[keyD].first;
                    break;
                case MA_TCPPORTSREUSED:
                    // per second
                    ++portReused_ps[miscAnomaly->second - from];
                    // per minute per IP
                    ++portReused_n.ipToService[key].first;
                    ++portReused_n.source[keyS].first;
                    ++portReused_n.destination[keyD].first;
                    break;
                case MA_TCPOUTOFORDER:
                    // per second
                    ++outOfOrders_ps[miscAnomaly->second - from];
                    // per minute per IP
                    ++outOfOrders_n.ipToService[key].first;
                    ++outOfOrders_n.source[keyS].first;
                    ++outOfOrders_n.destination[keyD].first;
                    break;
                default:
                    // just ignore
                    continue;
                }
            }

            // Remarks
            for (auto remarks = loader->firstRemarks(); remarks.content; remarks = loader->nextRemarks(remarks)) {
                const auto &session = loader->sessions.at(remarks.sessionId);
                switch (session->detectedL7) {
                // extract HTTP errors
                case SuperCodex::Session::HTTP: {
                    // prepare for prefix
                    char ipLength = SuperCodex::ipLength(session->etherType);
                    std::string prefix;
                    prefix.append(ipLength * 2 + 1, '\0'); // 9 or 33 bytes
                    prefix[0] = ipLength;
                    memcpy(&prefix[1], session->ips, ipLength * 2);

                    // prepare for variables to recognize session and build description
                    const auto &sessionId = session->id;
                    const std::string humanReadableDestinationIp = SuperCodex::humanReadableIp(SuperCodex::destinationIp(*session));
                    const uint16_t destinationPort = session->destinationPort;
                    std::string_view content(remarks.content, remarks.size);

                    // determine whether this session ends with an orphaned request
                    size_t lastRequest = content.rfind("HttpRequest="s), lastResponse = content.rfind("HttpResponse="s);
                    if (lastRequest != std::string_view::npos && lastRequest > lastResponse) { // this session ends with HTTP request
                        const std::string_view raw = content.substr(lastRequest);
                        httpErrorOrphanedRequests.push_back(std::make_pair(sessionId, prefix + FeedRefinerTopNHttpErrors::buildDescription(raw, humanReadableDestinationIp, destinationPort)));
                    }

                    // we search from end of remarks in reverse direction
                    while (lastResponse != std::string_view::npos) {
                        // check whether the stats code is 4XX or 5XX
                        const size_t statusCodeOffset = lastResponse + 33;
                        const char &statusCodeFiirst = content.at(statusCodeOffset);
                        if (statusCodeFiirst == '4' || statusCodeFiirst == '5') {
                            const size_t pairRequestOffset = content.rfind("HttpRequest=", lastResponse);
                            if (pairRequestOffset == std::string_view::npos) { // this is orphaned response with HTTP 4XX or 5XX in the beginning. We can safely register orphan and break this loop
                                httpErrorOrphanedResponses.push_back(std::make_pair(sessionId, std::string(content.substr(statusCodeOffset, 3))));
                                break;
                            } else {
                                auto newRecord = FeedRefinerTopNHttpErrors::buildDescription(content.substr(pairRequestOffset, content.find("HttpEnd=Request"s, pairRequestOffset) - pairRequestOffset), humanReadableDestinationIp, destinationPort);
                                memcpy(&newRecord[0], &content[statusCodeOffset], 3);
                                ++httpErrors[prefix + newRecord];
                            }
                        }

                        // search for next occurrence
                        if (lastResponse > 0)
                            lastResponse = content.rfind("HttpResponse="s, lastResponse - 13);
                        else // this is orphaned response in the beginning, but it's not HTTP error. We can safely ignore it
                            break;
                    }
                } break;

                // extract data for DNS tracker
                case SuperCodex::Session::DNS: {
                    // build record - session description is filled on loop for filling sessions
                    FeedRefinerDnsTracker::SessionRecord &targetRecord = intermediate.dnsRecords[remarks.sessionId];
                    targetRecord.remarks = std::string(remarks.content, remarks.size);
                    targetRecord.status = FeedRefinerDnsTracker::determineStatus(targetRecord.remarks);
                    targetRecord.query = FeedRefinerDnsTracker::extractQuery(targetRecord.remarks);
                    targetRecord.sessionId = remarks.sessionId;

                    // if the record is orphaned request, move to vector(others are unmoved)
                    if (targetRecord.status == FeedRefinerDnsTracker::REQUESTONLY) {
                        intermediate.dnsRequestOnly.push_back(targetRecord);
                        intermediate.dnsRecords.erase(remarks.sessionId);
                    }
                } break;

                // fill TLS SNI
                case SuperCodex::Session::TLS:
                    tlsDump[remarks.sessionId].sni = FeedRefinerAbstract::remarksValue(std::string_view(remarks.content, remarks.size), "TLSSNI"s);
                    break;

                default:
                    if (icmpSessionSummary.contains(remarks.sessionId)) { // is it ICMP?
                        std::string remarksString(remarks.content, remarks.size);
                        std::istringstream lineReader(remarksString);
                        for (std::string line; std::getline(lineReader, line, '\n');) {
                            const size_t separator = line.find('=');
                            const int32_t packetIndex = std::stoi(line.substr(4, separator - 4));
                            if (icmpsToMerge.contains(packetIndex)) {
                                // get value from line(each line from remarks looks like `ICMP939=17 a87e3f01c0a8010b350038f`)
                                auto &targetPacket = icmpsToMerge[packetIndex];
                                std::string lineValue = line.substr(separator + 1);
                                const size_t recordSplitter = lineValue.find(' '), record2Size = lineValue.size() - recordSplitter - 1;
                                bool ipValid = false, hasPortNumbers = false;
                                switch (record2Size) {
                                case 24: // IPv4
                                    hasPortNumbers = true;
                                case 16: // IPv4 (no port numbers)
                                    ipValid = (targetPacket.ipLength == 4);
                                    break;
                                case 72: // IPv6
                                    hasPortNumbers = true;
                                case 64: // IPv6 (no port number)
                                    ipValid = (targetPacket.ipLength == 16);
                                    break;
                                }
                                if (ipValid)
                                    try { // we have expected length for IP addresses
                                        targetPacket.payloadProtocol = std::stoi(lineValue.substr(0, recordSplitter));
                                        std::string ipPortPartRaw = SuperCodex::stringFromHex(lineValue.substr(recordSplitter + 1));
                                        const char *remarksRawStart = ipPortPartRaw.data();
                                        const size_t ipLengthDouble = targetPacket.ipLength * 2;
                                        memcpy(targetPacket.ipsOriginal, remarksRawStart, ipLengthDouble);
                                        if (hasPortNumbers) { // port number could be 0, since the original packet may NOT have port number(e.g. original packet is ICMP. :P)
                                            targetPacket.port = *(const uint16_t *) (remarksRawStart + ipLengthDouble);
                                            targetPacket.port2 = *(const uint16_t *) (remarksRawStart + ipLengthDouble + 2);
                                        }
                                    } catch (...) {
                                        // remove given record from descriptions
                                        icmpsToMerge.erase(packetIndex);
                                        logger.oops("Failed to parse remarks("s + loader->fileName + "): "s + std::to_string(remarks.sessionId) + "-> " + line);
                                    }
                            }
                        }
                    }
                }
            }

            // post processing for ICMP packets
            auto &intermediateIcmps = intermediate.icmps;
            intermediateIcmps.reserve(icmpsToMerge.size());
            for (const auto &pair : icmpsToMerge)
                intermediateIcmps.push_back(pair.second);
            std::sort(intermediateIcmps.begin(), intermediateIcmps.end(), [](const FeedRefinerIcmpWalk::Description &a, const FeedRefinerIcmpWalk::Description &b) -> bool { return a.timestamp < b.timestamp; });

            // return intermediate result
            return intermediate;
        });

        // reading is complete - merge intermediate data
        if (mergeThread.joinable())
            mergeThread.join();
        mergeThread = std::thread(
            [&](std::vector<Intermediate> intermediatesFuture) {
                for (auto &intermediate : intermediatesFuture) {
                    // merge per second statstics
                    const size_t baseOffset = intermediate.from - final.from;
                    for (int i = 0, iEnd = intermediate.to - intermediate.from + 1; i < iEnd; ++i) {
                        size_t offsetForFinal = baseOffset + i;
                        // special values
                        final.perSecondTotal.pps[offsetForFinal].values += intermediate.pps[i];
                        final.perSecondTotal.rtts[offsetForFinal] += intermediate.rtts[i];
                        // uint64_t
                        final.perSecondTotal.bps[offsetForFinal] += intermediate.bps[i];
                        final.perSecondTotal.timeouts[offsetForFinal] += intermediate.timeouts[i];
                        final.perSecondTotal.rsts[offsetForFinal] += intermediate.rsts[i];
                        final.perSecondTotal.dupAcks[offsetForFinal] += intermediate.dupAcks[i];
                        final.perSecondTotal.retransmissions[offsetForFinal] += intermediate.retransmissions[i];
                        final.perSecondTotal.zeroWindows[offsetForFinal] += intermediate.zeroWindows[i];
                        final.perSecondTotal.portReused[offsetForFinal] += intermediate.portReused[i];
                        final.perSecondTotal.outOfOrders[offsetForFinal] += intermediate.outOfOrders[i];
                        final.perSecondTotal.flowCounts[offsetForFinal] += intermediate.flowCounts[i];
                    }

                    // adjust flow count numbers as needed
                    if (timestampForLastTail == intermediate.from)
                        for (const auto &sessionId : sessionsInLastTail)
                            if (intermediate.sessionsFromHead.contains(sessionId))
                                --final.perSecondTotal.flowCounts[baseOffset];
                    sessionsInLastTail = intermediate.sessionsInTail;
                    timestampForLastTail = intermediate.to;

                    // merge top N data
                    if (final.bytes_n.source.empty())
                        std::swap(final.bytes_n, intermediate.bytes_n);
                    else {
                        for (const auto &pair : intermediate.bytes_n.source)
                            final.bytes_n.source[pair.first] += pair.second;
                        for (const auto &pair : intermediate.bytes_n.destination)
                            final.bytes_n.destination[pair.first] += pair.second;
                        for (const auto &pair : intermediate.bytes_n.ipToService)
                            final.bytes_n.ipToService[pair.first] += pair.second;
                    }
                    if (final.packets_n.source.empty())
                        std::swap(final.packets_n, intermediate.packets_n);
                    else {
                        for (const auto &pair : intermediate.packets_n.source)
                            final.packets_n.source[pair.first] += pair.second;
                        for (const auto &pair : intermediate.packets_n.destination)
                            final.packets_n.destination[pair.first] += pair.second;
                        for (const auto &pair : intermediate.packets_n.ipToService)
                            final.packets_n.ipToService[pair.first] += pair.second;
                    }
                    if (final.latencies_n.source.empty())
                        std::swap(final.latencies_n, intermediate.latencies_n);
                    else {
                        for (const auto &pair : intermediate.latencies_n.source) {
                            auto &target = final.latencies_n.source[pair.first];
                            auto &source = pair.second;
                            target += source;
                        }
                        for (const auto &pair : intermediate.latencies_n.destination) {
                            auto &target = final.latencies_n.destination[pair.first];
                            auto &source = pair.second;
                            target += source;
                        }
                        for (const auto &pair : intermediate.latencies_n.ipToService) {
                            auto &target = final.latencies_n.ipToService[pair.first];
                            auto &source = pair.second;
                            target += source;
                        }
                    }
                    if (final.timeouts_n.source.empty())
                        std::swap(final.timeouts_n, intermediate.timeouts_n);
                    else {
                        for (const auto &pair : intermediate.timeouts_n.source)
                            addPair(final.timeouts_n.source[pair.first], pair.second);
                        for (const auto &pair : intermediate.timeouts_n.destination)
                            addPair(final.timeouts_n.destination[pair.first], pair.second);
                        for (const auto &pair : intermediate.timeouts_n.ipToService)
                            addPair(final.timeouts_n.ipToService[pair.first], pair.second);
                    }
                    if (final.rsts_n.source.empty())
                        std::swap(final.rsts_n, intermediate.rsts_n);
                    else {
                        for (const auto &pair : intermediate.rsts_n.source)
                            addPair(final.rsts_n.source[pair.first], pair.second);
                        for (const auto &pair : intermediate.rsts_n.destination)
                            addPair(final.rsts_n.destination[pair.first], pair.second);
                        for (const auto &pair : intermediate.rsts_n.ipToService)
                            addPair(final.rsts_n.ipToService[pair.first], pair.second);
                    }
                    if (final.dupAcks_n.source.empty())
                        std::swap(final.dupAcks_n, intermediate.dupAcks_n);
                    else {
                        for (const auto &pair : intermediate.dupAcks_n.source)
                            addPair(final.dupAcks_n.source[pair.first], pair.second);
                        for (const auto &pair : intermediate.dupAcks_n.destination)
                            addPair(final.dupAcks_n.destination[pair.first], pair.second);
                        for (const auto &pair : intermediate.dupAcks_n.ipToService)
                            addPair(final.dupAcks_n.ipToService[pair.first], pair.second);
                    }
                    if (final.retransmissions_n.source.empty())
                        std::swap(final.retransmissions_n, intermediate.retransmissions_n);
                    else {
                        for (const auto &pair : intermediate.retransmissions_n.source)
                            addPair(final.retransmissions_n.source[pair.first], pair.second);
                        for (const auto &pair : intermediate.retransmissions_n.destination)
                            addPair(final.retransmissions_n.destination[pair.first], pair.second);
                        for (const auto &pair : intermediate.retransmissions_n.ipToService)
                            addPair(final.retransmissions_n.ipToService[pair.first], pair.second);
                    }
                    if (final.zeroWindows_n.source.empty())
                        std::swap(final.zeroWindows_n, intermediate.zeroWindows_n);
                    else {
                        for (const auto &pair : intermediate.zeroWindows_n.source)
                            addPair(final.zeroWindows_n.source[pair.first], pair.second);
                        for (const auto &pair : intermediate.zeroWindows_n.destination)
                            addPair(final.zeroWindows_n.destination[pair.first], pair.second);
                        for (const auto &pair : intermediate.zeroWindows_n.ipToService)
                            addPair(final.zeroWindows_n.ipToService[pair.first], pair.second);
                    }
                    if (final.portReused_n.source.empty())
                        std::swap(final.portReused_n, intermediate.portReused_n);
                    else {
                        for (const auto &pair : intermediate.portReused_n.source)
                            addPair(final.portReused_n.source[pair.first], pair.second);
                        for (const auto &pair : intermediate.portReused_n.destination)
                            addPair(final.portReused_n.destination[pair.first], pair.second);
                        for (const auto &pair : intermediate.portReused_n.ipToService)
                            addPair(final.portReused_n.ipToService[pair.first], pair.second);
                    }
                    if (final.outOfOrders_n.source.empty())
                        std::swap(final.outOfOrders_n, intermediate.outOfOrders_n);
                    else {
                        for (const auto &pair : intermediate.outOfOrders_n.source)
                            addPair(final.outOfOrders_n.source[pair.first], pair.second);
                        for (const auto &pair : intermediate.outOfOrders_n.destination)
                            addPair(final.outOfOrders_n.destination[pair.first], pair.second);
                        for (const auto &pair : intermediate.outOfOrders_n.ipToService)
                            addPair(final.outOfOrders_n.ipToService[pair.first], pair.second);
                    }

                    // reconnect "orphaned" HTTP requests and responses
                    for (const auto &orphanedReseponse : intermediate.httpErrorOrphanedResponses)
                        if (final.httpErrorOrphanedRequests.contains(orphanedReseponse.first)) {
                            auto toMerge = final.httpErrorOrphanedRequests.extract(orphanedReseponse.first).value().second;
                            size_t statusCodeOffset = toMerge.front() * 2 + 1;
                            memcpy(&toMerge[statusCodeOffset], &orphanedReseponse.second[0], 3);
                            ++final.httpErrors[toMerge];
                        } else
                            final.httpErrorOrphanedResponses.push_back(orphanedReseponse);

                    // register new orphaned HTTP requests
                    for (const auto &request : intermediate.httpErrorOrphanedRequests)
                        final.httpErrorOrphanedRequests.insert(request);

                    // merge Top N HTTP errors
                    if (final.httpErrors.empty())
                        final.httpErrors.swap(intermediate.httpErrors);
                    else
                        for (const auto &pair : intermediate.httpErrors)
                            final.httpErrors[pair.first] += pair.second;

                    // DNS tracker: merge timeouts (merging timeouts against orphaned requests is unnecessary, since the period for timeout 72 seconds and our lookback window is only 60 seconds)
                    for (auto &sessionId : intermediate.dnsTimeouts)
                        final.dnsTimedoutSessions.push_back(sessionId);

                    // DNS tracker: update full records
                    for (auto &pair : intermediate.dnsRecords) {
                        // merge data to descriptions
                        auto &record = pair.second;
                        final.dnsDescriptions[record.destinationIp].mergeSessionRecord(record);

                        // delete orphaned requests as needed
                        if (final.dnsOrphanedRequests.contains(record.sessionId))
                            final.dnsOrphanedRequests.erase(record.sessionId);
                    }

                    // DNS tracker: merge orphaned requests
                    for (auto &record : intermediate.dnsRequestOnly)
                        final.dnsOrphanedRequests[record.sessionId] = record;

                    // ICMP walk: merge all the records
                    for (const auto &item : intermediate.icmps)
                        final.icmpWalkDescriptions.push_back(item);

                    // TLS dumps
                    if (final.tlsDumpsHead.empty()) {
                        auto &head = final.tlsDumpsHead;
                        head.reserve(intermediate.tlsDumps.size());
                        for (const auto &pair : intermediate.tlsDumps)
                            head.push_back(pair.second);
                    } else {
                        auto &dumps = final.tlsDumps;
                        dumps.reserve(dumps.size() + intermediate.tlsDumps.size());
                        for (const auto &pair : intermediate.tlsDumps)
                            dumps.push_back(pair.second);
                    }
                }
            },
            std::move(intermediates));

        return true;
    });

    // finalize
    if (mergeThread.joinable())
        mergeThread.join();

    // sort TLS dump records per timestamp for better indexing
    std::sort(final.tlsDumpsHead.begin(), final.tlsDumpsHead.end(), [](const TlsDump &a, const TlsDump &b) -> bool { return a.timestamp < b.timestamp; });
    std::sort(final.tlsDumps.begin(), final.tlsDumps.end(), [](const TlsDump &a, const TlsDump &b) -> bool { return a.timestamp < b.timestamp; });

    // flush everything to the database at once
    logger.log("Save record"s);

    // preprocess: remove any overlapping records from TLS dump head
    {
        FeatherLite feather(feedPath + dbs.back(), SQLITE_OPEN_READONLY);
        feather.prepare("SELECT EXISTS(SELECT sessionid, timestamp FROM rows WHERE sessionid=? AND timestamp=?);"s);
        auto &head = final.tlsDumpsHead;
        for (auto i = head.begin(); i != head.end();) {
            feather.bindBlob(1, &i->sessionId, 8);
            feather.bindInt64(2, i->timestamp);
            feather.next();
            if (feather.getInt(0) == 1)
                i = head.erase(i);
            else
                ++i;
            feather.reset();
        }
    }

    // try writing to the database
    {
        FeatherLite feather(feedPath + dbs[0]);

        // attach PMPI
        if (!feather.exec("ATTACH '"s + feedPath + dbs[1] + "' AS pmpi;"s))
            return "Failed to attach PMPI. Details: "s + feather.lastError();
        if (!feather.optimize("pmpi"s))
            return "Failed to optimize performance for PMPI. Details: "s + feather.lastError();

        // attach TLS Dump
        if (!feather.exec("ATTACH '"s + feedPath + dbs[2] + "' AS tlsdump;"s))
            return "Failed to attach TLS Dump. Details: "s + feather.lastError();
        if (!feather.optimize("tlsdump"s))
            return "Failed to optimize performance for TLS Dump. Details: "s + feather.lastError();

        // start transaction
        if (!feather.exec("BEGIN TRANSACTION"s))
            return "Failed to begin transaction. Details: "s + feather.lastError();
        // prepare to bind for per second statistics
        if (!feather.prepare("INSERT INTO main.rows(timestamp, chapter, value) VALUES "
                             "(?1, ?2, ?3)," // BPS
                             "(?1, ?4, ?5)," // timeouts
                             "(?1, ?6, ?7)," // RSTS
                             "(?1, ?8, ?9)," // DUPACKs
                             "(?1, ?10, ?11)," // Retransmissions
                             "(?1, ?12, ?13)," // zero windows
                             "(?1, ?14, ?15)," // port reused
                             "(?1, ?16, ?17)," // out of orders
                             "(?1, ?18, ?19)," // flow counts
                             "(?1, ?20, ?21)," // PPS
                             "(?1, ?22, ?23);" // RTTs
                             ))
            return "Failed to prepare for insert into ps. Details: "s + feather.lastError();
        constexpr size_t size60 = sizeof(uint64_t) * 60; // common size for 60 seconds
        // bind timestamp
        if (!feather.bindInt(1, final.from))
            return "Failed to bind 1. Details: "s + feather.lastError();
        // bind BPS
        if (!feather.bindInt(2, SuperCodex::ChapterType::BPSPERSESSION))
            return "Failed to bind 2. Details: "s + feather.lastError();
        if (!feather.bindBlob(3, &final.perSecondTotal.bps, size60))
            return "Failed to bind 3. Details: "s + feather.lastError();
        // bind timeouts
        if (!feather.bindInt(4, SuperCodex::ChapterType::TIMEOUTS))
            return "Failed to bind 4. Details: "s + feather.lastError();
        if (!feather.bindBlob(5, &final.perSecondTotal.timeouts, size60))
            return "Failed to bind 5. Details: "s + feather.lastError();
        // bind TCP RSTs
        if (!feather.bindInt(6, SuperCodex::ChapterType::TCPRSTS))
            return "Failed to bind 6. Details: "s + feather.lastError();
        if (!feather.bindBlob(7, &final.perSecondTotal.rsts, size60))
            return "Failed to bind 7. Details: "s + feather.lastError();
        // bind TCP DUPACKs
        if (!feather.bindInt(8, SuperCodex::ChapterType::TCPDUPACKS))
            return "Failed to bind 8. Details: "s + feather.lastError();
        if (!feather.bindBlob(9, &final.perSecondTotal.dupAcks, size60))
            return "Failed to bind 9. Details: "s + feather.lastError();
        // bind TCP retransmissions
        if (!feather.bindInt(10, SuperCodex::ChapterType::TCPRETRANSMISSIONS))
            return "Failed to bind 10. Details: "s + feather.lastError();
        if (!feather.bindBlob(11, &final.perSecondTotal.retransmissions, size60))
            return "Failed to bind 11. Details: "s + feather.lastError();
        // bind TCP zero windows
        if (!feather.bindInt(12, SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPZEROWINDOW))
            return "Failed to bind 12. Details: "s + feather.lastError();
        if (!feather.bindBlob(13, &final.perSecondTotal.zeroWindows, size60))
            return "Failed to bind 13. Details: "s + feather.lastError();
        // bind TCP port reused
        if (!feather.bindInt(14, SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPPORTSREUSED))
            return "Failed to bind 14. Details: "s + feather.lastError();
        if (!feather.bindBlob(15, &final.perSecondTotal.portReused, size60))
            return "Failed to bind 15. Details: "s + feather.lastError();
        // bind TCP out of order
        if (!feather.bindInt(16, SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPOUTOFORDER))
            return "Failed to bind 16. Details: "s + feather.lastError();
        if (!feather.bindBlob(17, &final.perSecondTotal.outOfOrders, size60))
            return "Failed to bind 17. Details: "s + feather.lastError();
        // bind flow counts
        if (!feather.bindInt(18, SuperCodex::ChapterType::SESSIONS))
            return "Failed to bind 18. Details: "s + feather.lastError();
        if (!feather.bindBlob(19, &final.perSecondTotal.flowCounts, size60))
            return "Failed to bind 19. Details: "s + feather.lastError();
        // bind PPS
        if (!feather.bindInt(20, SuperCodex::ChapterType::PPSPERSESSION))
            return "Failed to bind 20. Details: "s + feather.lastError();
        if (!feather.bindBlob(21, &final.perSecondTotal.pps, sizeof(final.perSecondTotal.pps)))
            return "Failed to bind 21. Details: "s + feather.lastError();
        // bind RTTs
        if (!feather.bindInt(22, SuperCodex::ChapterType::RTTS))
            return "Failed to bind 22. Details: "s + feather.lastError();
        if (!feather.bindBlob(23, &final.perSecondTotal.rtts, sizeof(final.perSecondTotal.rtts)))
            return "Failed to bind 23. Details: "s + feather.lastError();
        // flush
        if (!feather.next())
            return "Failed to next for ps. Details: "s + feather.lastError();
        if (!feather.reset())
            return "Failed to reset ps. Details: "s + feather.lastError();
        if (!feather.finalize())
            return "Failed to finalize ps. Details: "s + feather.lastError();

        // prepare to bind data for per minute per IPs
        if (!feather.prepare("INSERT INTO pmpi.rows(timestamp, chapter, originalsize, filepath) VALUES "
                             "(?1, ?2, ?3, ?4)," // bytes
                             "(?1, ?5, ?6, ?7)," // packets
                             "(?1, ?8, ?9, ?10)," // timeouts
                             "(?1, ?11, ?12, ?13)," // RSTs
                             "(?1, ?14, ?15, ?16)," // DUP ACKs
                             "(?1, ?17, ?18, ?19)," // retransmissions
                             "(?1, ?20, ?21, ?22)," // zero windows
                             "(?1, ?23, ?24, ?25)," // port reused
                             "(?1, ?26, ?27, ?28)," // out of orders
                             "(?1, ?29, ?30, ?31)," // latencies
                             "(?1, ?32, ?33, ?34)," // HTTP errors
                             "(?1, ?35, ?36, ?37)," // DNS tracker
                             "(?1, ?38, ?39, ?40);" // ICMP walk
                             ))
            return "Failed to prepare for insert into pmpi. Details: "s + feather.lastError();
        // bind timestamp
        if (!feather.bindInt(1, final.from))
            return "Failed to bind 1. Details: "s + feather.lastError();
        // bytes
        if (!feather.bindInt(2, SuperCodex::ChapterType::BPSPERSESSION))
            return "Failed to bind 2. Details: "s + feather.lastError();
        std::string pathBytes = savePmpiPrefix + std::to_string(SuperCodex::ChapterType::BPSPERSESSION);
        if (!feather.bindInt(3, compressAndFlushPmpi(pathBytes, final.bytes_n)))
            return "Failed to bind 3. Details: "s + feather.lastError();
        if (!feather.bindText(4, pathBytes))
            return "Failed to bind 4. Details: "s + feather.lastError();
        // packets
        if (!feather.bindInt(5, SuperCodex::ChapterType::PPSPERSESSION))
            return "Failed to bind 5. Details: "s + feather.lastError();
        std::string pathPackets = savePmpiPrefix + std::to_string(SuperCodex::ChapterType::PPSPERSESSION);
        if (!feather.bindInt(6, compressAndFlushPmpi(pathPackets, final.packets_n)))
            return "Failed to bind 6. Details: "s + feather.lastError();
        if (!feather.bindText(7, pathPackets))
            return "Failed to bind 7. Details: "s + feather.lastError();
        // timeouts
        if (!feather.bindInt(8, SuperCodex::ChapterType::TIMEOUTS))
            return "Failed to bind 8. Details: "s + feather.lastError();
        std::string pathTimeouts = savePmpiPrefix + std::to_string(SuperCodex::ChapterType::TIMEOUTS);
        if (!feather.bindInt(9, compressAndFlushPmpi(pathTimeouts, final.timeouts_n)))
            return "Failed to bind 9. Details: "s + feather.lastError();
        if (!feather.bindText(10, pathTimeouts))
            return "Failed to bind 10. Details: "s + feather.lastError();
        // RSTs
        if (!feather.bindInt(11, SuperCodex::ChapterType::TCPRSTS))
            return "Failed to bind 11. Details: "s + feather.lastError();
        std::string pathRsts = savePmpiPrefix + std::to_string(SuperCodex::ChapterType::TCPRSTS);
        if (!feather.bindInt(12, compressAndFlushPmpi(pathRsts, final.rsts_n)))
            return "Failed to bind 12. Details: "s + feather.lastError();
        if (!feather.bindText(13, pathRsts))
            return "Failed to bind 13. Details: "s + feather.lastError();
        // DUP ACKs
        if (!feather.bindInt(14, SuperCodex::ChapterType::TCPDUPACKS))
            return "Failed to bind 14. Details: "s + feather.lastError();
        std::string pathDupAcks = savePmpiPrefix + std::to_string(SuperCodex::ChapterType::TCPDUPACKS);
        if (!feather.bindInt(15, compressAndFlushPmpi(pathDupAcks, final.dupAcks_n)))
            return "Failed to bind 15. Details: "s + feather.lastError();
        if (!feather.bindText(16, pathDupAcks))
            return "Failed to bind 16. Details: "s + feather.lastError();
        // retransmissions
        if (!feather.bindInt(17, SuperCodex::ChapterType::TCPRETRANSMISSIONS))
            return "Failed to bind 17. Details: "s + feather.lastError();
        std::string pathRetransmissions = savePmpiPrefix + std::to_string(SuperCodex::ChapterType::TCPRETRANSMISSIONS);
        if (!feather.bindInt(18, compressAndFlushPmpi(pathRetransmissions, final.retransmissions_n)))
            return "Failed to bind 18. Details: "s + feather.lastError();
        if (!feather.bindText(19, pathRetransmissions))
            return "Failed to bind 19. Details: "s + feather.lastError();
        // zero windows
        if (!feather.bindInt(20, SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPZEROWINDOW))
            return "Failed to bind 20. Details: "s + feather.lastError();
        std::string pathZeroWindows = savePmpiPrefix + std::to_string(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPZEROWINDOW);
        if (!feather.bindInt(21, compressAndFlushPmpi(pathZeroWindows, final.zeroWindows_n)))
            return "Failed to bind 21. Details: "s + feather.lastError();
        if (!feather.bindText(22, pathZeroWindows))
            return "Failed to bind 22. Details: "s + feather.lastError();
        // port reused
        if (!feather.bindInt(23, SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPPORTSREUSED))
            return "Failed to bind 23. Details: "s + feather.lastError();
        std::string pathPortReused = savePmpiPrefix + std::to_string(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPPORTSREUSED);
        if (!feather.bindInt(24, compressAndFlushPmpi(pathPortReused, final.portReused_n)))
            return "Failed to bind 24. Details: "s + feather.lastError();
        if (!feather.bindText(25, pathPortReused))
            return "Failed to bind 25. Details: "s + feather.lastError();
        // out of order
        if (!feather.bindInt(26, SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPOUTOFORDER))
            return "Failed to bind 26. Details: "s + feather.lastError();
        std::string pathOutOfOrder = savePmpiPrefix + std::to_string(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPOUTOFORDER);
        if (!feather.bindInt(27, compressAndFlushPmpi(pathOutOfOrder, final.outOfOrders_n)))
            return "Failed to bind 27. Details: "s + feather.lastError();
        if (!feather.bindText(28, pathOutOfOrder))
            return "Failed to bind 28. Details: "s + feather.lastError();
        // latencies
        if (!feather.bindInt(29, SuperCodex::ChapterType::RTTS))
            return "Failed to bind 29. Details: "s + feather.lastError();
        std::string pathLatencies = savePmpiPrefix + std::to_string(SuperCodex::ChapterType::RTTS);
        if (!feather.bindInt(30, compressAndFlushPmpi(pathLatencies, final.latencies_n)))
            return "Failed to bind 30. Details: "s + feather.lastError();
        if (!feather.bindText(31, pathLatencies))
            return "Failed to bind 31. Details: "s + feather.lastError();
        // HTTP errors
        if (!feather.bindInt(32, SuperCodex::ChapterType::REMARKS + SuperCodex::Session::HTTP))
            return "Failed to bind 32. Details: "s + feather.lastError();
        std::string pathHttpErrors = savePmpiPrefix + std::to_string(SuperCodex::ChapterType::REMARKS + SuperCodex::Session::HTTP);
        if (!feather.bindInt(33, compressAndFlushPmpiHttpErrors(pathHttpErrors, final)))
            return "Failed to bind 33. Details: "s + feather.lastError();
        if (!feather.bindText(34, pathHttpErrors))
            return "Failed to bind 34. Details: "s + feather.lastError();
        // DNS tracker
        if (!feather.bindInt(35, SuperCodex::ChapterType::REMARKS + SuperCodex::Session::DNS))
            return "Failed to bind 35. Details: "s + feather.lastError();
        std::string pathDnsTracker = savePmpiPrefix + std::to_string(SuperCodex::ChapterType::REMARKS + SuperCodex::Session::DNS);
        if (!feather.bindInt(36, compressAndFlushDnsTracker(pathDnsTracker, final)))
            return "Failed to bind 36. Details: "s + feather.lastError();
        if (!feather.bindText(37, pathDnsTracker))
            return "Failed to bind 37. Details: "s + feather.lastError();
        // ICMP walk
        if (!feather.bindInt(38, -1))
            return "Failed to bind 38. Details: "s + feather.lastError();
        std::string pathIcmpWalk = savePmpiPrefix + "-1"s;
        if (!feather.bindInt(39, compressAndFlushIcmpWalk(pathIcmpWalk, final)))
            return "Failed to bind 39. Details: "s + feather.lastError();
        if (!feather.bindText(40, pathIcmpWalk))
            return "Failed to bind 40. Details: "s + feather.lastError();

        // flush
        if (!feather.next())
            return "Failed to call next for pmpi. Details: "s + feather.lastError();
        if (!feather.reset())
            return "Failed to reset pmpi. Details: "s + feather.lastError();
        if (!feather.finalize())
            return "Failed to finalize pmpi. Details: "s + feather.lastError();

        // push TLS dump data
        // push 40 records at once for faster DB push
        if (!feather.prepare("INSERT INTO tlsdump.rows(sessionid, timestamp, ips, clientport, serverport, sni) VALUES"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?),"
                             "(?,?,?,?,?,?);"s))
            return "Failed to prepare for insert into tls(phase 1). Details: "s + feather.lastError();
        for (int i = 0, iEnd = final.tlsDumps.size() / 40 * 40; i < iEnd; ++i) {
            const auto &record = final.tlsDumps[i];
            int bindOffset = (i % 40) * 6 + 1; // reminder (%) calculation: there can be multiple of 40 records(e.g. 80, 120, ......)
            if (!feather.bindBlob(bindOffset, &record.sessionId, 8))
                return "Failed to bind session ID to tls(phase 1). Details: "s + feather.lastError();
            if (!feather.bindInt64(bindOffset + 1, record.timestamp))
                return "Failed to bind timestamp to tls(phase 1). Details: "s + feather.lastError();
            if (!feather.bindBlob(bindOffset + 2, record.ips.data(), record.ips.size()))
                return "Failed to bind IPs to tls(phase 1). Details: "s + feather.lastError();
            if (!feather.bindInt(bindOffset + 3, record.clientPort))
                return "Failed to bind client port to tlsdump(phase 1). Details: "s + feather.lastError();
            if (!feather.bindInt(bindOffset + 4, record.serverPort))
                return "Failed to bind server port to tls(phase 1). Details: "s + feather.lastError();
            if (!feather.bindText(bindOffset + 5, record.sni))
                return "Failed to bind SNI to tls(phase 1). Details: "s + feather.lastError();

            // flush if all 40 slots are fully filled
            if (i % 40 == 39) {
                if (!feather.next())
                    return "Failed to move cursor in tls(phase 1). Details: "s + feather.lastError();
                if (!feather.reset())
                    return "Failed to reset statement in tls(phase 1). Details: "s + feather.lastError();
            }
        }
        feather.finalize();

        // push anything remaining
        if (!feather.prepare("INSERT INTO tlsdump.rows(sessionid, timestamp, ips, clientport, serverport, sni) VALUES(?,?,?,?,?,?);"))
            return "Failed to prepare for insert into tls(phase 2). Details: "s + feather.lastError();
        for (int i = final.tlsDumps.size() / 40 * 40, iEnd = final.tlsDumps.size(); i < iEnd; ++i) {
            const auto &record = final.tlsDumps[i];
            if (!feather.bindBlob(1, &record.sessionId, 8))
                return "Failed to bind session ID to tls(phase 2). Details: "s + feather.lastError();
            if (!feather.bindInt64(2, record.timestamp))
                return "Failed to bind timestamp to tls(phase 3). Details: "s + feather.lastError();
            if (!feather.bindBlob(3, record.ips.data(), record.ips.size()))
                return "Failed to bind IPs to tls(phase 2). Details: "s + feather.lastError();
            if (!feather.bindInt(4, record.clientPort))
                return "Failed to bind client port to tls(phase 2). Details: "s + feather.lastError();
            if (!feather.bindInt(5, record.serverPort))
                return "Failed to bind server port to tls(phase 2). Details: "s + feather.lastError();
            if (!feather.bindText(6, record.sni))
                return "Failed to bind SNI to tls(phase 2). Details: "s + feather.lastError();

            if (!feather.next())
                return "Failed to move cursor in tls(phase 2). Details: "s + feather.lastError();
            if (!feather.reset())
                return "Failed to reset statement in tls(phase 2). Details: "s + feather.lastError();
        }
        feather.finalize();

        // commit
        if (!feather.exec("COMMIT"s))
            return "Failed to commit. Details: "s + feather.lastError();
    }

    // declare data is flushed
    logger.log("Flushed"s);
    return ""s;
}

int SuperCache::compressAndFlushPmpi(const std::string &filePath, const SuperCache::PmpiPack<uint64_t> &rawData)
{
    int result = 0;

    if (!rawData.source.empty()) {
        // prepare for variables
        int32_t sourceSize = rawData.source.size(), destinationSize = rawData.destination.size(), ipToServiceSize = rawData.ipToService.size();
        std::string compressionBuffer;
        compressionBuffer.reserve((sourceSize + destinationSize) * pmpiSizeSingle + ipToServiceSize * pmpiSizeIpToService + 12); // 12: 3 int32_t (3 integers to save length of individual records)

        // extract: source
        {
            auto values = rawData.source.values();
            std::sort(values.begin(), values.end(), [](const std::pair<FeedRefinerTopN::KeySingle, uint64_t> &a, const std::pair<FeedRefinerTopN::KeySingle, uint64_t> &b) -> bool { return a.second > b.second; });
            while (!values.empty() && values.back().second == 0)
                values.pop_back();
            int32_t rawLength = sourceSize * pmpiSizeSingle;
            compressionBuffer.append((const char *) &rawLength, 4).append((const char *) values.data(), rawLength);
        }

        // exract: destination
        {
            auto values = rawData.destination.values();
            std::sort(values.begin(), values.end(), [](const std::pair<FeedRefinerTopN::KeySingle, uint64_t> &a, const std::pair<FeedRefinerTopN::KeySingle, uint64_t> &b) -> bool { return a.second > b.second; });
            while (!values.empty() && values.back().second == 0)
                values.pop_back();
            int32_t rawLength = destinationSize * pmpiSizeSingle;
            compressionBuffer.append((const char *) &rawLength, 4).append((const char *) values.data(), rawLength);
        }

        // extract: IP-to-service
        {
            auto values = rawData.ipToService.values();
            std::sort(values.begin(), values.end(), [](const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> &a, const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> &b) -> bool { return a.second > b.second; });
            while (!values.empty() && values.back().second == 0)
                values.pop_back();
            int32_t rawLength = ipToServiceSize * pmpiSizeIpToService;
            compressionBuffer.append((const char *) &rawLength, 4).append((const char *) values.data(), rawLength);
        }

        // compress data and save to the disk
        result = compressionBuffer.size();
        auto compressed = SuperCodex::compress((const char *) compressionBuffer.data(), result);
        std::ofstream file(filePath, std::ios::trunc | std::ios::binary);
        file.write((const char *) compressed.data, compressed.size);
        file.close();
        delete[] compressed.data;
    }

    return result;
}

int SuperCache::compressAndFlushPmpi(const std::string &filePath, const PmpiPack<std::pair<uint64_t, uint64_t>> &rawData)
{
    int result = 0;

    if (!rawData.source.empty()) {
        // prepare for variables
        int32_t sourceSize = rawData.source.size(), destinationSize = rawData.destination.size(), ipToServiceSize = rawData.ipToService.size();
        std::string compressionBuffer;
        compressionBuffer.reserve((sourceSize + destinationSize) * pmpiSizeSingle2 + ipToServiceSize * pmpiSizeIpToService2 + 12); // 12: 3 int32_t (3 integers to save length of individual records)

        // extract: source
        {
            auto values = rawData.source.values();
            std::sort(values.begin(), values.end(), [](const std::pair<FeedRefinerTopN::KeySingle, std::pair<uint64_t, uint64_t>> &a, const std::pair<FeedRefinerTopN::KeySingle, std::pair<uint64_t, uint64_t>> &b) -> bool { return a.second.first > b.second.first; });
            while (!values.empty() && values.back().second.first == 0)
                values.pop_back();
            int32_t rawLength = sourceSize * pmpiSizeSingle2;
            compressionBuffer.append((const char *) &rawLength, 4).append((const char *) values.data(), rawLength);
        }

        // exract: destination
        {
            auto values = rawData.destination.values();
            std::sort(values.begin(), values.end(), [](const std::pair<FeedRefinerTopN::KeySingle, std::pair<uint64_t, uint64_t>> &a, const std::pair<FeedRefinerTopN::KeySingle, std::pair<uint64_t, uint64_t>> &b) -> bool { return a.second.first > b.second.first; });
            while (!values.empty() && values.back().second.first == 0)
                values.pop_back();
            int32_t rawLength = destinationSize * pmpiSizeSingle2;
            compressionBuffer.append((const char *) &rawLength, 4).append((const char *) values.data(), rawLength);
        }

        // extract: IP-to-service
        {
            auto values = rawData.ipToService.values();
            std::sort(values.begin(), values.end(), [](const std::pair<FeedRefinerTopN::KeyIpToService, std::pair<uint64_t, uint64_t>> &a, const std::pair<FeedRefinerTopN::KeyIpToService, std::pair<uint64_t, uint64_t>> &b) -> bool { return a.second.first > b.second.first; });
            while (!values.empty() && values.back().second.first == 0)
                values.pop_back();
            int32_t rawLength = ipToServiceSize * pmpiSizeIpToService2;
            compressionBuffer.append((const char *) &rawLength, 4).append((const char *) values.data(), rawLength);
        }

        // compress data and save to the disk
        result = compressionBuffer.size();
        auto compressed = SuperCodex::compress((const char *) compressionBuffer.data(), result);
        std::ofstream file(filePath, std::ios::trunc | std::ios::binary);
        file.write((const char *) compressed.data, compressed.size);
        file.close();
        delete[] compressed.data;
    }

    return result;
}

int SuperCache::compressAndFlushPmpi(const std::string &filePath, const SuperCache::PmpiPack<FeedRefinerAbstract::ValuesRtt> &rawData)
{
    int result = 0;

    if (!rawData.source.empty()) {
        // prepare for variables
        int32_t sourceSize = rawData.source.size(), destinationSize = rawData.destination.size(), ipToServiceSize = rawData.ipToService.size();
        std::string compressionBuffer;
        compressionBuffer.reserve((sourceSize + destinationSize) * pmpiSizeSingleRtt + ipToServiceSize * pmpiSizeIpToService2 + 12); // 12: 3 int32_t (3 integers to save length of individual records)

        // extract: source
        {
            auto values = rawData.source.values();
            std::sort(values.begin(), values.end(), [](const std::pair<FeedRefinerTopN::KeySingle, FeedRefinerAbstract::ValuesRtt> &a, const std::pair<FeedRefinerTopN::KeySingle, FeedRefinerAbstract::ValuesRtt> &b) -> bool { return a.second.represent() > b.second.represent(); });
            while (!values.empty() && values.back().second.represent() == 0)
                values.pop_back();
            int32_t rawLength = sourceSize * pmpiSizeSingleRtt;
            compressionBuffer.append((const char *) &rawLength, 4).append((const char *) values.data(), rawLength);
        }

        // extract: destination
        {
            auto values = rawData.destination.values();
            std::sort(values.begin(), values.end(), [](const std::pair<FeedRefinerTopN::KeySingle, FeedRefinerAbstract::ValuesRtt> &a, const std::pair<FeedRefinerTopN::KeySingle, FeedRefinerAbstract::ValuesRtt> &b) -> bool { return a.second.represent() > b.second.represent(); });
            while (!values.empty() && values.back().second.represent() == 0)
                values.pop_back();
            int32_t rawLength = destinationSize * pmpiSizeSingleRtt;
            compressionBuffer.append((const char *) &rawLength, 4).append((const char *) values.data(), rawLength);
        }

        // extract: IP-to-service
        {
            auto values = rawData.ipToService.values();
            std::sort(values.begin(), values.end(), [](const std::pair<FeedRefinerTopN::KeyIpToService, FeedRefinerAbstract::ValuesRtt> &a, const std::pair<FeedRefinerTopN::KeyIpToService, FeedRefinerAbstract::ValuesRtt> &b) -> bool { return a.second.represent() > b.second.represent(); });
            while (!values.empty() && values.back().second.represent() == 0)
                values.pop_back();
            int32_t rawLength = ipToServiceSize * pmpiSizeIpToServiceRtt;
            compressionBuffer.append((const char *) &rawLength, 4).append((const char *) values.data(), rawLength);
        }

        // compress data and save to the disk
        result = compressionBuffer.size();
        auto compressed = SuperCodex::compress((const char *) compressionBuffer.data(), result);
        std::ofstream file(filePath, std::ios::trunc | std::ios::binary);
        file.write((const char *) compressed.data, compressed.size);
        file.close();
        delete[] compressed.data;
    }

    return result;
}

int SuperCache::compressAndFlushPmpiHttpErrors(const std::string &filePath, const Final &final)
{
    HttpErrorHeader header;

    // serialize orphaned requests
    std::string orphanedRequestsSerialized;
    orphanedRequestsSerialized.reserve(final.httpErrorOrphanedRequests.size() * 85); // 77 + 8 = 85. premise: mean length of a URL is about 77, which is used on reserving RAM. reference: https://stackoverflow.com/questions/6168962/typical-url-lengths-for-storage-calculation-purposes-url-shortener
    for (const auto &pair : final.httpErrorOrphanedRequests) {
        header.value = pair.first; // session ID
        header.descriptionLength = pair.second.size();
        orphanedRequestsSerialized.append((const char *) &header, httpErrorHeaderSize).append(pair.second.data(), pair.second.size());
    }

    // serialize orphaned responses
    std::string orphanedResponsesSerialized;
    orphanedResponsesSerialized.reserve(final.httpErrorOrphanedResponses.size() * httpErrorHeaderSize); // status code is only 3 bytes long, so we can store everything in HttpErrorHeader
    for (const auto &pair : final.httpErrorOrphanedResponses) {
        header.value = pair.first; // session ID
        header.descriptionLength = 0;
        memcpy(&header.descriptionLength, &pair.second[0], 3); // descriptionLength is treated as 8-byte string buffer (only here)
        orphanedResponsesSerialized.append((const char *) &header, httpErrorHeaderSize);
    }

    // serialize full records
    std::string fullErrors;
    fullErrors.reserve(final.httpErrors.size() * 85);
    for (const auto &pair : final.httpErrors) {
        header.value = pair.second; // number of hits
        header.descriptionLength = pair.first.size();
        fullErrors.append((const char *) &header, httpErrorHeaderSize).append(pair.first.data(), pair.first.size());
    }

    // merge serialized data
    std::string merged;
    merged.reserve(12 + orphanedRequestsSerialized.size() + orphanedResponsesSerialized.size() + fullErrors.size());
    uint32_t size;
    size = orphanedRequestsSerialized.size();
    merged.append((const char *) &size, 4).append(orphanedRequestsSerialized);
    size = orphanedResponsesSerialized.size();
    merged.append((const char *) &size, 4).append(orphanedResponsesSerialized);
    size = fullErrors.size();
    merged.append((const char *) &size, 4).append(fullErrors);

    // compress data and save to the disk
    int result = merged.size();
    auto compressed = SuperCodex::compress((const char *) merged.data(), result);
    std::ofstream file(filePath, std::ios::trunc | std::ios::binary);
    file.write((const char *) compressed.data, compressed.size);
    file.close();
    delete[] compressed.data;

    return result;
}

int SuperCache::compressAndFlushDnsTracker(const std::string &filePath, const Final &final)
{
    // prepare for variables
    std::string merged, part;
    uint32_t partSize;

    // merge timeouts
    size_t byteLength = final.dnsTimedoutSessions.size() * 8;
    part.reserve(byteLength);
    part = std::string((const char *) final.dnsTimedoutSessions.data(), byteLength);
    partSize = part.size();
    merged.append((const char *) &partSize, 4).append(part);
    part.clear();

    // merge request only records
    part.reserve((final.dnsOrphanedRequests.size() + 15) * dnsSessionHeaderSize);
    for (const auto &pair : final.dnsOrphanedRequests) {
        auto serialized = DnsSessionHeader::fromDnsTrackerSessionRecord(pair.second);
        part.append((const char *) &serialized, dnsSessionHeaderSize).append(pair.second.query);
    }
    partSize = part.size();
    merged.append((const char *) &partSize, 4).append(part);
    part.clear();

    // merge main body: server IP + <status[0..4] + <DNS query + <deduplicated client IPs + number of hits>>>
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);
    for (const auto &serverIpPair : final.dnsDescriptions) { // server IP + description
        // register new server IP
        const std::string serverIpHex = SuperCodex::stringToHex(serverIpPair.first);
        yyjson_mut_val *dnsQueryStatusArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add(rootObject, yyjson_mut_strncpy(document, serverIpHex.data(), serverIpHex.size()), dnsQueryStatusArray);

        // register status
        for (int32_t i = 0; i < 5; ++i) {
            const auto &details = serverIpPair.second.details[i];
            yyjson_mut_val *dnsQueryStatusRepresentative = yyjson_mut_obj(document); // object to contain all the objects describing hits per DNS query
            yyjson_mut_arr_add_val(dnsQueryStatusArray, dnsQueryStatusRepresentative);
            // register individual query
            for (const auto &queryPair : details) { // DNS query string + <client IP + usage data>
                yyjson_mut_val *dnsQueryStringWithUsageData = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, dnsQueryStatusRepresentative, queryPair.first.data(), dnsQueryStringWithUsageData); // key: DNS query string, value: object to contain client hits (IP address + usage data)
                // push client IP + hits per given query
                for (const auto &clientPair : queryPair.second) { // client IP + usage data(hits and latency)
                    std::string clientIpHex = SuperCodex::stringToHex(clientPair.first);
                    yyjson_mut_val *usage = yyjson_mut_obj(document);
                    yyjson_mut_obj_add(dnsQueryStringWithUsageData, yyjson_mut_strncpy(document, clientIpHex.data(), clientIpHex.size()), usage);
                    yyjson_mut_obj_add_uint(document, usage, "hits", clientPair.second.hits);
                    yyjson_mut_obj_add_uint(document, usage, "fastest", clientPair.second.fastest);
                    yyjson_mut_obj_add_uint(document, usage, "slowest", clientPair.second.slowest);
                    yyjson_mut_obj_add_uint(document, usage, "sum", clientPair.second.sum);
                }
            }
        }
    }
    // add JSON to merged
    size_t jsonSize;
    char *jsonRaw = yyjson_mut_write(document, YYJSON_WRITE_NOFLAG, &jsonSize);
    partSize = jsonSize;
    merged.append((const char *) &partSize, 4).append(jsonRaw, jsonSize);
    free(jsonRaw);
    yyjson_mut_doc_free(document);

    // compress data and save to the disk
    int result = merged.size();
    auto compressed = SuperCodex::compress((const char *) merged.data(), result);
    std::ofstream file(filePath, std::ios::trunc | std::ios::binary);
    file.write((const char *) compressed.data, compressed.size);
    file.close();
    delete[] compressed.data;

    return result;
}

int SuperCache::compressAndFlushIcmpWalk(const std::string &filePath, const Final &final)
{
    // compress data and save to the disk
    int result = final.icmpWalkDescriptions.size() * FeedRefinerIcmpWalk::descriptionSize;
    auto compressed = SuperCodex::compress((const char *) final.icmpWalkDescriptions.data(), result);
    std::ofstream file(filePath, std::ios::trunc | std::ios::binary);
    file.write((const char *) compressed.data, compressed.size);
    file.close();
    delete[] compressed.data;

    return result;
}

void SuperCache::addPair(std::pair<uint64_t, uint64_t> &a, const std::pair<uint64_t, uint64_t> &b)
{
    a.first += b.first;
    a.second += b.second;
}

SuperCache::PmpiTriplet SuperCache::getPmpiTriplet(const std::string &file, const size_t decompressedSize)
{
    PmpiTriplet result{}; // if result.decompressedRaw is nullptr, we can say that we have some problem

    // decompress raw data
    std::string compressed(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(file, std::ifstream::binary).rdbuf()).str());
    if (compressed.size() <= 12) // exception handling: there's only length bytes or is null
        return result;
    result.decompressedRaw = SuperCodex::decompress(SuperCodex::Glyph{(char *) compressed.data(), static_cast<int32_t>(compressed.size())}, compressed.size(), decompressedSize);

    int32_t length;
    // per source
    const char *cursor = result.decompressedRaw;
    length = *(const int32_t *) cursor;
    cursor += 4;
    result.perSourceRaw = std::string_view(cursor, length);
    // per destination
    cursor += length;
    length = *(const int32_t *) cursor;
    cursor += 4;
    result.perDestinationRaw = std::string_view(cursor, length);
    // per IP-to-service
    cursor += length;
    length = *(const int32_t *) cursor;
    cursor += 4;
    result.perIpToServiceRaw = std::string_view(cursor, length);

    return result;
}
