#include "supercache0.h"
#include "supercache.h"
#include "datafeed.h"
#include "codexindex.h"
#include "../featherlite.h"

#include <ankerl/unordered_dense.h>
#include <yyjson.h>
#include <sstream>

using namespace std::string_literals;

std::string SuperCacheZero::feedPath;
std::vector<SuperCacheZero::SignaturePack> SuperCacheZero::signatures;

std::vector<std::string> SuperCacheZero::dbs = {
    "/supercache.ps2"s // per second per signature
};
std::vector<std::string> SuperCacheZero::ddls = {
    // table 0: per second per signature
    "CREATE TABLE rows(timestamp INTEGER, chapter INTEGER, signature BIGINT, value BLOB);"
    "CREATE UNIQUE INDEX idx1 ON rows(timestamp,chapter,signature);"s,
};

Logger SuperCacheZero::logger("SuperCacheZero"s);

void SuperCacheZero::start()
{
    logger.log("Startup"s);
    auto nextCheckpoint = std::chrono::steady_clock::now() + std::chrono::hours(1);
    while (true) {
        // calculate time until next minute
        std::chrono::steady_clock::time_point nextStart = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        feedPath.clear();

        // try to build signature from user defined services(but, IP addresses only) to build the prototype for signatures
        ankerl::unordered_dense::set<uint32_t> signatureSetProto;
        std::vector<SignaturePack> signaturesProto;
        {
            bool prepared = false;
            while (!prepared) {
                // open database for user defined applications
                FeatherLite feather("apps.user"s, SQLITE_OPEN_READONLY);
                prepared = feather.prepare("SELECT ips FROM raw;"s);
                if (!prepared) { // if the database is not prepared, sleep for 1 seoncd and try again
                    logger.oops("User defined service database not ready. Trying again in 1 second");
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;
                }

                // build signatures
                while (feather.next() == SQLITE_ROW) {
                    // apply IP addresses
                    SuperCodex::IpFilter ipFilter;
                    std::string ips(feather.getText(0));
                    std::istringstream ipSplitter(ips);
                    for (std::string ip; std::getline(ipSplitter, ip, ',');)
                        ipFilter.registerNetwork(ip);

                    // register signature
                    if (!ipFilter.isEmpty) {
                        const uint32_t signature = ipFilter.signature();
                        if (!signatureSetProto.contains(signature)) { // check duplicate signatures to prevent from overlapping jobs
                            signatureSetProto.insert(signature);
                            signaturesProto.push_back(SignaturePack{{}, std::move(ipFilter), signature, false});
                        }
                    }
                }
            }
        }

        // for each data feed
        for (const auto &feed : DataFeed::describeFeeds()) {
            // initialize variables and database
            feedPath = CodexIndex::feedRoot + feed.name;
            SuperCache::initializeDatabase(feedPath, dbs, ddls);
            ankerl::unordered_dense::set<uint32_t> signatureSet = signatureSetProto;
            signatures = signaturesProto;

            // build signatures from tags
            std::filesystem::path tagsJsonPath(feedPath + "/tags.json"s);
            if (std::filesystem::exists(tagsJsonPath)) {
                // read file
                yyjson_doc *document = yyjson_read_file(tagsJsonPath.string().data(), YYJSON_READ_NOFLAG, nullptr, nullptr);
                yyjson_val *rootObject = yyjson_doc_get_root(document);
                yyjson_val *tagName, *tagDescription;
                yyjson_obj_iter iterator = yyjson_obj_iter_with(rootObject);
                while ((tagName = yyjson_obj_iter_next(&iterator))) { // for each tag......
                    // extract registered IPs
                    SuperCodex::IpFilter ipFilter;
                    tagDescription = yyjson_obj_iter_get_val(tagName);
                    yyjson_val *ips = yyjson_obj_get(tagDescription, "ips"), *ip;
                    yyjson_arr_iter ipsIterator = yyjson_arr_iter_with(ips);

                    // read(and optionally unfold) IP addresses
                    while ((ip = yyjson_arr_iter_next(&ipsIterator)))
                        ipFilter.registerNetwork(yyjson_get_str(ip));

                    // build signature for this tag
                    if (!ipFilter.isEmpty) {
                        const uint32_t signature = ipFilter.signature();
                        if (!signatureSet.contains(signature)) { // check duplicate signatures to prevent from overlapping jobs
                            signatureSet.insert(signature);
                            signatures.push_back(SignaturePack{{}, std::move(ipFilter), signature, false});
                        }
                    }
                }
            }

            // declare some variables to use for future processing
            ankerl::unordered_dense::set<uint32_t> signaturesFromDbs;
            uint32_t startingPoint;

            // introduce new curly brace pair to limit scope for reusable FeatherLite object
            {
                // initialize database connector
                FeatherLite feather(feedPath + dbs[0]);

                // get signatures from database
                if (!feather.prepare("SELECT DISTINCT signature FROM rows;"s)) {
                    logger.oops("Failed to get signature from database. Details: "s + feather.lastError());
                    continue;
                }
                while (feather.next() == SQLITE_ROW)
                    signaturesFromDbs.insert((uint64_t) feather.getInt64(0));
                feather.finalize();

                // remove records that doesn't exist in current tag. CAUTION: currently we have only 1 table to catch up. This may be changed in the future
                if (!feather.prepare("DELETE FROM rows WHERE signature=?;"s)) {
                    logger.oops("Failed to prepare for signature cleanup. Deetails: "s + feather.lastError());
                    continue;
                }
                for (const auto &signature : signaturesFromDbs)
                    if (!signatureSet.contains(signature)) {
                        logger.log("Deleteing signature "s + std::to_string(signature));
                        feather.bindInt64(1, (int64_t) signature);
                        feather.next();
                        feather.reset();
                    }
                feather.finalize();

                // determine starting timestamp from per second statistics records, which must have the least records by design
                if (!feather.prepare("SELECT MAX(timestamp) FROM rows;")) {
                    logger.oops("Failed to prepare for statement on getting last starting point. Details: "s + feather.lastError());
                    continue;
                }
                if (feather.next() == SQLITE_ROW)
                    startingPoint = feather.getInt(0);
                else {
                    logger.oops("Failed to fetch timestamp to build cache for "s + feed.name + ". Details: "s + feather.lastError());
                    continue;
                }
                if (startingPoint < feed.from)
                    startingPoint = feed.from / 60 * 60 + 60;
            }

            // build cache for brand new tags from the beginning of the tags to current
            int newTagsCount = 0;
            for (auto &signature : signatures)
                if (!signaturesFromDbs.contains(signature.signature)) {
                    signature.buildNow = true;
                    newTagsCount++;
                }
            if (newTagsCount) {
                logger.log("Introduce "s + std::to_string(newTagsCount) + " new signatures for "s + feed.name);
                for (int32_t i = feed.from / 60 * 60 + 60; i < startingPoint; i += 60) {
                    const std::string encounteredError = buildCache(feed.name, i);
                    if (!encounteredError.empty()) { // if an error is found, stop generating SuperCache
                        logger.oops(encounteredError);
                        break;
                    }
                }
            }

            // build cache for everything
            for (auto &pair : signatures)
                pair.buildNow = true;
            if (!signatures.empty()) {
                for (int32_t i = startingPoint + 60; i + 60 < feed.to; i += 60) { // condition: remaining windows should be bigger than 60 seconds
                    const std::string encounteredError = buildCache(feed.name, i);
                    if (!encounteredError.empty()) { // if an error is found, stop generating SuperCache
                        logger.oops(encounteredError);
                        break;
                    }
                }
            }
        }

        // cleanup and finalize
        if (std::chrono::steady_clock::now() >= nextCheckpoint) { // in next period(now per an hour)
            // checkpoint database and remove too old records
            SuperCache::checkpointDatabase(dbs);
            nextCheckpoint = std::chrono::steady_clock::now() + std::chrono::hours(1);
        }
        std::this_thread::sleep_until(nextStart);
    }
}

std::string SuperCacheZero::buildCache(const std::string &feedName, const uint32_t from)
{
    logger.log("Build cache: "s + feedName + " from "s + std::to_string(from));
    const size_t numberOfSignatures = signatures.size();

    // query list of SuperCodex files
    SuperCodex::Conditions conditions;
    conditions.from = from;
    conditions.to = from + 59;
    conditions.dataFeed = feedName;
    conditions.codicesToGo = DataFeed::codexIndex->codices(conditions);
    if (conditions.codicesToGo.empty()) {
        logger.log("No SuperCodex files to process: "s + std::to_string(conditions.from) + " -> "s + std::to_string(conditions.to));
        return ""; // there can be missing SuperCodex files in the middle(e.g. packet capture was stopped for some time, i.e. 1~2 hours, due to some external reason)
    }

    // prepare for a few variables to read and store stuff
    SuperCodex::ChapterType chaptersToOpen = static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::BPSPERSESSION | SuperCodex::PPSPERSESSION | SuperCodex::RTTS | SuperCodex::TIMEOUTS | SuperCodex::TCPRSTS | SuperCodex::TCPMISCANOMALIES | SuperCodex::TCPRETRANSMISSIONS | SuperCodex::TCPDUPACKS);
    std::thread mergeThread;
    Final final(from, numberOfSignatures);
    std::vector<std::vector<uint64_t>> sessionsInTail;
    uint32_t timestampForLastTail;
    sessionsInTail.resize(numberOfSignatures);
    const std::string savePmpiPrefix = std::filesystem::path(conditions.codicesToGo.front()).parent_path().string() + "/pmpi."s + std::to_string(from) + '.';

    logger.log("Read SuperCodex files: "s + conditions.codicesToGo.front() + " -> "s + conditions.codicesToGo.back());
    // read SuperCodex files in parallel and refine intermediate results
    FeedConsumer::consumeByChunk(conditions, chaptersToOpen, std::thread::hardware_concurrency(), [&](std::vector<SuperCodex::Loader *> &codicesLoaded, const bool isFinal) -> bool {
        std::vector<Intermediate> intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, Intermediate>(codicesLoaded, [&](const SuperCodex::Loader *loader) -> Intermediate {
            // initialize variables
            Intermediate intermediate{};
            intermediate.from = std::max(loader->secondStart, conditions.from);
            intermediate.to = std::min(loader->secondEnd, conditions.to);

            // declare some shortcuts
            auto &packs = intermediate.packs;
            packs.resize(numberOfSignatures);
            const auto from = intermediate.from, to = intermediate.to;

            // simple sanity check
            if (to < from) {
                logger.oops("Corrupt lookback window: "s + loader->fileName + ' ' + std::to_string(from) + " -> "s + std::to_string(to));
                return intermediate;
            }

            // prepare for storage
            const size_t duration = to - from + 1;
            for (auto &pack : packs) {
                pack.pps.resize(duration, {});
                pack.rtts.resize(duration, {});
                pack.bps.resize(duration, 0);
                pack.timeouts.resize(duration, 0);
                pack.rsts.resize(duration, 0);
                pack.dupAcks.resize(duration, 0);
                pack.retransmissions.resize(duration, 0);
                pack.zeroWindows.resize(duration, 0);
                pack.portReused.resize(duration, 0);
                pack.outOfOrders.resize(duration, 0);
                pack.flowCounts.resize(duration, 0);
            }

            // build keys from sessions, count number of flows per second
            ankerl::unordered_dense::map<uint64_t, ankerl::unordered_dense::set<size_t>> sessionToSignatureIndex; // session ID + index for the signature(s)
            sessionToSignatureIndex.reserve(loader->sessions.size());
            for (const auto &pair : loader->sessions) {
                const SuperCodex::Session &session = *pair.second;

                // determine to which table index this session belongs to
                std::string sourceIp = SuperCodex::sourceIp(session), destinationIp = SuperCodex::destinationIp(session);
                for (size_t i = 0; i < numberOfSignatures; ++i) {
                    const auto &signature = signatures[i];
                    if (signature.filter.contains(sourceIp))
                        sessionToSignatureIndex[session.id].insert(i);
                    if (signature.filter.contains(destinationIp))
                        sessionToSignatureIndex[session.id].insert(i);
                }

                // if there are index(es) with this session belongs to, count flow per second
                if (sessionToSignatureIndex.contains(session.id)) {
                    auto packsToFillFlowPerSecond = sessionToSignatureIndex[session.id];

                    // count flow per second
                    for (size_t i = std::max(session.first.second, conditions.from) - from, iEnd = std::min(session.last.second, conditions.to) - from + 1; i < iEnd; ++i)
                        for (const auto &index : packsToFillFlowPerSecond) {
                            auto &targetPack = packs[index];
                            ++targetPack.flowCounts[i];
                            if (session.first.second == from)
                                targetPack.sessionsFromHead.insert(session.id);
                            if (session.last.second == to)
                                targetPack.sessionsInTail.push_back(session.id);
                        }
                }
            }

            // BPS
            for (auto bps = loader->firstBpsPerSession(); bps; bps = loader->nextBpsPerSession(bps))
                if (sessionToSignatureIndex.contains(bps->sessionId)) {
                    auto sum = bps->fromSmallToBig + bps->fromBigToSmall;
                    for (const auto &index : sessionToSignatureIndex.at(bps->sessionId))
                        packs[index].bps[bps->second - from] += sum * 8; // change byte to bit
                }

            // PPS
            for (auto pps = loader->firstPpsPerSession(); pps; pps = loader->nextPpsPerSession(pps))
                if (sessionToSignatureIndex.contains(pps->sessionId)) {
                    auto sum = pps->fromSmallToBig + pps->fromBigToSmall;
                    const auto sessionType = SuperCodex::castType(*loader->sessions.at(pps->sessionId));

                    for (const auto &index : sessionToSignatureIndex.at(pps->sessionId)) {
                        auto &targetPack = packs[index];
                        switch (sessionType) {
                        case SuperCodex::UNICAST:
                            targetPack.pps[pps->second - from].unicast += sum;
                            break;
                        case SuperCodex::MULTICAST:
                            targetPack.pps[pps->second - from].multicast += sum;
                            break;
                        case SuperCodex::BROADCAST:
                            targetPack.pps[pps->second - from].broadcast += sum;
                            break;
                        case SuperCodex::UNKNOWN:
                            targetPack.pps[pps->second - from].unknown += sum;
                            break;
                        }
                    }
                }

            // RTT / latency
            for (auto rtt = loader->firstRtt(); rtt; rtt = loader->nextRtt(rtt))
                if (rtt->tail < 10000000000 && sessionToSignatureIndex.contains(rtt->sessionId)) {
                    // simple sanity check
                    if (rtt->tail < 0) {
                        logger.log("Skipping negative RTT tail at "s + std::to_string(rtt->second) + ' ' + std::to_string(rtt->tail));
                        continue;
                    }
                    const auto sourceIsSmall = loader->sessions.at(rtt->sessionId)->sourceIsSmall;

                    for (const auto &index : sessionToSignatureIndex.at(rtt->sessionId)) {
                        auto &target = packs[index].rtts[rtt->second - from];
                        if (sourceIsSmall == rtt->fromSmallToBig) {
                            target.numerator0 += rtt->tail;
                            ++target.denominator0;
                        } else {
                            target.numerator1 += rtt->tail;
                            ++target.denominator1;
                        }
                    }
                }

            // timeout
            for (auto timeout = loader->firstTimeout(); timeout; timeout = loader->nextTimeout(timeout)) {
                // check whether this session belongs to anything
                const std::string sourceIp = SuperCodex::sourceIp(timeout->session), destinationIp = SuperCodex::destinationIp(timeout->session);
                ankerl::unordered_dense::set<size_t> signatureIndicesToPush;
                for (size_t i = 0; i < numberOfSignatures; ++i) {
                    const auto &signature = signatures[i];
                    if (signature.filter.contains(sourceIp))
                        signatureIndicesToPush.insert(i);
                    if (signature.filter.contains(destinationIp))
                        signatureIndicesToPush.insert(i);
                }

                // if there are tables, make a record
                if (!signatureIndicesToPush.empty())
                    for (const auto &index : signatureIndicesToPush)
                        ++packs[index].timeouts[timeout->marker.second - from];
            }

            // TCP RSTs
            for (auto rst = loader->firstTcpRst(); rst; rst = loader->nextTcpRst(rst))
                if (sessionToSignatureIndex.contains(rst->sessionId))
                    for (const auto &index : sessionToSignatureIndex.at(rst->sessionId))
                        ++packs[index].rsts[rst->second - from];

            // TCP DUP ACKs
            for (auto dupAck = loader->firstTcpDupAck(); dupAck; dupAck = loader->nextTcpDupAck(dupAck))
                if (sessionToSignatureIndex.contains(dupAck->sessionId))
                    for (const auto &index : sessionToSignatureIndex.at(dupAck->sessionId))
                        ++packs[index].dupAcks[dupAck->second - from];

            // TCP retransmissions
            for (auto retransmission = loader->firstTcpRetransmission(); retransmission; retransmission = loader->nextTcpRetransmission(retransmission))
                if (sessionToSignatureIndex.contains(retransmission->sessionId))
                    for (const auto &index : sessionToSignatureIndex.at(retransmission->sessionId))
                        ++packs[index].retransmissions[retransmission->second - from];

            // TCP Miscellaneous Anomalies
            for (auto miscAnomaly = loader->firstTcpMiscAnomaly(); miscAnomaly; miscAnomaly = loader->nextTcpMiscAnomaly(miscAnomaly))
                if (sessionToSignatureIndex.contains(miscAnomaly->sessionId)) {
                    switch (miscAnomaly->tail) {
                    case MA_TCPZEROWINDOW:
                        for (const auto &index : sessionToSignatureIndex.at(miscAnomaly->sessionId))
                            ++packs[index].zeroWindows[miscAnomaly->second - from];
                        break;
                    case MA_TCPPORTSREUSED:
                        for (const auto &index : sessionToSignatureIndex.at(miscAnomaly->sessionId))
                            ++packs[index].portReused[miscAnomaly->second - from];
                        break;
                    case MA_TCPOUTOFORDER:
                        for (const auto &index : sessionToSignatureIndex.at(miscAnomaly->sessionId))
                            ++packs[index].outOfOrders[miscAnomaly->second - from];
                        break;
                    default:
                        // just ignore
                        continue;
                    }
                }

            return intermediate;
        });

        // reading is complete - merge intermediate data
        if (mergeThread.joinable())
            mergeThread.join();
        mergeThread = std::thread(
            [&](std::vector<Intermediate> intermediatesFuture) {
                for (auto &intermediate : intermediatesFuture) {
                    // merge statstic per signatures per second
                    const size_t baseOffset = intermediate.from - final.from;
                    for (size_t index = 0; index < numberOfSignatures; ++index) {
                        const auto &source = intermediate.packs[index];
                        auto &target = final.packs[index];
                        for (int i = 0, iEnd = intermediate.to - intermediate.from + 1; i < iEnd; ++i) {
                            size_t offsetForFinal = baseOffset + i;
                            // special values
                            target.pps[offsetForFinal].values += source.pps[i];
                            target.rtts[offsetForFinal] += source.rtts[i];
                            // uint64_t
                            target.bps[offsetForFinal] += source.bps[i];
                            target.timeouts[offsetForFinal] += source.timeouts[i];
                            target.rsts[offsetForFinal] += source.rsts[i];
                            target.dupAcks[offsetForFinal] += source.dupAcks[i];
                            target.retransmissions[offsetForFinal] += source.retransmissions[i];
                            target.zeroWindows[offsetForFinal] += source.zeroWindows[i];
                            target.portReused[offsetForFinal] += source.portReused[i];
                            target.outOfOrders[offsetForFinal] += source.outOfOrders[i];
                            target.flowCounts[offsetForFinal] += source.flowCounts[i];
                        }

                        // adjust flow count numbers as needed
                        if (timestampForLastTail == intermediate.from) {
                            auto &designatedSessionsInTail = sessionsInTail[index];
                            for (const auto &sessionId : designatedSessionsInTail)
                                if (source.sessionsFromHead.contains(sessionId))
                                    --target.flowCounts[baseOffset];
                            designatedSessionsInTail = source.sessionsInTail;
                        }
                    }
                    timestampForLastTail = intermediate.to; // this doesn't need to be done repeatedly
                }
            },
            std::move(intermediates));

        return true;
    });

    // finalize
    if (mergeThread.joinable())
        mergeThread.join();

    // flush everything to the database at once
    logger.log("Save record"s);
    // try writing to the database everything at once(all or nothing)
    {
        FeatherLite feather(feedPath + dbs[0]);

        // begin transaction
        if (!feather.exec("BEGIN TRANSACTION"s))
            return "Failed to begin transaction. Details: "s + feather.lastError();

        // for each table.......
        for (size_t i = 0; i < numberOfSignatures; ++i) {
            // determine which signature and pack to use
            const auto &signatureToGo = signatures[i];
            const auto &pack = final.packs[i];

            // prepare statement
            if (!feather.prepare("INSERT INTO main.rows(timestamp, signature, chapter, value) VALUES "
                                 "(?1, ?2, ?3, ?4)," // BPS
                                 "(?1, ?2, ?5, ?6)," // timeouts
                                 "(?1, ?2, ?7, ?8)," // RSTS
                                 "(?1, ?2, ?9, ?10)," // DUPACKs
                                 "(?1, ?2, ?11, ?12)," // Retransmissions
                                 "(?1, ?2, ?13, ?14)," // zero windows
                                 "(?1, ?2, ?15, ?16)," // port reused
                                 "(?1, ?2, ?17, ?18)," // out of orders
                                 "(?1, ?2, ?19, ?20)," // flow counts
                                 "(?1, ?2, ?21, ?22)," // PPS
                                 "(?1, ?2, ?23, ?24);" // RTTs
                                 ))
                return "Failed to prepare for insert into ps2. Details: "s + feather.lastError();
            constexpr size_t size60 = sizeof(uint64_t) * 60; // common size for 60 seconds
            // bind timestamp
            if (!feather.bindInt(1, final.from))
                return "Failed to bind 1. Details: "s + feather.lastError();
            // bind signature(force change to int64, since SQLite doesn't support unsigned 64bit integer)
            if (!feather.bindInt64(2, signatureToGo.signature))
                return "Failed to bind 2. Details: "s + feather.lastError();
            // bind BPS
            if (!feather.bindInt(3, SuperCodex::ChapterType::BPSPERSESSION))
                return "Failed to bind 3. Details: "s + feather.lastError();
            if (!feather.bindBlob(4, &pack.bps, size60))
                return "Failed to bind 4. Details: "s + feather.lastError();
            // bind timeouts
            if (!feather.bindInt(5, SuperCodex::ChapterType::TIMEOUTS))
                return "Failed to bind 5. Details: "s + feather.lastError();
            if (!feather.bindBlob(6, &pack.timeouts, size60))
                return "Failed to bind 6. Details: "s + feather.lastError();
            // bind TCP RSTs
            if (!feather.bindInt(7, SuperCodex::ChapterType::TCPRSTS))
                return "Failed to bind 7. Details: "s + feather.lastError();
            if (!feather.bindBlob(8, &pack.rsts, size60))
                return "Failed to bind 8. Details: "s + feather.lastError();
            // bind TCP DUPACKs
            if (!feather.bindInt(9, SuperCodex::ChapterType::TCPDUPACKS))
                return "Failed to bind 9. Details: "s + feather.lastError();
            if (!feather.bindBlob(10, &pack.dupAcks, size60))
                return "Failed to bind 10. Details: "s + feather.lastError();
            // bind TCP retransmissions
            if (!feather.bindInt(11, SuperCodex::ChapterType::TCPRETRANSMISSIONS))
                return "Failed to bind 11. Details: "s + feather.lastError();
            if (!feather.bindBlob(12, &pack.retransmissions, size60))
                return "Failed to bind 12. Details: "s + feather.lastError();
            // bind TCP zero windows
            if (!feather.bindInt(13, SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPZEROWINDOW))
                return "Failed to bind 13. Details: "s + feather.lastError();
            if (!feather.bindBlob(14, &pack.zeroWindows, size60))
                return "Failed to bind 14. Details: "s + feather.lastError();
            // bind TCP port reused
            if (!feather.bindInt(15, SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPPORTSREUSED))
                return "Failed to bind 15. Details: "s + feather.lastError();
            if (!feather.bindBlob(16, &pack.portReused, size60))
                return "Failed to bind 16. Details: "s + feather.lastError();
            // bind TCP out of order
            if (!feather.bindInt(17, SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPOUTOFORDER))
                return "Failed to bind 17. Details: "s + feather.lastError();
            if (!feather.bindBlob(18, &pack.outOfOrders, size60))
                return "Failed to bind 18. Details: "s + feather.lastError();
            // bind flow counts
            if (!feather.bindInt(19, SuperCodex::ChapterType::SESSIONS))
                return "Failed to bind 19. Details: "s + feather.lastError();
            if (!feather.bindBlob(20, &pack.flowCounts, size60))
                return "Failed to bind 20. Details: "s + feather.lastError();
            // bind PPS
            if (!feather.bindInt(21, SuperCodex::ChapterType::PPSPERSESSION))
                return "Failed to bind 21. Details: "s + feather.lastError();
            if (!feather.bindBlob(22, &pack.pps, sizeof(pack.pps)))
                return "Failed to bind 22. Details: "s + feather.lastError();
            // bind RTTs
            if (!feather.bindInt(23, SuperCodex::ChapterType::RTTS))
                return "Failed to bind 23. Details: "s + feather.lastError();
            if (!feather.bindBlob(24, &pack.rtts, sizeof(pack.rtts)))
                return "Failed to bind 24. Details: "s + feather.lastError();
            // flush
            if (!feather.next())
                return "Failed to next for ps. Details: "s + feather.lastError();
            if (!feather.reset())
                return "Failed to reset ps. Details: "s + feather.lastError();
            if (!feather.finalize())
                return "Failed to finalize ps. Details: "s + feather.lastError();
        }

        // commit
        if (!feather.exec("COMMIT"s))
            return "Failed to commit. Details: "s + feather.lastError();
    }

    // declare success
    logger.log("Flushed");
    return ""s;
}
