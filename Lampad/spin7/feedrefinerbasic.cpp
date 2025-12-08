#include "feedrefinerbasic.h"
#include "civet7.hpp"
#include "codexindex.h"
#include "supercache0.h"
#include "../fnvhash.h"
#include "../featherlite.h"

#include <tbb/parallel_for.h>
#include <tbb/parallel_for_each.h>
#include <yyjson.h>

#include <filesystem>
#include <sstream>
#include <fstream>

FeedRefinerPerSecondStatistics::FeedRefinerPerSecondStatistics(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    // determine type
    mode = conditions.parameters.at("type");
    if (mode == "bps"s) {
        logger.setLogHeader("FeedRefiner_BPS"s);
        readData = &readBps;
        cachedChapter = SuperCodex::ChapterType::BPSPERSESSION;
    } else if (mode == "timeoutcounts"s) {
        logger.setLogHeader("FeedRefiner_Timeouts"s);
        readData = &readTimeouts;
        cachedChapter = SuperCodex::ChapterType::TIMEOUTS;
    } else if (mode == "tcprsts"s) {
        logger.setLogHeader("FeedRefiner_TcpRsts"s);
        readData = &readTcpRsts;
        cachedChapter = SuperCodex::ChapterType::TCPRSTS;
    } else if (mode == "tcpzerowindows"s) {
        logger.setLogHeader("FeedRefiner_TcpZeroWindows"s);
        readData = &readTcpZeroWindows;
        cachedChapter = static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPZEROWINDOW);
    } else if (mode == "tcpdupacks"s) {
        logger.setLogHeader("FeedRefiner_TcpDupAcks"s);
        readData = &readTcpDupAcks;
        cachedChapter = SuperCodex::ChapterType::TCPDUPACKS;
    } else if (mode == "tcpretransmissions"s) {
        logger.setLogHeader("FeedRefiner_TcpRetransmissions"s);
        readData = &readTcpRetransmissions;
        cachedChapter = SuperCodex::ChapterType::TCPRETRANSMISSIONS;
    } else if (mode == "tcpportsreused"s) {
        logger.setLogHeader("FeedRefiner_TcpPortsReused"s);
        readData = &readTcpPortsReused;
        cachedChapter = static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPPORTSREUSED);
    } else if (mode == "tcpoutoforders"s) {
        logger.setLogHeader("FeedRefiner_TcpOutOfOrders"s);
        readData = &readTcpOutOfOrders;
        cachedChapter = static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPOUTOFORDER);
    }

    // determine whether to use SuperCache and, if available, which to use(PS or PS2)
    bool useSuperCache = conditions.payloadProtocol == 0 && conditions.l7Protocol == SuperCodex::Session::NOL7DETECTED && conditions.ports.empty() && conditions.mplsLabels.empty() && conditions.vlanQTags.empty();

    // build IP signatures
    if (conditions.allowedIps.isEmpty)
        useSuperCache &= true;
    else {
        if (conditions.includeExternalTransfer) { // conditions.ips.empty() is FALSE and includeExternalTransfer is TRUE
            superCacheSignature = this->conditions.allowedIps.signature();
            FeatherLite feather(CodexIndex::feedRoot + conditions.dataFeed + "/supercache.ps2"s, SQLITE_OPEN_READONLY);
            feather.prepare("SELECT EXISTS(SELECT signature FROM rows WHERE signature=?);"s);
            feather.bindInt64(1, superCacheSignature);
            feather.next();
            useSuperCache &= feather.getInt(0);
            feather.reset();
            feather.finalize();
        } else
            useSuperCache = false; // includeExternalTransfer is false, which is NOT supported by SuperCache Zero
    }

    if (useSuperCache) {
        if (conditions.allowedIps.isEmpty) {
            logger.log("Apply SuperCache PS"s);
            superCachePath = CodexIndex::feedRoot + conditions.dataFeed + SuperCache::dbs[0];
        } else {
            logger.log("Apply SuperCache PS2"s);
            superCachePath = CodexIndex::feedRoot + conditions.dataFeed + SuperCacheZero::dbs[0];
        }
    } else
        logger.log("SuperCache unapplicable");

    // prepare for buffer
    if (readData) {
        bufferSize = conditions.to - conditions.from + 1;
        buffer = new TimeValuePair[bufferSize];
        for (int i = 0; i < bufferSize; ++i)
            buffer[i] = TimeValuePair{conditions.from + i, 0};
    }
}

FeedRefinerPerSecondStatistics::~FeedRefinerPerSecondStatistics()
{
    if (buffer)
        delete[] buffer;
}

void FeedRefinerPerSecondStatistics::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    // sanity check
    if (readData == nullptr) {
        logger.oops("readData null.");
        return;
    }
    // read codices
    logger.log("Processing: "s + std::to_string(codices.size()));
    std::vector<std::vector<TimeValuePair>> intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, std::vector<TimeValuePair>>(codices, readData, affinityPartitioner);

    // merge data
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<std::vector<TimeValuePair>> intermediatesFuture) {
            logger.log("Merging "s + std::to_string(intermediatesFuture.size()));
            for (const auto &intermediate : intermediatesFuture)
                for (const auto &pair : intermediate) {
                    auto offset = pair.second - conditions.from;
                    if (offset < 0 || offset >= bufferSize)
                        continue;
                    buffer[pair.second - conditions.from].value += pair.value;
                }
        },
        std::move(intermediates));
}

void FeedRefinerPerSecondStatistics::finalize()
{
    // update target time frame
    secondStart = conditions.from;
    secondEnd = conditions.to;

    // apply SuperCache
    if (conditions.cacheFrom) {
        // query database
        FeatherLite feather(superCachePath, SQLITE_OPEN_READONLY);
        if (conditions.allowedIps.isEmpty) {
            feather.prepare("SELECT timestamp,value FROM rows WHERE timestamp>=? AND timestamp<=? AND chapter=?;"s);
            feather.bindInt(1, conditions.cacheFrom);
            feather.bindInt(2, conditions.cacheTo);
            feather.bindInt(3, cachedChapter);
        } else {
            feather.prepare("SELECT timestamp,value FROM rows WHERE timestamp>=? AND timestamp<=? AND signature=? AND chapter=?;"s);
            feather.bindInt(1, conditions.cacheFrom);
            feather.bindInt(2, conditions.cacheTo);
            feather.bindInt64(3, superCacheSignature);
            feather.bindInt(4, cachedChapter);
        }

        // merge cache
        while (feather.next() == SQLITE_ROW) {
            std::string_view rawData = feather.getBlob(1);
            const uint64_t *cursor = (const uint64_t *) rawData.data();
            for (int i = feather.getInt(0) - conditions.from, iEnd = i + 60; i < iEnd; ++i) {
                buffer[i].value += *cursor;
                ++cursor;
            }
        }
    }

    // write down "values" file
    std::ofstream valuesWriter(messyRoomPrefix + "/values"s, std::ios::out | std::ios::binary | std::ios::trunc);
    std::unique_ptr<char[]> writeBuffer(new char[536870912]); // 512MB
    valuesWriter.rdbuf()->pubsetbuf(writeBuffer.get(), 536870912);
    valuesWriter.write((const char *) buffer, timeValuePairSize * (conditions.to - conditions.from + 1));
    valuesWriter.close();
    delete[] buffer;
    buffer = nullptr;
    logger.log("Result ready to serve: "s + std::to_string(secondStart) + " -> "s + std::to_string(secondEnd));
}

std::vector<FeedRefinerAbstract::TimeValuePair> FeedRefinerPerSecondStatistics::readBps(const SuperCodex::Loader *codex)
{
    // prepare for result set
    int indexOffset = codex->secondStart;
    size_t resultSize = codex->secondEnd - indexOffset + 1;
    std::vector<TimeValuePair> result;
    result.reserve(resultSize);
    for (uint32_t i = 0; i < resultSize; ++i)
        result.push_back(TimeValuePair{i + indexOffset, 0});

    // read from SuperCodex
    for (auto bps = codex->firstBpsPerSession(); bps; bps = codex->nextBpsPerSession(bps)) {
        if (bps->second < codex->secondStart || bps->second > codex->secondEnd)
            continue;
        result[bps->second - indexOffset].value += (bps->fromBigToSmall + bps->fromSmallToBig) * 8; // data storing policy is same for both raw and combined codex
    }

    return result;
}

std::vector<FeedRefinerAbstract::TimeValuePair> FeedRefinerPerSecondStatistics::readTimeouts(const SuperCodex::Loader *codex)
{
    // prepare
    ankerl::unordered_dense::map<uint32_t, int64_t> counts;
    counts.reserve(6);

    // count per second occurrences
    for (const SuperCodex::Timeout *timeout = codex->firstTimeout(); timeout; timeout = codex->nextTimeout(timeout))
        if (timeout->marker.second)
            ++counts[timeout->marker.second];

    // build result object
    std::vector<TimeValuePair> result;
    result.reserve(counts.size());
    for (const auto &pair : counts)
        result.push_back(TimeValuePair{pair.first, pair.second});
    std::sort(result.begin(), result.end(), [](const TimeValuePair &a, const TimeValuePair &b) -> bool { return a.second < b.second; });
    return result;
}

std::vector<FeedRefinerAbstract::TimeValuePair> FeedRefinerPerSecondStatistics::readTcpRsts(const SuperCodex::Loader *codex)
{
    // prepare for result set
    int indexOffset = codex->secondStart;
    size_t resultSize = codex->secondEnd - indexOffset + 1;
    std::vector<TimeValuePair> result;
    result.reserve(resultSize);
    for (uint32_t i = 0; i < resultSize; ++i)
        result.push_back(TimeValuePair{i + indexOffset, 0});

    // read from SuperCodex
    for (const SuperCodex::PacketMarker *marker = codex->firstTcpRst(); marker; marker = codex->nextTcpRst(marker))
        if (marker->second)
            ++result[marker->second - indexOffset].value;

    return result;
}

std::vector<FeedRefinerAbstract::TimeValuePair> FeedRefinerPerSecondStatistics::readTcpZeroWindows(const SuperCodex::Loader *codex)
{
    // prepare for result set
    int indexOffset = codex->secondStart;
    size_t resultSize = codex->secondEnd - indexOffset + 1;
    std::vector<TimeValuePair> result;
    result.reserve(resultSize);
    for (uint32_t i = 0; i < resultSize; ++i)
        result.push_back(TimeValuePair{i + indexOffset, 0});

    // read from SuperCodex
    for (const SuperCodex::PacketMarker *marker = codex->firstTcpMiscAnomaly(); marker; marker = codex->nextTcpMiscAnomaly(marker)) {
        int32_t type = marker->tail & 0xffffffff;
        if (type == MA_TCPZEROWINDOW)
            ++result[marker->second - indexOffset].value;
    }

    return result;
}

std::vector<FeedRefinerAbstract::TimeValuePair> FeedRefinerPerSecondStatistics::readTcpDupAcks(const SuperCodex::Loader *codex)
{
    // prepare for result set
    int indexOffset = codex->secondStart;
    size_t resultSize = codex->secondEnd - indexOffset + 1;
    std::vector<TimeValuePair> result;
    result.reserve(resultSize);
    for (uint32_t i = 0; i < resultSize; ++i)
        result.push_back(TimeValuePair{i + indexOffset, 0});

    // read from SuperCodex
    for (const SuperCodex::PacketMarker *marker = codex->firstTcpDupAck(); marker; marker = codex->nextTcpDupAck(marker))
        if (marker->second)
            ++result[marker->second - indexOffset].value;

    return result;
}

std::vector<FeedRefinerAbstract::TimeValuePair> FeedRefinerPerSecondStatistics::readTcpRetransmissions(const SuperCodex::Loader *codex)
{
    // prepare for result set
    int indexOffset = codex->secondStart;
    size_t resultSize = codex->secondEnd - indexOffset + 1;
    std::vector<TimeValuePair> result;
    result.reserve(resultSize);
    for (uint32_t i = 0; i < resultSize; ++i)
        result.push_back(TimeValuePair{i + indexOffset, 0});

    // read from SuperCodex
    for (const SuperCodex::PacketMarker *marker = codex->firstTcpRetransmission(); marker; marker = codex->nextTcpRetransmission(marker))
        if (marker->second)
            ++result[marker->second - indexOffset].value;

    return result;
}

std::vector<FeedRefinerAbstract::TimeValuePair> FeedRefinerPerSecondStatistics::readTcpPortsReused(const SuperCodex::Loader *codex)
{
    // prepare for result set
    int indexOffset = codex->secondStart;
    size_t resultSize = codex->secondEnd - indexOffset + 1;
    std::vector<TimeValuePair> result;
    result.reserve(resultSize);
    for (uint32_t i = 0; i < resultSize; ++i)
        result.push_back(TimeValuePair{i + indexOffset, 0});

    // read from SuperCodex
    for (const SuperCodex::PacketMarker *marker = codex->firstTcpMiscAnomaly(); marker; marker = codex->nextTcpMiscAnomaly(marker)) {
        int32_t type = marker->tail & 0xffffffff;
        if (type == MA_TCPPORTSREUSED)
            ++result[marker->second - indexOffset].value;
    }

    return result;
}

std::vector<FeedRefinerAbstract::TimeValuePair> FeedRefinerPerSecondStatistics::readTcpOutOfOrders(const SuperCodex::Loader *codex)
{
    // prepare for result set
    int indexOffset = codex->secondStart;
    size_t resultSize = codex->secondEnd - indexOffset + 1;
    std::vector<TimeValuePair> result;
    result.reserve(resultSize);
    for (uint32_t i = 0; i < resultSize; ++i)
        result.push_back(TimeValuePair{i + indexOffset, 0});

    // read from SuperCodex
    for (const SuperCodex::PacketMarker *marker = codex->firstTcpMiscAnomaly(); marker; marker = codex->nextTcpMiscAnomaly(marker)) {
        int32_t type = marker->tail & 0xffffffff;
        if (type == MA_TCPOUTOFORDER)
            ++result[marker->second - indexOffset].value;
    }

    return result;
}

void FeedRefinerPerSecondStatistics::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    if (!std::filesystem::exists(messyRoomPrefix + "/values"s)) {
        logger.oops("'values' file not found. Returning 204"s);
        mg_send_http_error(connection, 204, "\r\n\r\n");
        return;
    }

    if (bindValue == 0) {
        // determine scope
        if (to > secondEnd - secondStart)
            to = secondEnd - secondStart + 1;
        from += secondStart;
        to += secondEnd;

        // write JSON
        std::ifstream file(messyRoomPrefix + "/values", std::ios::binary);
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);

        // read first record
        TimeValuePair record;
        file.read((char *) &record, timeValuePairSize);
        while (file.gcount()) {
            // check scope
            if (record.second < from) {
                file.read((char *) &record, timeValuePairSize);
                continue;
            }
            if (record.second > to)
                break;

            // write JSON object
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(rootArray, object);
            yyjson_mut_obj_add_int(document, object, "timestamp", record.second);
            yyjson_mut_obj_add_int(document, object, "value", record.value);

            // read next record
            file.read((char *) &record, timeValuePairSize);
        }
        file.close();

        if (connection)
            Civet7::respond200(connection, document);
        else
            lastInterativeResult = document;
    } else if (bindValue > 0)
        summarize(connection, messyRoomPrefix + "/values"s, bindValue);
    else if (bindValue == -1)
        minAndMax(connection, messyRoomPrefix + "/values"s);
    else
        rankingPerSecond(connection, messyRoomPrefix + "/values"s, bindValue * (-1));
}

void FeedRefinerPerSecondStatistics::dumpResults(mg_connection *connection)
{
    // send header
    std::string chunk("Timestamp\tValue\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // send body chunks
    std::ifstream file(messyRoomPrefix + "/values"s, std::ios::binary);
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);
    // read first record
    TimeValuePair record;
    file.read((char *) &record, timeValuePairSize);
    while (file.gcount()) {
        chunk.append(epochToIsoDate(record.second)).append("\t"s).append(std::to_string(record.value)).push_back('\n');

        // flush chunk if its size is over 100MB
        if (chunk.size() > 100000000) {
            switch (mg_send_chunk(connection, chunk.data(), chunk.size())) {
            case 0:
                logger.log("Client closed socket. Cancelling operation."s);
                return;
            case -1:
                logger.log("Server encountered an error. Cancelling operation."s);
                return;
            default:
                chunk.clear();
            }
        }

        // read next record
        file.read((char *) &record, timeValuePairSize);
    }

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);

    file.close();
}

FeedRefinerPps::FeedRefinerPps(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerPerSecondStatistics(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerPps"s);
    cachedChapter = SuperCodex::PPSPERSESSION;

    // reserve RAM for buffer
    bufferSize = conditions.to - conditions.from + 1;
    buffer = new ResultRecord[bufferSize];
    for (int i = 0; i < bufferSize; ++i)
        buffer[i] = ResultRecord{conditions.from + i, Description{}};

    // build ignore list
    if (conditions.parameters.contains("ignoremac"s)) {
        std::istringstream separator(conditions.parameters.at("ignoremac"s));
        for (std::string mac; std::getline(separator, mac, ',');) {
            std::transform(mac.begin(), mac.end(), mac.begin(), [](unsigned char c) { return std::tolower(c); });
            std::string macBinary = SuperCodex::stringFromHex(mac);
            if (macBinary.size() == 6) {
                logger.log("Add to MAC exclusion list: "s + mac);
                ignoreMac.insert(macBinary);
            } else
                logger.log("Ignoring MAC address: "s + mac);
        }
    }

    // determine whether to use SuperCache and, if available, which to use(PS or PS2)
    bool useSuperCache = conditions.payloadProtocol == 0 && conditions.l7Protocol == SuperCodex::Session::NOL7DETECTED && conditions.ports.empty() && conditions.mplsLabels.empty() && conditions.vlanQTags.empty();

    // build IP signatures
    if (conditions.allowedIps.isEmpty)
        useSuperCache &= true;
    else {
        if (conditions.includeExternalTransfer) { // conditions.ips.empty() is FALSE and includeExternalTransfer is TRUE
            superCacheSignature = this->conditions.allowedIps.signature();
            FeatherLite feather(CodexIndex::feedRoot + conditions.dataFeed + "/supercache.ps2"s, SQLITE_OPEN_READONLY);
            feather.prepare("SELECT EXISTS(SELECT signature FROM rows WHERE signature=?);"s);
            feather.bindInt64(1, superCacheSignature);
            feather.next();
            useSuperCache &= feather.getInt(0);
            feather.reset();
            feather.finalize();
        } else
            useSuperCache = false; // includeExternalTransfer is false, which is NOT supported by SuperCache Zero
    }

    if (useSuperCache) {
        if (conditions.allowedIps.isEmpty) {
            logger.log("Apply SuperCache PS"s);
            superCachePath = CodexIndex::feedRoot + conditions.dataFeed + SuperCache::dbs[0];
        } else {
            logger.log("Apply SuperCache PS2"s);
            superCachePath = CodexIndex::feedRoot + conditions.dataFeed + SuperCacheZero::dbs[0];
        }
    } else
        logger.log("SuperCache unapplicable");
}

void FeedRefinerPps::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    // read pages
    logger.log("Processing: "s + std::to_string(codices.size()));
    std::vector<std::vector<ResultRecord>> intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, std::vector<ResultRecord>>(
        codices,
        [&](const SuperCodex::Loader *codex) -> std::vector<ResultRecord> {
            // prepare for result set
            int indexOffset = codex->secondStart;
            size_t resultSize = codex->secondEnd - indexOffset + 1;
            std::vector<ResultRecord> result;
            result.reserve(resultSize);
            for (uint32_t i = 0; i < resultSize; ++i)
                result.push_back(ResultRecord{i + indexOffset, {}});
            for (auto pps = codex->firstPpsPerSession(); pps; pps = codex->nextPpsPerSession(pps)) { // data storing policy is same for both raw and combined codex
                SuperCodex::CastType castType = SuperCodex::castType(*codex->sessions.at(pps->sessionId));
                if (castType == SuperCodex::UNICAST)
                    result[pps->second - indexOffset].values.unicast += pps->fromSmallToBig + pps->fromBigToSmall;
                else if (castType == SuperCodex::MULTICAST)
                    result[pps->second - indexOffset].values.multicast += pps->fromSmallToBig + pps->fromBigToSmall;
                else if (castType == SuperCodex::BROADCAST)
                    result[pps->second - indexOffset].values.broadcast += pps->fromSmallToBig + pps->fromBigToSmall;
                else // UNKNOWN
                    result[pps->second - indexOffset].values.unknown += pps->fromSmallToBig + pps->fromBigToSmall;
            }

            // adjust values with MAC filter as needed
            if (!ignoreMac.empty()) {
                // build values to subtract
                for (auto packet = codex->firstPacket(); packet; packet = codex->nextPacket(packet)) {
                    if (ignoreMac.contains(std::string((const char *) packet->sourceMac, 6)) || ignoreMac.contains(std::string((const char *) packet->destinationMac, 6)))
                        switch (SuperCodex::castType(*codex->sessions.at(packet->sessionId))) {
                        case SuperCodex::UNICAST:
                            --result[packet->second - indexOffset].values.unicast;
                            break;
                        case SuperCodex::MULTICAST:
                            --result[packet->second - indexOffset].values.multicast;
                            break;
                        case SuperCodex::BROADCAST:
                            --result[packet->second - indexOffset].values.broadcast;
                            break;
                        case SuperCodex::UNKNOWN:
                            --result[packet->second - indexOffset].values.unknown;
                            break;
                        }
                }
            }

            return result;
        },
        affinityPartitioner);

    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](std::vector<std::vector<ResultRecord>> intermediatesFuture) {
            logger.log("Merging "s + std::to_string(intermediatesFuture.size()));
            for (const auto &intermediate : intermediatesFuture)
                for (const auto &record : intermediate) {
                    auto offset = record.second - conditions.from;
                    if (offset < 0 || offset >= bufferSize)
                        continue;
                    buffer[record.second - conditions.from].values += record.values;
                }
        },
        std::move(intermediates));
}

void FeedRefinerPps::finalize()
{
    // update target time frame
    secondStart = conditions.from;
    secondEnd = conditions.to;

    // apply SuperCache
    if (conditions.cacheFrom) {
        // query database
        FeatherLite feather(superCachePath, SQLITE_OPEN_READONLY);
        if (conditions.allowedIps.isEmpty) {
            feather.prepare("SELECT timestamp,value FROM rows WHERE timestamp>=? AND timestamp<=? AND chapter=?;"s);
            feather.bindInt(1, conditions.cacheFrom);
            feather.bindInt(2, conditions.cacheTo);
            feather.bindInt(3, cachedChapter);
        } else {
            feather.prepare("SELECT timestamp,value FROM rows WHERE timestamp>=? AND timestamp<=? AND signature=? AND chapter=?;"s);
            feather.bindInt(1, conditions.cacheFrom);
            feather.bindInt(2, conditions.cacheTo);
            feather.bindInt64(3, superCacheSignature);
            feather.bindInt(4, cachedChapter);
        }

        // merge cache
        while (feather.next() == SQLITE_ROW) {
            std::string_view rawData = feather.getBlob(1);
            const ResultRecord *cursor = (const ResultRecord *) rawData.data();
            for (int i = feather.getInt(0) - conditions.from, iEnd = i + 60; i < iEnd; ++i) {
                buffer[i].second = conditions.from + i;
                buffer[i].values += cursor->values;
                ++cursor;
            }
        }
    }

    // close the job
    std::ofstream valuesWriter(messyRoomPrefix + "/values"s, std::ios::out | std::ios::binary | std::ios::trunc);
    std::unique_ptr<char[]> writeBuffer(new char[536870912]); // 512MB
    valuesWriter.rdbuf()->pubsetbuf(writeBuffer.get(), 536870912);
    valuesWriter.write((const char *) buffer, resultRecordSize * (conditions.to - conditions.from + 1));
    valuesWriter.close();

    // log
    delete[] buffer;
    logger.log("Result ready to serve: "s + std::to_string(secondStart) + " -> "s + std::to_string(secondEnd));
}

void FeedRefinerPps::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    if (!std::filesystem::exists(messyRoomPrefix + "/values"s)) {
        mg_send_http_error(connection, 204, "\r\n\r\n");
        return;
    }

    if (bindValue == 0) {
        // build result source
        if (to > secondEnd - secondStart)
            to = secondEnd - secondStart + 1;
        from += secondStart;
        to += secondEnd;

        // write JSON
        std::ifstream file(messyRoomPrefix + "/values", std::ios::binary);
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);

        // read first record
        ResultRecord record;
        file.read((char *) &record, resultRecordSize);
        while (file.gcount()) {
            // check scope
            if (record.second < from) {
                file.read((char *) &record, resultRecordSize);
                continue;
            }
            if (record.second > to)
                break;

            // write JSON object
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(rootArray, object);
            yyjson_mut_obj_add_int(document, object, "timestamp", record.second);
            yyjson_mut_obj_add_int(document, object, "unknown", record.values.unknown);
            yyjson_mut_obj_add_int(document, object, "broadcast", record.values.broadcast);
            yyjson_mut_obj_add_int(document, object, "multicast", record.values.multicast);
            yyjson_mut_obj_add_int(document, object, "unicast", record.values.unicast);

            // read next record
            file.read((char *) &record, resultRecordSize);
        }
        file.close();

        Civet7::respond200(connection, document);
    } else if (bindValue > 0) {
        // prepare for reading file
        std::ifstream file(messyRoomPrefix + "/values", std::ios::binary);
        uint32_t timestamp = conditions.from, next = timestamp + bindValue;
        int64_t containers = 0;
        Description top{}, total{}, bottom{INT64_MAX, INT64_MAX, INT64_MAX, INT64_MAX};
        struct Timestamps
        {
            uint32_t unknown, broadcast, multicast, unicast;
        } topAt{timestamp, timestamp, timestamp, timestamp}, bottomAt{timestamp, timestamp, timestamp, timestamp};

        // write JSON
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);

        // read first record
        ResultRecord record;
        file.read((char *) &record, resultRecordSize);

        for (int i = timestamp, iEnd = conditions.to + 1; i < iEnd; ++i) {
            if (i >= next) {
                // write object
                yyjson_mut_val *object = yyjson_mut_obj(document);
                yyjson_mut_arr_append(rootArray, object);
                yyjson_mut_obj_add_int(document, object, "timestamp", timestamp);
                yyjson_mut_obj_add_int(document, object, "containers", containers);

                // unicast
                yyjson_mut_val *unicast = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "unicast", unicast);
                yyjson_mut_obj_add_int(document, unicast, "total", total.unicast);
                yyjson_mut_obj_add_int(document, unicast, "top", top.unicast);
                yyjson_mut_obj_add_int(document, unicast, "bottom", bottom.unicast == INT64_MAX ? 0 : bottom.unicast);
                yyjson_mut_obj_add_int(document, unicast, "topat", topAt.unicast);
                yyjson_mut_obj_add_int(document, unicast, "bottomat", bottomAt.unicast);

                // multicast
                yyjson_mut_val *multicast = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "multicast", multicast);
                yyjson_mut_obj_add_int(document, multicast, "total", total.multicast);
                yyjson_mut_obj_add_int(document, multicast, "top", top.multicast);
                yyjson_mut_obj_add_int(document, multicast, "bottom", bottom.multicast == INT64_MAX ? 0 : bottom.multicast);
                yyjson_mut_obj_add_int(document, multicast, "topat", topAt.multicast);
                yyjson_mut_obj_add_int(document, multicast, "bottomat", bottomAt.multicast);

                // broadcast
                yyjson_mut_val *broadcast = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "broadcast", broadcast);
                yyjson_mut_obj_add_int(document, broadcast, "total", total.broadcast);
                yyjson_mut_obj_add_int(document, broadcast, "top", top.broadcast);
                yyjson_mut_obj_add_int(document, broadcast, "bottom", bottom.broadcast == INT64_MAX ? 0 : bottom.broadcast);
                yyjson_mut_obj_add_int(document, broadcast, "topat", topAt.broadcast);
                yyjson_mut_obj_add_int(document, broadcast, "bottomat", bottomAt.broadcast);

                // unknown
                yyjson_mut_val *unknown = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "unknown", unknown);
                yyjson_mut_obj_add_int(document, unknown, "total", total.unknown);
                yyjson_mut_obj_add_int(document, unknown, "top", top.unknown);
                yyjson_mut_obj_add_int(document, unknown, "bottom", bottom.unknown == INT64_MAX ? 0 : bottom.unknown);
                yyjson_mut_obj_add_int(document, unknown, "topat", topAt.unknown);
                yyjson_mut_obj_add_int(document, unknown, "bottomat", bottomAt.unknown);

                // reset data container variables
                timestamp += bindValue;
                next += bindValue;
                containers = 0;
                total = {0, 0, 0, 0};
                top = {0, 0, 0, 0};
                topAt = Timestamps{timestamp, timestamp, timestamp, timestamp};
                bottom = Description{INT64_MAX, INT64_MAX, INT64_MAX, INT64_MAX};
                bottomAt = {timestamp, timestamp, timestamp, timestamp};
            }

            // accumulate & evaluate values
            total += record.values;
            if (record.values.unicast > top.unicast) {
                top.unicast = record.values.unicast;
                topAt.unicast = record.second;
            }
            if (record.values.multicast > top.multicast) {
                top.multicast = record.values.multicast;
                topAt.multicast = record.second;
            }
            if (record.values.broadcast > top.broadcast) {
                top.broadcast = record.values.broadcast;
                topAt.broadcast = record.second;
            }
            if (record.values.unknown > top.unknown) {
                top.unknown = record.values.unknown;
                topAt.unknown = record.second;
            }
            if (record.values.unicast < bottom.unicast) {
                bottom.unicast = record.values.unicast;
                bottomAt.unicast = record.second;
            }
            if (record.values.multicast < bottom.multicast) {
                bottom.multicast = record.values.multicast;
                bottomAt.multicast = record.second;
            }
            if (record.values.broadcast < bottom.broadcast) {
                bottom.broadcast = record.values.broadcast;
                bottomAt.broadcast = record.second;
            }
            if (record.values.unknown < bottom.unknown) {
                bottom.unknown = record.values.unknown;
                bottomAt.unknown = record.second;
            }

            // read next record
            if (!file.eof())
                file.read((char *) &record, resultRecordSize);
            ++containers; // container is always counted up, regardless of existence of the record itself
        }

        // write final object
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(rootArray, object);
        yyjson_mut_obj_add_int(document, object, "timestamp", timestamp);
        yyjson_mut_obj_add_int(document, object, "containers", containers);

        // unicast
        yyjson_mut_val *unicast = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, object, "unicast", unicast);
        yyjson_mut_obj_add_int(document, unicast, "total", total.unicast);
        yyjson_mut_obj_add_int(document, unicast, "top", top.unicast);
        yyjson_mut_obj_add_int(document, unicast, "bottom", bottom.unicast == INT64_MAX ? 0 : bottom.unicast);
        yyjson_mut_obj_add_int(document, unicast, "topat", topAt.unicast);
        yyjson_mut_obj_add_int(document, unicast, "bottomat", bottomAt.unicast);

        // multicast
        yyjson_mut_val *multicast = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, object, "multicast", multicast);
        yyjson_mut_obj_add_int(document, multicast, "total", total.multicast);
        yyjson_mut_obj_add_int(document, multicast, "top", top.multicast);
        yyjson_mut_obj_add_int(document, multicast, "bottom", bottom.multicast == INT64_MAX ? 0 : bottom.multicast);
        yyjson_mut_obj_add_int(document, multicast, "topat", topAt.multicast);
        yyjson_mut_obj_add_int(document, multicast, "bottomat", bottomAt.multicast);

        // broadcast
        yyjson_mut_val *broadcast = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, object, "broadcast", broadcast);
        yyjson_mut_obj_add_int(document, broadcast, "total", total.broadcast);
        yyjson_mut_obj_add_int(document, broadcast, "top", top.broadcast);
        yyjson_mut_obj_add_int(document, broadcast, "bottom", bottom.broadcast == INT64_MAX ? 0 : bottom.broadcast);
        yyjson_mut_obj_add_int(document, broadcast, "topat", topAt.broadcast);
        yyjson_mut_obj_add_int(document, broadcast, "bottomat", bottomAt.broadcast);

        // unknown
        yyjson_mut_val *unknown = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, object, "unknown", unknown);
        yyjson_mut_obj_add_int(document, unknown, "total", total.unknown);
        yyjson_mut_obj_add_int(document, unknown, "top", top.unknown);
        yyjson_mut_obj_add_int(document, unknown, "bottom", bottom.unknown == INT64_MAX ? 0 : bottom.unknown);
        yyjson_mut_obj_add_int(document, unknown, "topat", topAt.unknown);
        yyjson_mut_obj_add_int(document, unknown, "bottomat", bottomAt.unknown);

        // finalize
        file.close();
        if (connection)
            Civet7::respond200(connection, document);
        else
            lastInterativeResult = document;
    } else if (bindValue == -1) {
        TimeValuePair min{0, INT64_MAX}, max{0, 0};
        ResultRecord readBuffer;
        std::ifstream file(messyRoomPrefix + "/values", std::ios::binary);

        // read record
        file.read((char *) &readBuffer, resultRecordSize);
        while (file.gcount()) {
            int64_t sum = readBuffer.values.unicast + readBuffer.values.multicast + readBuffer.values.broadcast + readBuffer.values.unknown;
            if (sum > max.value)
                max = TimeValuePair{readBuffer.second, sum};
            if (sum > 0 && sum < min.value)
                min = TimeValuePair{readBuffer.second, sum};

            // read next record
            file.read((char *) &readBuffer, resultRecordSize);
        }
        file.close();

        // write JSON
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootObject = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootObject);
        // register minimum
        yyjson_mut_val *minimum = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, rootObject, "minimum", minimum);
        yyjson_mut_obj_add_int(document, minimum, "timestamp", min.second);
        yyjson_mut_obj_add_int(document, minimum, "value", min.value);
        // register maximum
        yyjson_mut_val *maximum = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, rootObject, "maximum", maximum);
        yyjson_mut_obj_add_int(document, maximum, "timestamp", max.second);
        yyjson_mut_obj_add_int(document, maximum, "value", max.value);

        if (connection)
            Civet7::respond200(connection, document);
        else
            lastInterativeResult = document;
    } else { // bindValue<0
        // prepare for reading file
        int ranksToInclude = bindValue * (-1);
        std::ifstream file(messyRoomPrefix + "/values", std::ios::binary);
        std::vector<TimeValuePair> ranks;
        ranks.reserve(ranksToInclude);
        ResultRecord readBuffer;

        // try to fill up records up to ranks to show
        for (int i = 0; i < ranksToInclude; ++i) {
            file.read((char *) &readBuffer, resultRecordSize);
            if (file.gcount() == 0)
                break;
            else
                ranks.push_back(TimeValuePair{readBuffer.second, readBuffer.values.unicast + readBuffer.values.multicast + readBuffer.values.broadcast + readBuffer.values.unknown});
        }
        std::sort(ranks.begin(), ranks.end(), [](const TimeValuePair &a, const TimeValuePair &b) { return a.value > b.value; });
        if (file.eof())
            goto writeJson; // if file hits EOF, write JSON immediately

        // read record
        file.read((char *) &readBuffer, resultRecordSize);
        while (!file.eof()) {
            int64_t sum = readBuffer.values.unicast + readBuffer.values.multicast + readBuffer.values.broadcast + readBuffer.values.unknown;
            if (sum > ranks.back().value) {
                ranks.back() = TimeValuePair{readBuffer.second, sum};
                std::sort(ranks.begin(), ranks.end(), [](const TimeValuePair &a, const TimeValuePair &b) { return a.value > b.value; });
            }

            // read next record
            file.read((char *) &readBuffer, resultRecordSize);
        }

        // write JSON
    writeJson:
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);
        for (const auto &pair : ranks) {
            // write object
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(rootArray, object);
            yyjson_mut_obj_add_int(document, object, "timestamp", pair.second);
            yyjson_mut_obj_add_int(document, object, "value", pair.value);
        }

        if (connection)
            Civet7::respond200(connection, document);
        else
            lastInterativeResult = document;
    }
}

void FeedRefinerPps::dumpResults(mg_connection *connection)
{
    // send header
    std::string chunk("Timestamp\tUnicast\tMulticast\tBroadcast\tUnknown\n"s);
    chunk.reserve(110000000);
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // send body
    std::ifstream file(messyRoomPrefix + "/values", std::ios::binary);
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);
    // read first record
    ResultRecord record;
    file.read((char *) &record, resultRecordSize);
    while (!file.eof()) {
        // fill chunk buffer
        chunk.append(epochToIsoDate(record.second) + '\t').append(std::to_string(record.values.unicast) + '\t').append(std::to_string(record.values.multicast) + '\t').append(std::to_string(record.values.broadcast) + '\t').append(std::to_string(record.values.unknown) + '\n');

        // flush chunk if its size is over 100MB
        if (chunk.size() > 100000000) {
            switch (mg_send_chunk(connection, chunk.data(), chunk.size())) {
            case 0:
                logger.log("Client closed socket. Cancelling operation."s);
                return;
            case -1:
                logger.log("Server encountered an error. Cancelling operation."s);
                return;
            default:
                chunk.clear();
            }
        }

        // read next record
        file.read((char *) &record, resultRecordSize);
    }

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

FeedRefinerLatency::FeedRefinerLatency(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerPerSecondStatistics(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerLatency"s);
    cachedChapter = SuperCodex::RTTS;

    // reserve RAM for buffer
    bufferSize = conditions.to - conditions.from + 1;
    buffer = new std::pair<uint32_t, ValuesRtt>[bufferSize];
    for (int i = 0; i < bufferSize; ++i)
        buffer[i] = std::make_pair(conditions.from + i, ValuesRtt{});
}

void FeedRefinerLatency::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    logger.log("Processing: "s + std::to_string(codices.size()));
    std::vector<std::vector<std::pair<int32_t, ValuesRtt>>> intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, std::vector<std::pair<int32_t, ValuesRtt>>>(
        codices,
        [&](const SuperCodex::Loader *codex) -> std::vector<std::pair<int32_t, ValuesRtt>> {
            // prepare for result set
            int indexOffset = codex->secondStart;
            size_t resultSize = codex->secondEnd - indexOffset + 1;
            std::vector<std::pair<int32_t, ValuesRtt>> result;
            for (int i = 0; i < resultSize; ++i)
                result.push_back(std::make_pair(i + indexOffset, ValuesRtt{}));

            // merge data
            for (auto rtt = codex->firstRtt(); rtt; rtt = codex->nextRtt(rtt))
                if (rtt->tail < 10000000000) { // ignore values more than 10 seconds since it can mean just idling more than having troubles
                    // simple sanity check
                    if (rtt->tail < 0) {
                        logger.log("Skipping negative RTT tail at "s + std::to_string(rtt->second) + ' ' + std::to_string(rtt->tail));
                        continue;
                    }

                    if (rtt->fromSmallToBig == codex->sessions.at(rtt->sessionId)->sourceIsSmall) {
                        result[rtt->second - indexOffset].second.numerator0 += rtt->tail;
                        ++result[rtt->second - indexOffset].second.denominator0;
                    } else {
                        result[rtt->second - indexOffset].second.numerator1 += rtt->tail;
                        ++result[rtt->second - indexOffset].second.denominator1;
                    }
                }

            return result;
        },
        affinityPartitioner);

    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](std::vector<std::vector<std::pair<int32_t, ValuesRtt>>> intermediatesFuture) {
            logger.log("Merging "s + std::to_string(intermediatesFuture.size()));
            for (const auto &intermediate : intermediatesFuture)
                for (const auto &pair : intermediate) {
                    auto offset = pair.first - conditions.from;
                    if (offset < 0 || offset >= bufferSize)
                        continue;
                    buffer[offset].second += pair.second;
                }
        },
        std::move(intermediates));
}

void FeedRefinerLatency::finalize()
{
    // update target time frame
    secondStart = conditions.from;
    secondEnd = conditions.to;

    // apply SuperCache
    if (conditions.cacheFrom) {
        FeatherLite feather(superCachePath, SQLITE_OPEN_READONLY);
        if (conditions.allowedIps.isEmpty) {
            feather.prepare("SELECT timestamp,value FROM rows WHERE timestamp>=? AND timestamp<=? AND chapter=?;"s);
            feather.bindInt(1, conditions.cacheFrom);
            feather.bindInt(2, conditions.cacheTo);
            feather.bindInt(3, cachedChapter);
        } else {
            feather.prepare("SELECT timestamp,value FROM rows WHERE timestamp>=? AND timestamp<=? AND signature=? AND chapter=?;"s);
            feather.bindInt(1, conditions.cacheFrom);
            feather.bindInt(2, conditions.cacheTo);
            feather.bindInt64(3, superCacheSignature);
            feather.bindInt(4, cachedChapter);
        }
        while (feather.next() == SQLITE_ROW) {
            std::string_view rawData = feather.getBlob(1);
            const FeedRefinerAbstract::ValuesRtt *cursor = (const FeedRefinerAbstract::ValuesRtt *) rawData.data();
            for (int i = feather.getInt(0) - conditions.from, iEnd = i + 60; i < iEnd; ++i) {
                buffer[i].second += *cursor;
                ++cursor;
            }
        }
    }

    // close the job
    std::ofstream valuesWriter(messyRoomPrefix + "/values"s, std::ios::out | std::ios::binary | std::ios::trunc);
    std::unique_ptr<char[]> writeBuffer(new char[536870912]); // 512MB
    valuesWriter.rdbuf()->pubsetbuf(writeBuffer.get(), 536870912);
    TimeValuePair record;
    for (size_t i = 0; i < bufferSize; ++i) {
        const auto &target = buffer[i];
        record = TimeValuePair{target.first, static_cast<int64_t>(target.second.represent())};
        valuesWriter.write((const char *) &record, timeValuePairSize);
    }
    valuesWriter.close();

    // finalize and log
    delete[] buffer;
    logger.log("Result ready to serve: "s + std::to_string(secondStart) + " -> "s + std::to_string(secondEnd));
}

FeedRefinerFlowCounts::FeedRefinerFlowCounts(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerPerSecondStatistics(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerFlowCounts"s);
    cachedChapter = SuperCodex::SESSIONS;

    // initialize buffer
    bufferSize = conditions.to - conditions.from + 1;
    buffer = new TimeValuePair[bufferSize];
    for (int i = 0; i < bufferSize; ++i)
        buffer[i] = TimeValuePair{conditions.from + i, 0};
}

void FeedRefinerFlowCounts::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    logger.log("Processing: "s + std::to_string(codices.size()));
    std::vector<Intermediate> intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, Intermediate>(
        codices,
        [&](const SuperCodex::Loader *codex) -> Intermediate {
            // initialize result variable
            Intermediate intermediate;
            intermediate.from = codex->secondStart;
            intermediate.to = codex->secondEnd;
            auto from = intermediate.from, to = intermediate.to;
            intermediate.counters.resize(to - from + 1);

            for (const auto &pair : codex->sessions) {
                const auto &session = *pair.second;
                // count up number of sessions
                for (size_t i = std::max(session.first.second, from) - from, iEnd = std::min(session.last.second, to) - from + 1; i < iEnd; ++i)
                    ++intermediate.counters[i];

                // check whether this session lives in first or last second
                if (session.first.second == from)
                    intermediate.sessionsFromHeads.insert(session.id);
                if (session.last.second == to)
                    intermediate.sessionsInTails.push_back(session.id);
            }

            return intermediate;
        },
        affinityPartitioner);

    // consolidate individual sessions
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Intermediate> intermediatesFuture) {
            for (const auto &intermediate : intermediatesFuture) {
                auto offset = intermediate.from - conditions.from;
                // merge counters
                for (size_t i = 0, iEnd = intermediate.counters.size(); i < iEnd; ++i) {
                    auto targetIndex = i + offset;
                    if (targetIndex >= 0 && targetIndex < bufferSize) {
                        buffer[targetIndex].value += intermediate.counters[i];
                    }
                }

                // adjust numbers for head and tail
                if (timestampFromLastTail == intermediate.from)
                    for (const auto &sessionId : sessionsInLastTails)
                        if (intermediate.sessionsFromHeads.contains(sessionId))
                            --buffer[offset].value;
                timestampFromLastTail = intermediate.to;
                sessionsInLastTails = intermediate.sessionsInTails;
            }
        },
        std::move(intermediates));
}

void FeedRefinerFlowCounts::finalize()
{
    // update target time frame
    secondStart = conditions.from;
    secondEnd = conditions.to;

    // apply SuperCache
    if (conditions.cacheFrom) {
        FeatherLite feather(CodexIndex::feedRoot + conditions.dataFeed + "/supercache.ps"s, SQLITE_OPEN_READONLY);
        feather.prepare("SELECT timestamp,value FROM rows WHERE timestamp>=? AND timestamp<=? AND chapter=?;"s);
        feather.bindInt(1, conditions.cacheFrom);
        feather.bindInt(2, conditions.cacheTo);
        feather.bindInt(3, SuperCodex::SESSIONS);
        while (feather.next() == SQLITE_ROW) {
            std::string_view rawData = feather.getBlob(1);
            const uint64_t *cursor = (const uint64_t *) rawData.data();
            for (int i = feather.getInt(0) - conditions.from, iEnd = i + 60; i < iEnd; ++i) {
                buffer[i].value = *cursor;
                ++cursor;
            }
        }
    }

    // write down "values" file
    std::ofstream valuesWriter(messyRoomPrefix + "/values"s, std::ios::out | std::ios::binary | std::ios::trunc);
    std::unique_ptr<char[]> writeBuffer(new char[536870912]); // 512MB
    valuesWriter.rdbuf()->pubsetbuf(writeBuffer.get(), 536870912);
    valuesWriter.write((const char *) buffer, timeValuePairSize * (conditions.to - conditions.from + 1));
    valuesWriter.close();
    delete[] buffer;
    logger.log("Result ready to serve: "s + std::to_string(secondStart) + " -> "s + std::to_string(secondEnd));
}

FeedRefinerMicroBurst::FeedRefinerMicroBurst(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    // initialize session store
    sessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();

    // initialize some more
    merged = new ankerl::unordered_dense::map<uint64_t, ankerl::unordered_dense::map<uint64_t, std::pair<long long, long long>>>();
    partial = new ankerl::unordered_dense::map<uint64_t, ankerl::unordered_dense::map<uint64_t, std::pair<long long, long long>>>();

    // override default configuration as needed
    if (conditions.parameters.contains("resolution"s)) {
        const std::string &resoultion = conditions.parameters.at("resolution"s);
        if (resoultion == "ms"s)
            divider = 1000000;
        else if (resoultion == "us"s)
            divider = 1000;
        else if (resoultion == "ns"s)
            divider = 1;
    }
    if (conditions.parameters.contains("threshold"s))
        try {
            threshold = std::stoll(conditions.parameters.at("threshold"s)) / 8; // input is in bits so we need to convert it to bytes
        } catch (...) {
        } // silenty ignore
}

void FeedRefinerMicroBurst::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string detail;
    if (parameters.contains("detail"s))
        detail = parameters.at("detail"s);

    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootArray = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, rootArray);
    if (detail.empty()) { // enumerate timestamps for detected microburst and total bytes transferred
        for (const auto &pair : burstedTimePoints) {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(rootArray, object);
            yyjson_mut_obj_add_int(document, object, "timestamp", pair.first);
            yyjson_mut_obj_add_int(document, object, "bytes", pair.second);
        }
    } else { // show list of IP-to-services for selected timestamp
        std::string filename = messyRoomPrefix + '/' + detail;
        if (std::filesystem::exists(filename)) { // this works only when file exists
            // preparation
            ResultRecord record;
            std::ifstream file;
            std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
            file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);

            // open file
            file.open(filename, std::ios::binary);

            // read first record
            file.read((char *) &record, resultRecordSize);
            while (file.gcount()) {
                // prepare for variables
                yyjson_mut_val *object = yyjson_mut_obj(document);
                std::string temp;

                // write object body
                temp = SuperCodex::stringToHex(std::string(record.ips, record.ipLength));
                yyjson_mut_obj_add_strncpy(document, object, "ip", temp.data(), temp.size());
                temp = SuperCodex::stringToHex(std::string(record.ips + record.ipLength, record.ipLength));
                yyjson_mut_obj_add_strncpy(document, object, "ip2", temp.data(), temp.size());
                yyjson_mut_obj_add_int(document, object, "port2", record.serverPort);
                yyjson_mut_obj_add_int(document, object, "iptoip2", record.clientToServer);
                yyjson_mut_obj_add_int(document, object, "ip2toip", record.serverToClient);

                // read next record
                yyjson_mut_arr_append(rootArray, object);
                file.read((char *) &record, resultRecordSize);
            }

            // close file
            file.close();
        }
    }

    // send the result and free working memory
    Civet7::respond200(connection, document);
}

void FeedRefinerMicroBurst::dumpResults(mg_connection *connection)
{
    // send header
    std::string chunk("Timestamp\tClientIP\tServerIP\tServerPort\tClientToServer\tServerToClient\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // send body chunks
    ResultRecord record;
    std::ifstream file;
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);
    for (const auto &pair : burstedTimePoints) {
        // open file
        file.open(messyRoomPrefix + '/' + std::to_string(pair.first), std::ios::binary);

        // read first record
        file.read((char *) &record, resultRecordSize);
        while (file.gcount()) {
            // prepare for timestamp
            std::string decimal = std::to_string(pair.first % 1000000000), timestamp = epochToIsoDate(pair.first / 1000000000) + '.' + std::string(9 - decimal.size(), '0') + decimal; // timestamp
            chunk.append(timestamp + '\t').append(SuperCodex::humanReadableIp(std::string(record.ips, record.ipLength)) + '\t').append(SuperCodex::humanReadableIp(std::string(record.ips + record.ipLength, record.ipLength)) + '\t').append(std::to_string(record.serverPort) + '\t').append(std::to_string(record.clientToServer) + '\t').append(std::to_string(record.serverToClient) + '\t').push_back('\n');

            // flush chunk if its size is over 100MB
            if (chunk.size() > 100000000) {
                switch (mg_send_chunk(connection, chunk.data(), chunk.size())) {
                case 0:
                    logger.log("Client closed socket. Cancelling operation."s);
                    return;
                case -1:
                    logger.log("Server encountered an error. Cancelling operation."s);
                    return;
                default:
                    chunk.clear();
                }
            }

            // read next record
            file.read((char *) &record, resultRecordSize);
        }

        // close file
        file.close();
    }

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

void FeedRefinerMicroBurst::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    // build raw data
    std::vector<Intermediate> intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, Intermediate>(
        codices,
        [&](const SuperCodex::Loader *codex) -> Intermediate {
            Intermediate intermediate;

            // get sessions
            intermediate.sessions.reserve(codex->sessions.size());
            for (const auto &pair : codex->sessions)
                intermediate.sessions.push_back(*pair.second);

            // get per packet counter
            for (auto packet = codex->firstPacket(); packet; packet = codex->nextPacket(packet)) {
                if (packet->fromSmallToBig)
                    intermediate.counters[static_cast<long long>(packet->second) * 1000000000 + packet->nanosecond / divider * divider][packet->sessionId].first += packet->savedLength;
                else
                    intermediate.counters[static_cast<long long>(packet->second) * 1000000000 + packet->nanosecond / divider * divider][packet->sessionId].second += packet->savedLength;
            }

            // determine first and last timestamp
            long long timestampStart = INT64_MAX, timestampEnd = 0;
            for (const auto &pair : intermediate.counters) {
                if (pair.first < timestampStart)
                    timestampStart = pair.first;
                if (pair.first > timestampEnd)
                    timestampEnd = pair.first;
            }

            // extract records from first and last timestamp
            for (const auto &pair : intermediate.counters) {
                if (pair.first == timestampStart)
                    intermediate.firsts.insert(pair);
                if (pair.first == timestampEnd)
                    intermediate.lasts.insert(pair);
            }
            for (const auto &pair : intermediate.firsts)
                intermediate.counters.erase(pair.first);
            for (const auto &pair : intermediate.lasts)
                intermediate.counters.erase(pair.first);

            // filter out non-microburst records
            for (auto i = intermediate.counters.begin(); i != intermediate.counters.end();) {
                unsigned long long sum = 0;
                for (const auto &counterPair : i->second)
                    sum += counterPair.second.first + counterPair.second.second;
                if (sum >= threshold)
                    ++i;
                else
                    i = intermediate.counters.erase(i);
            }

            return intermediate;
        },
        affinityPartitioner);

    // merge pack
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Intermediate> intermediatesFuture) {
            // background: merge sessions from current and new raw data
            std::thread sessionOrganizer([&]() {
                for (const auto &intermediate : intermediatesFuture)
                    updateTimestampAndMergeSessions(intermediate.sessions);
            });

            // merge data
            for (const auto &intermediate : intermediatesFuture) {
                // move obvious microbursts
                for (const auto &pair : intermediate.counters)
                    merged->insert(pair);

                // merge values from overlapping timestamps
                for (const auto &timestampPair : intermediate.lasts)
                    for (const auto &sessionPair : timestampPair.second) {
                        auto &target = (*partial)[timestampPair.first][sessionPair.first];
                        target.first += sessionPair.second.first;
                        target.second += sessionPair.second.second;
                    }
                for (const auto &timestampPair : *partial) {
                    unsigned long long sum = 0;
                    for (const auto &counterPair : timestampPair.second)
                        sum += counterPair.second.first + counterPair.second.second;
                    if (sum >= threshold)
                        merged->insert(timestampPair);
                }

                // refresh the container for partial records with new records
                partial->clear();
                for (const auto &pair : intermediate.firsts)
                    partial->insert(pair);
            }

            // wait for session organizer to finish
            sessionOrganizer.join();

            // flush fully merged data to files
            flushMerged();
        },
        intermediates);
}

void FeedRefinerMicroBurst::finalize()
{
    // finally, sort out microbursts from partial records once again
    for (const auto &timestampPair : *partial) {
        unsigned long long sum = 0;
        for (const auto &counterPair : timestampPair.second)
            sum += counterPair.second.first + counterPair.second.second;
        if (sum >= threshold)
            merged->insert(timestampPair);
    }
    delete partial; // it has done its use

    // final merge
    flushMerged();
    delete merged; // free fully used object

    // sort bursted time points
    std::sort(burstedTimePoints.begin(), burstedTimePoints.end(), [](const std::pair<long long, long long> &a, const std::pair<long long, long long> &b) -> bool { return a.first < b.first; });

    // finalize
    logger.log("Result ready to serve"s);
}

void FeedRefinerMicroBurst::flushMerged()
{
    // prepare to write file
    std::ofstream resultsFile;
    std::unique_ptr<char[]> resultsFileBuffer(new char[536870912]); // 512MB
    resultsFile.rdbuf()->pubsetbuf(resultsFileBuffer.get(), 536870912);
    for (const auto &timestampPair : *merged) {
        // merge records per IP-to-service
        ankerl::unordered_dense::map<std::string, ResultRecord> perIpToService;
        long long sum = 0;
        for (const auto &sessionPair : timestampPair.second) {
            // calculate sum
            sum += sessionPair.second.first + sessionPair.second.second;

            // build key for the IP-to-service
            const auto &session = sessions->at(sessionPair.first);
            int8_t ipLength = SuperCodex::ipLength(session.etherType);
            std::string key((const char *) session.ips, ipLength * 2);
            key.append((const char *) &session.destinationPort, 2);

            // create new or append to existing
            if (perIpToService.contains(key)) { // merge to existing IP-to-service record
                auto &targetRecord = perIpToService[key];
                if (session.sourceIsSmall) {
                    targetRecord.clientToServer += sessionPair.second.first;
                    targetRecord.serverToClient += sessionPair.second.second;
                } else {
                    targetRecord.clientToServer += sessionPair.second.second;
                    targetRecord.serverToClient += sessionPair.second.first;
                }
            } else { // create new IP-to-service record
                ResultRecord record{{}, session.destinationPort, ipLength, {}, {}};
                memcpy(record.ips, session.ips, 32);
                if (session.sourceIsSmall) {
                    record.clientToServer = sessionPair.second.first;
                    record.serverToClient = sessionPair.second.second;
                } else {
                    record.clientToServer = sessionPair.second.second;
                    record.serverToClient = sessionPair.second.first;
                }
                perIpToService[key] = std::move(record);
            }
        }

        // sort data by total data transferred
        std::vector<ResultRecord> perIpToServiceSorted;
        perIpToServiceSorted.reserve(perIpToService.size());
        for (const auto &pair : perIpToService)
            perIpToServiceSorted.push_back(pair.second);
        std::sort(perIpToServiceSorted.begin(), perIpToServiceSorted.end(), [](const ResultRecord &a, const ResultRecord &b) -> bool { return a.clientToServer + a.serverToClient > b.clientToServer + b.serverToClient; });

        // write down data to file
        resultsFile.open(messyRoomPrefix + '/' + std::to_string(timestampPair.first), std::ios::out | std::ios::binary | std::ios::trunc);
        for (const auto record : perIpToServiceSorted)
            resultsFile.write((const char *) &record, resultRecordSize);

        // register and close file
        burstedTimePoints.push_back(std::make_pair(timestampPair.first, sum));
        resultsFile.close();
    }

    // remove records written to disk from RAM
    merged->clear();
}

FeedRefinerRaw::FeedRefinerRaw(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerRaw"s);

    // initialize session store
    sessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();

    // set whether to build packet hash
    if (conditions.parameters.contains("buildpackethash"s) && conditions.parameters.at("buildpackethash"s) == "true")
        buildPacketHash = true;
}

void FeedRefinerRaw::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // obtain target chapter
    if (parameters.contains("chapter"s) == 0) {
        mg_send_http_error(connection, 400, "parameter 'chapter' is required.");
        return;
    }
    const std::string &chapter = parameters.at("chapter"s);

    // enumerate SuperCodex files to read
    std::vector<std::string> targetSuperCodexFiles;
    targetSuperCodexFiles.reserve(conditions.codicesToGo.size()); // at maximum
    for (const auto &fileName : conditions.codicesToGo) {
        const auto duration = SuperCodex::durationContained(fileName);

        // check boundary
        if (duration.second < from)
            continue;
        if (duration.first > to)
            break;

        // add to target files
        targetSuperCodexFiles.push_back(fileName);
    }

    // adjust timestamp for session filter
    SuperCodex::Conditions adjusted = conditions;
    adjusted.from = from;
    adjusted.to = to;

    // determine which chapter to send
    std::string (FeedRefinerRaw::*readChapter)(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters) = nullptr;
    if (chapter == "packets"s)
        readChapter = &FeedRefinerRaw::chapterPackets;
    else if (chapter == "sessions"s) {
        // exceptional case: session data is not from SuperCodex files, but from consolidated data in RAM
        targetSuperCodexFiles.clear();
        targetSuperCodexFiles.push_back("");
        readChapter = &FeedRefinerRaw::chapterSessions;
    } else if (chapter == "bps"s)
        readChapter = &FeedRefinerRaw::chapterBpsPerSession;
    else if (chapter == "pps"s)
        readChapter = &FeedRefinerRaw::chapterPpsPerSession;
    else if (chapter == "rtts"s)
        readChapter = &FeedRefinerRaw::chapterRtts;
    else if (chapter == "timeouts"s)
        readChapter = &FeedRefinerRaw::chapterTimeouts;
    else if (chapter == "remarks"s)
        readChapter = &FeedRefinerRaw::chapterRemarks;
    else if (chapter == "tcpsyns"s)
        readChapter = &FeedRefinerRaw::chapterTcpSyns;
    else if (chapter == "tcprsts"s)
        readChapter = &FeedRefinerRaw::chapterTcpRsts;
    else if (chapter == "tcpmiscanomalies"s)
        readChapter = &FeedRefinerRaw::chapterTcpMiscAnomalies;
    else if (chapter == "tcpretransmissions"s)
        readChapter = &FeedRefinerRaw::chapterTcpRetransmissions;
    else if (chapter == "tcpdupacks"s)
        readChapter = &FeedRefinerRaw::chapterTcpDupAcks;
    else if (chapter == "packethash"s) {
        // behave exceptionally: handle in unique way
        processPacketHash(connection, parameters);
        return;
    }

    // read and send selected chapter
    if (readChapter == nullptr) {
        mg_send_http_error(connection, 400, ("Unknown chapter: "s + chapter).data());
        return;
    }

    // send HTTP header for chunked encoding
    Civet7::respond200(connection, nullptr, 0, "application/octet-stream");

    // send body chunk
    std::string chunk;
    chunk.reserve(110000000); // 110 MB
    for (const auto &fileName : targetSuperCodexFiles) {
        // fill chunk from SuperCodex file
        chunk.append(std::invoke(readChapter, this, fileName, adjusted, bindValue, parameters));

        // determine whether to flush
        if (chunk.size() > 100000000) {
            switch (mg_send_chunk(connection, chunk.data(), chunk.size())) {
            case 0:
                logger.log("Client closed socket. Cancelling operation."s);
                return;
            case -1:
                logger.log("Server encountered an error. Cancelling operation."s);
                return;
            default:
                chunk.clear();
            }
        }
    }

    // send final chunk
    if (!chunk.empty()) {
        switch (mg_send_chunk(connection, chunk.data(), chunk.size())) {
        case 0:
            logger.log("Final - client closed socket. Cancelling operation."s);
            return;
        case -1:
            logger.log("Final - server encountered an error. Cancelling operation."s);
            return;
        }
    }
    mg_send_chunk(connection, "", 0);
}

void FeedRefinerRaw::dumpResults(mg_connection *connection)
{
    // do nothing
    std::string notice = "No data to show for default tab separated. Please use type=binary combined with parameter \"chapter\"."s;
    mg_send_chunk(connection, notice.data(), notice.size());
    mg_send_chunk(connection, "", 0);
}

void FeedRefinerRaw::put(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // check whether packet hash was declared to be built
    if (!buildPacketHash || packetHashFiles.empty()) {
        mg_send_http_error(connection, 412, "Packet hashtable didn't build. Check whether buildpackethash=true was set or time duration was out of bound on POST request.");
        return;
    }

    if (parameters.contains("raw"s)) {
        // decompress uploaded stream
        int32_t from, to;
        std::string fileName;
        SuperCodex::Glyph decompressed = decompressPacketHash(parameters.at("raw"s), &from, &to, &fileName);
        if (!decompressed.data) {
            mg_send_http_error(connection, 500, "Failed to decompress source file.");
            return;
        }
        if (decompressed.size % packetHashSize != 0) {
            mg_send_http_error(connection, 412, "Data incompatible or corrupted");
            return;
        }

        // build packet hash list
        std::vector<const PacketHash *> inputs;
        inputs.reserve(decompressed.size / packetHashSize);
        for (const PacketHash *i = (const PacketHash *) decompressed.data, *iEnd = (const PacketHash *) (decompressed.data + decompressed.size); i < iEnd; ++i)
            inputs.push_back(i);

        // prepare for binary search
        size_t indexLeft = 0, indexRight = packetHashFiles.size() - 1;
        std::function<void(size_t &, size_t &, const int32_t)> searchPackethashFile = [&](size_t &left, size_t &right, const int32_t target) {
            const size_t middleIndex = (left + right) / 2;
            const auto &middle = packetHashFiles[middleIndex];
            if (target < middle.from)
                right = middleIndex;
            else if (target >= middle.to)
                left = middleIndex;
            else {
                left = middleIndex;
                right = middleIndex;
            }
        };

        // find left end
        {
            size_t left = 0, right = packetHashFiles.size() - 1;
            while (right - left > 1)
                searchPackethashFile(left, right, from - 10); // look a bit backward
            indexLeft = left;
        }

        // find right end
        {
            size_t left = 0, right = packetHashFiles.size() - 1;
            while (right - left > 1)
                searchPackethashFile(left, right, to + 10); // look a bit forward
            indexRight = right;
        }

        // load packet hash files to search
        std::vector<SuperCodex::Glyph> localHashes;
        localHashes.reserve(indexRight - indexLeft + 1);
        for (size_t i = indexLeft; i <= indexRight; ++i) {
            const std::string &fileName = packetHashFiles.at(i).name;
            logger.log("Load "s + fileName);
            localHashes.push_back(decompressPacketHash(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(messyRoomPrefix + '/' + fileName, std::ifstream::binary).rdbuf()).str()));
        }
        std::function buildIndex = [](const SuperCodex::Glyph raw) -> std::vector<const PacketHash *> {
            std::vector<const PacketHash *> result;
            result.reserve(raw.size / packetHashSize);
            for (const PacketHash *i = (const PacketHash *) raw.data, *iEnd = (const PacketHash *) (raw.data + raw.size); i < iEnd; ++i)
                result.push_back(i);
            return result;
        };
        std::vector<std::vector<const PacketHash *>> localHashIndices = SuperCodex::parallel_convert<SuperCodex::Glyph, std::vector<const PacketHash *>>(localHashes, buildIndex);

        // find matching hashes to calculate latency or detect loss
        std::vector<PacketHash> results;
        results.reserve(inputs.size());
        for (auto &input : inputs) {
            // search
            std::function<int64_t(const std::vector<const PacketHash *>)> searchAmongHashes = [&](const std::vector<const PacketHash *> index) -> int64_t {
                // exception handling: no hashes for given SuperCodex file
                if (index.empty())
                    return INT64_MIN;

                // prepare for variables
                const uint64_t hash = input->hash;
                const int64_t timestamp = input->timestamp;

                // use binary search to find matching packet
                size_t left = 0, right = index.size() - 1;
                std::function<bool(size_t &, size_t &, const uint64_t)> binarySearch = [&](size_t &left, size_t &right, const uint64_t target) -> bool {
                    // check boundary
                    if (target < index[left]->hash || target > index[right]->hash)
                        return false; // target out of bound

                    // compare against middle
                    const size_t middle = (left + right) / 2;
                    const uint64_t middleHash = index[middle]->hash;
                    if (target < middleHash) {
                        right = middle - 1;
                    } else if (target > middleHash) {
                        left = middle + 1;
                    } else { // exact match: target == middleHash
                        left = middle;
                        right = middle;
                    }

                    // report that target is still inbound
                    return true;
                };
                while (right - left > 1)
                    if (!binarySearch(left, right, hash)) // hash out of bound: target not found
                        return INT64_MIN; // packet not found

                // determine result
                for (int i = left; i <= right; ++i) {
                    const auto &toCompare = index[i];
                    if (hash == toCompare->hash)
                        return toCompare->timestamp - timestamp;
                }

                return INT64_MIN; // packet not found
            };
            std::vector<int64_t> searchRaw = SuperCodex::parallel_convert<std::vector<const PacketHash *>, int64_t>(localHashIndices, searchAmongHashes);

            // determine result
            std::sort(searchRaw.begin(), searchRaw.end());
            PacketHash result = *input;
            if (searchRaw.back() < 0) {
                if (searchRaw.back() == INT64_MIN) // packet lost
                    result.status = PacketHash::Status::LOST;
                else // reverse direction
                    result.timestamp = searchRaw.back() * -1;
            } else { // forward direction (searchRaw.back()>=0)
                int64_t lastLatency = searchRaw.back();
                while (searchRaw.back() > 0) {
                    lastLatency = searchRaw.back();
                    searchRaw.pop_back();
                }
                result.timestamp = lastLatency;
            }
            results.push_back(result);
        }

        // DEBUG: show result in console
        int reverse = 0, dropped = 0, found = 0, zero = 0;
        for (const auto &result : results)
            switch (result.status) {
            case PacketHash::Status::NORMAL: {
                if (result.timestamp > 0)
                    ++found;
                else if (result.timestamp < 0)
                    ++reverse;
                else
                    ++zero;
            } break;
            case PacketHash::Status::LOST:
                ++dropped;
                break;
            }
        logger.debug("All / Found / Zero / Dropped / Reverse: "s + std::to_string(inputs.size()) + ' ' + std::to_string(found) + ' ' + std::to_string(zero) + ' ' + std::to_string(dropped) + ' ' + std::to_string(reverse));

        // save results
        if (!results.empty()) {
            packetHashMutex.lock();
            std::sort(results.begin(), results.end(), [](const PacketHash &a, const PacketHash &b) -> bool { return a.hash < b.hash; });
            std::ofstream writer;
            std::unique_ptr<char[]> step1Buffer(new char[536870912]); // 512MB
            writer.rdbuf()->pubsetbuf(step1Buffer.get(), 536870912);
            uint64_t saveId = results.front().hash / 1000000000000000ULL;
            writer.open(messyRoomPrefix + "/co"s + std::to_string(saveId), std::ios::app | std::ios::binary);
            for (const auto &result : results) {
                // check whether target file is changed
                uint64_t saveIdNow = result.hash / 1000000000000000ULL;
                if (saveIdNow != saveId) {
                    writer.close();
                    writer.open(messyRoomPrefix + "/co"s + std::to_string(saveId), std::ios::app | std::ios::binary);
                }

                // save file
                writer.write((const char *) &result, packetHashSize);
            }
            writer.close();
            packetHashMutex.unlock();
        }

        // clean up
        delete[] decompressed.data;
        for (auto &glyph : localHashes)
            delete[] glyph.data;

        // return result
        mg_send_http_error(connection, 204, "\r\n\r\n");
    } else
        mg_send_http_error(connection, 400, "Check whether Content-Type is application/octect-stream.");
}

void FeedRefinerRaw::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    std::function<Intermediary(SuperCodex::Loader *)> extract = [&](SuperCodex::Loader *loader) -> Intermediary {
        Intermediary result;
        result.fileName = loader->fileName;
        result.from = loader->secondStart;
        result.to = loader->secondEnd;

        // read sessions
        for (const auto &pair : loader->sessions)
            result.sessions.push_back(*pair.second);

        // merge and sort packet hashes
        if (buildPacketHash) {
            for (auto packet = loader->firstPacket(); packet; packet = loader->nextPacket(packet))
                result.hashedPackets.push_back(packetHash(packet));
            // sort and deduplicate
            std::sort(result.hashedPackets.begin(), result.hashedPackets.end(), [](const PacketHash &a, const PacketHash &b) -> bool { return a.hash < b.hash || ((a.hash == b.hash) && (a.timestamp < b.timestamp)); });
            for (long long i = result.hashedPackets.size() - 2; i >= 0; --i)
                if (result.hashedPackets[i].hash == result.hashedPackets[i + 1].hash)
                    result.hashedPackets.erase(result.hashedPackets.begin() + i + 1);
        }

        return result;
    };
    std::vector<Intermediary> intermediaries = SuperCodex::parallel_convert<SuperCodex::Loader *, Intermediary>(codices, extract);

    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Intermediary> intermediariesFuture) {
            // merge session data in the background
            std::thread threadSessionMerge([&]() {
                for (const auto &intermediary : intermediariesFuture)
                    updateTimestampAndMergeSessions(intermediary.sessions);
            });

            // flush packet hashes in parallel
            if (buildPacketHash)
                tbb::parallel_for_each(intermediariesFuture, [&](const Intermediary &intermediary) {
                    // compress body
                    int32_t originalSize = packetHashSize * intermediary.hashedPackets.size();
                    auto compressed = SuperCodex::compress((const char *) intermediary.hashedPackets.data(), originalSize);

                    // prepare to write file
                    uint32_t fileHash = fnv32a(compressed.data, compressed.size); // hash for compressed data
                    std::ofstream writer(messyRoomPrefix + "/ph"s + std::to_string(intermediary.from) + '-' + std::to_string(fileHash), std::ios::binary);

                    // write headers
                    writer.write((const char *) &intermediary.from, 4);
                    writer.write((const char *) &intermediary.to, 4);
                    writer.write((const char *) &compressed.size, 4);
                    writer.write((const char *) &originalSize, 4);

                    // write body
                    writer.write(compressed.data, compressed.size);

                    // write SuperCodex filename
                    writer.write(intermediary.fileName.data(), intermediary.fileName.size());

                    // finalize
                    writer.close();
                    delete[] compressed.data;
                });

            // wait for session merge to complete
            threadSessionMerge.join();
        },
        std::move(intermediaries));
}

void FeedRefinerRaw::finalize()
{
    // build list of packet hash files
    if (buildPacketHash) {
        for (const auto &entry : std::filesystem::directory_iterator(messyRoomPrefix))
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                if (filename.substr(0, 2) == "ph") {
                    std::ifstream file(entry.path(), std::ios::binary);
                    char buffer[8];
                    file.read(buffer, 8);
                    packetHashFiles.push_back(PacketHashProfile{*(uint32_t *) buffer, *(uint32_t *) (buffer + 4), filename});
                    file.close();
                }
            }
        std::sort(packetHashFiles.begin(), packetHashFiles.end(), [](const PacketHashProfile &a, PacketHashProfile &b) -> bool { return a.from < b.from; }); // sort by filename
    }

    // copy sessions, as after finalization original session store will be removed
    sessionStore = std::move(*sessions);
    sessions = nullptr;
    logger.log("Result ready to serve: "s + std::to_string(sessionStore.size()));
}

FeedRefinerRaw::PacketHash FeedRefinerRaw::packetHash(const SuperCodex::Packet *packet)
{
    // prepare for basic information
    return PacketHash{packet->index,
                      static_cast<uint16_t>(packet->fromSmallToBig),
                      PacketHash::Status::NORMAL, // we have no idea whether this packet is lost or not when calculating the hash value
                      fnv64a(&packet->status, 2, fnv64a(&packet->savedLength, 4, fnv64a(&packet->tcpAck, 4, fnv64a(&packet->tcpSeq, 4, fnv64a(&packet->payloadDataSize, 2, fnv64a(packet->fromSmallToBig)))))), // hash
                      packet->sessionId,
                      static_cast<int64_t>(packet->second) * 1000000000 + packet->nanosecond};
}

std::string FeedRefinerRaw::chapterPackets(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string result;
    result.reserve(110000000); // 110 MB
    SuperCodex::Loader loader(fileName, static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::PACKETS), filter);
    for (auto packet = loader.firstPacket(); packet; packet = loader.nextPacket(packet))
        result.append((const char *) packet, SuperCodex::packetSize);

    return result;
}

std::string FeedRefinerRaw::chapterSessions(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string result;
    result.reserve(110000000); // 110 MB
    for (const auto &pair : sessionStore)
        if (pair.second.first.second >= filter.from && pair.second.last.second <= filter.to)
            result.append((const char *) &pair.second, SuperCodex::sessionSize);

    return result;
}

std::string FeedRefinerRaw::chapterBpsPerSession(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string result;
    result.reserve(110000000); // 110 MB
    SuperCodex::Loader loader(fileName, static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::BPSPERSESSION), filter);
    for (auto bps = loader.firstBpsPerSession(); bps; bps = loader.nextBpsPerSession(bps))
        result.append((const char *) bps, SuperCodex::Loader::bpsPpsItemSize);

    return result;
}

std::string FeedRefinerRaw::chapterPpsPerSession(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string result;
    result.reserve(110000000); // 110 MB
    SuperCodex::Loader loader(fileName, static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::PPSPERSESSION), filter);
    for (auto pps = loader.firstPpsPerSession(); pps; pps = loader.nextPpsPerSession(pps))
        result.append((const char *) pps, SuperCodex::Loader::bpsPpsItemSize);

    return result;
}

std::string FeedRefinerRaw::chapterRtts(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string result;
    result.reserve(110000000); // 110 MB
    SuperCodex::Loader loader(fileName, static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::RTTS), filter);
    for (auto rtt = loader.firstRtt(); rtt; rtt = loader.nextRtt(rtt))
        result.append((const char *) rtt, SuperCodex::packetMarkerSize);

    return result;
}

std::string FeedRefinerRaw::chapterTimeouts(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string result;
    result.reserve(110000000); // 110 MB
    SuperCodex::Loader loader(fileName, static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::TIMEOUTS), filter);
    for (auto timeout = loader.firstTimeout(); timeout; timeout = loader.nextTimeout(timeout))
        result.append((const char *) timeout, SuperCodex::timeoutSize);

    return result;
}

std::string FeedRefinerRaw::chapterRemarks(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string result;
    result.reserve(110000000); // 110 MB
    SuperCodex::Loader loader(fileName, static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::REMARKS), filter);
    for (auto remarks = loader.firstRemarks(); remarks.content; remarks = loader.nextRemarks(remarks))
        result.append((const char *) &remarks, 12).append(remarks.content, remarks.size);

    return result;
}

std::string FeedRefinerRaw::chapterTcpSyns(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string result;
    result.reserve(110000000); // 110 MB
    SuperCodex::Loader loader(fileName, static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::TCPSYNS), filter);
    for (auto tcpSyn = loader.firstTcpSyn(); tcpSyn; tcpSyn = loader.nextTcpSyn(tcpSyn))
        result.append((const char *) tcpSyn, SuperCodex::packetMarkerSize);

    return result;
}

std::string FeedRefinerRaw::chapterTcpRsts(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string result;
    result.reserve(110000000); // 110 MB
    SuperCodex::Loader loader(fileName, static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::TCPRSTS), filter);
    for (auto tcpRst = loader.firstTcpRst(); tcpRst; tcpRst = loader.nextTcpRst(tcpRst))
        result.append((const char *) tcpRst, SuperCodex::packetMarkerSize);

    return result;
}

std::string FeedRefinerRaw::chapterTcpMiscAnomalies(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string result;
    result.reserve(110000000); // 110 MB
    SuperCodex::Loader loader(fileName, static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::TCPMISCANOMALIES), filter);
    for (auto tcpMiscAnomaly = loader.firstTcpMiscAnomaly(); tcpMiscAnomaly; tcpMiscAnomaly = loader.nextTcpMiscAnomaly(tcpMiscAnomaly))
        result.append((const char *) tcpMiscAnomaly, SuperCodex::packetMarkerSize);

    return result;
}

std::string FeedRefinerRaw::chapterTcpRetransmissions(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string result;
    result.reserve(110000000); // 110 MB
    SuperCodex::Loader loader(fileName, static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::TCPRETRANSMISSIONS), filter);
    for (auto tcpRetransmission = loader.firstTcpRetransmission(); tcpRetransmission; tcpRetransmission = loader.nextTcpRetransmission(tcpRetransmission))
        result.append((const char *) tcpRetransmission, SuperCodex::packetMarkerSize);

    return result;
}

std::string FeedRefinerRaw::chapterTcpDupAcks(const std::string &fileName, const SuperCodex::Conditions &filter, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string result;
    result.reserve(110000000); // 110 MB
    SuperCodex::Loader loader(fileName, static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::TCPDUPACKS), filter);
    for (auto tcpDupAck = loader.firstTcpDupAck(); tcpDupAck; tcpDupAck = loader.nextTcpDupAck(tcpDupAck))
        result.append((const char *) tcpDupAck, SuperCodex::packetMarkerSize);

    return result;
}

void FeedRefinerRaw::processPacketHash(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    if (parameters.contains("target"s)) {
        const std::string &target = parameters.at("target"s);
        if (target == "result"s) { // report result until now
            // data structure for latency & loss
            struct Summary
            {
                uint64_t sessionId;
                struct
                {
                    int64_t sum = 0, count = 0;
                    std::vector<std::pair<int32_t, int64_t>> losses; // packet index + timestamp
                } smallToBig, bigToSmall;
            };
            ankerl::unordered_dense::map<uint64_t, Summary> summaries; // session ID + summary

            // read accumualted data
            packetHashMutex.lock();
            for (const auto &entry : std::filesystem::directory_iterator(messyRoomPrefix))
                if (entry.is_regular_file()) {
                    auto path = entry.path();
                    if (path.filename().string().substr(0, 2) == "co"s) {
                        // prepare for stream
                        std::ifstream reader(path, std::ios::binary);
                        std::unique_ptr<char[]> step1Buffer(new char[536870912]); // 512MB
                        reader.rdbuf()->pubsetbuf(step1Buffer.get(), 536870912);

                        // start reading
                        PacketHash buffer;
                        reader.read((char *) &buffer, packetHashSize);
                        while (reader.gcount() == packetHashSize) { // if gcount() doesn't match to packetHashSize, chances are that the data is corrupt
                            summaries[buffer.sessionId].sessionId = buffer.sessionId;
                            if (buffer.fromSmallToBig) {
                                auto &target = summaries[buffer.sessionId].smallToBig;
                                if (buffer.status == PacketHash::Status::LOST)
                                    target.losses.push_back(std::make_pair(buffer.index, buffer.timestamp));
                                else {
                                    target.sum += buffer.timestamp;
                                    ++target.count;
                                }
                            } else {
                                auto &target = summaries[buffer.sessionId].bigToSmall;
                                if (buffer.status == PacketHash::Status::LOST)
                                    target.losses.push_back(std::make_pair(buffer.index, buffer.timestamp));
                                else {
                                    target.sum += buffer.timestamp;
                                    ++target.count;
                                }
                            }

                            // read next
                            reader.read((char *) &buffer, packetHashSize);
                        }
                    }
                }
            packetHashMutex.unlock();

            // enumerate latencies and losses
            struct Latency
            {
                uint64_t sessionId;
                int8_t isSmallToBig;
                int64_t averageLatency;
            };
            std::vector<Latency> latencies;
            latencies.reserve(summaries.size() * 2);
            std::vector<const Summary *> lossesSorted;
            lossesSorted.reserve(summaries.size());
            for (const auto &pair : summaries) {
                latencies.push_back(Latency{pair.first, 1, pair.second.smallToBig.sum / (pair.second.smallToBig.count ? pair.second.smallToBig.count : 1)});
                latencies.push_back(Latency{pair.first, 0, pair.second.bigToSmall.sum / (pair.second.bigToSmall.count ? pair.second.bigToSmall.count : 1)});
                lossesSorted.push_back(&pair.second);
            }
            // sort latencies by slowest to fastest
            std::sort(latencies.begin(), latencies.end(), [](const Latency &a, const Latency &b) -> bool { return a.averageLatency > b.averageLatency; });
            // sort packet losses by number of packets lost
            std::sort(lossesSorted.begin(), lossesSorted.end(), [](const Summary *a, const Summary *b) -> bool { return a->smallToBig.losses.size() + a->bigToSmall.losses.size() > b->smallToBig.losses.size() + b->bigToSmall.losses.size(); });

            // write JSON result
            yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
            yyjson_mut_val *rootObject = yyjson_mut_obj(document);
            yyjson_mut_doc_set_root(document, rootObject);

            // determine how many slow transfers will be sent
            size_t slowTransfersLimit = 100;
            if (parameters.contains("slowtransferlimit"s))
                slowTransfersLimit = std::stoll(parameters.at("slowtransferlimit"s));
            if (slowTransfersLimit > latencies.size())
                slowTransfersLimit = latencies.size();

            // enumerate sessions with slow packet transfers
            yyjson_mut_val *latencyArray = yyjson_mut_arr(document);
            yyjson_mut_obj_add_val(document, rootObject, "latencies", latencyArray);
            for (size_t i = 0; i < slowTransfersLimit; ++i) {
                const auto &latency = latencies[i];
                yyjson_mut_val *object = yyjson_mut_obj(document);
                yyjson_mut_arr_add_val(latencyArray, object);
                yyjson_mut_obj_add_uint(document, object, "sessionid", latency.sessionId);
                yyjson_mut_obj_add_uint(document, object, "direction", latency.isSmallToBig);
                yyjson_mut_obj_add_uint(document, object, "latency", latency.averageLatency);
            }

            // determine how many sessions with lost packets should be sent
            size_t packetLossLimit = 100;
            if (parameters.contains("packetlosslimit"s))
                packetLossLimit = std::stoll(parameters.at("packetlosslimit"s));
            if (packetLossLimit > lossesSorted.size())
                packetLossLimit = lossesSorted.size();

            // enumerate sessions with lost packets
            yyjson_mut_val *packetLossArray = yyjson_mut_arr(document);
            yyjson_mut_obj_add_val(document, rootObject, "packetslost", packetLossArray);
            for (size_t i = 0; i < packetLossLimit; ++i) {
                const auto &sessionWithLostPackets = lossesSorted[i];

                // exception handling: no more packet losses at all
                if (sessionWithLostPackets->smallToBig.losses.empty() && sessionWithLostPackets->bigToSmall.losses.empty())
                    break;

                // prepare for the object
                yyjson_mut_val *object = yyjson_mut_obj(document), *lostStb = yyjson_mut_arr(document), *lostBts = yyjson_mut_arr(document);
                yyjson_mut_arr_add_val(packetLossArray, object);
                yyjson_mut_obj_add_uint(document, object, "sessionid", sessionWithLostPackets->sessionId);
                yyjson_mut_obj_add_val(document, object, "loststb", lostStb);
                yyjson_mut_obj_add_val(document, object, "lostbts", lostBts);

                // describe in detail
                for (const auto &item : sessionWithLostPackets->smallToBig.losses) {
                    yyjson_mut_val *lostPacket = yyjson_mut_obj(document);
                    yyjson_mut_arr_add_val(lostStb, lostPacket);
                    yyjson_mut_obj_add_int(document, lostPacket, "index", item.first);
                    yyjson_mut_obj_add_int(document, lostPacket, "timestamp", item.second);
                }
                for (const auto &item : sessionWithLostPackets->bigToSmall.losses) {
                    yyjson_mut_val *lostPacket = yyjson_mut_obj(document);
                    yyjson_mut_arr_add_val(lostBts, lostPacket);
                    yyjson_mut_obj_add_int(document, lostPacket, "index", item.first);
                    yyjson_mut_obj_add_int(document, lostPacket, "timestamp", item.second);
                }
            }

            // send JSON
            Civet7::respond200(connection, document);
        } else { // send selected packet hash file
            std::string fullPath = messyRoomPrefix + '/' + target;
            if (std::filesystem::exists(fullPath)) {
                std::string payload = static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(fullPath, std::ifstream::binary).rdbuf()).str();
                Civet7::respond200(connection, payload.data(), payload.size(), "application/octet-stream"s);
            }
        }
    } else { // enumerate packet hash files
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);
        for (const auto &file : packetHashFiles)
            yyjson_mut_arr_add_strn(document, rootArray, file.name.data(), file.name.size());
        Civet7::respond200(connection, document);
    }
}

SuperCodex::Glyph FeedRefinerRaw::decompressPacketHash(const std::string &compressed, int32_t *from, int32_t *to, std::string *fileName)
{
    // read header
    const char *head = compressed.data();
    uint32_t from_ = *(uint32_t *) head, to_ = *(uint32_t *) (head + 4);
    int32_t compressedSize = *(uint32_t *) (head + 8), originalSize = *(uint32_t *) (head + 12);
    if (from)
        *from = from_;
    if (to)
        *to = to_;

    // check timestamp boundary
    if (from_ > packetHashFiles.back().to || to_ < packetHashFiles.front().from) {
        logger.oops("Timestamp out of bound. From="s + std::to_string(from_) + " / To="s + std::to_string(to_));
        return SuperCodex::Glyph{};
    }

    // extract filename as needed
    if (fileName)
        *fileName = compressed.substr(16 + compressedSize);

    // decompress and return
    char *decompressed = SuperCodex::decompress(SuperCodex::Glyph{(char *) (head + 16), compressedSize}, compressedSize, originalSize);
    if (decompressed)
        return SuperCodex::Glyph{decompressed, originalSize};
    else
        return SuperCodex::Glyph{};
}

FeedRefinerBps2::FeedRefinerBps2(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerBps2"s);

    // reserve RAM
    finalSize = conditions.to - conditions.from + 1;
    final = new Stats[finalSize];
    for (int i = 0; i < finalSize; ++i)
        final[i] = Stats{conditions.from + i, 0, 0, 0, 0};

    // build internal IP list
    std::istringstream tokenizer(conditions.parameters.at("internalips"s));
    for (std::string ipRaw; std::getline(tokenizer, ipRaw, ',');)
        internalIps.registerNetwork(ipRaw);
}

void FeedRefinerBps2::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    if (bindValue == 0) {
        // build result source
        if (to > secondEnd - secondStart)
            to = secondEnd - secondStart + 1;
        from += secondStart;
        to += secondEnd;

        // write JSON
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);

        // read first record
        for (size_t i = 0; i < finalSize; ++i) {
            const auto &record = final[i];
            // check scope
            if (record.second < from)
                continue;
            if (record.second > to)
                break;

            // write JSON object
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(rootArray, object);
            yyjson_mut_obj_add_int(document, object, "timestamp", record.second);
            yyjson_mut_obj_add_int(document, object, "ingress", record.ingress);
            yyjson_mut_obj_add_int(document, object, "egress", record.egress);
            yyjson_mut_obj_add_int(document, object, "local", record.local);
            yyjson_mut_obj_add_int(document, object, "other", record.other);
        }

        Civet7::respond200(connection, document);
    } else if (bindValue > 0) {
        // prepare for reading file
        uint32_t timestamp = conditions.from, next = timestamp + bindValue;
        int64_t containers = 0;
        Stats top{}, total{}, bottom{0, INT64_MAX, INT64_MAX, INT64_MAX, INT64_MAX};
        struct Timestamps
        {
            uint32_t ingress, egress, local, other;
        } topAt{timestamp, timestamp, timestamp, timestamp}, bottomAt{timestamp, timestamp, timestamp, timestamp};

        // write JSON
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);

        // read first record
        for (int i = timestamp, iEnd = conditions.to + 1; i < iEnd; ++i) {
            auto &record = final[i - conditions.from];
            if (i >= next) {
                // write object
                yyjson_mut_val *object = yyjson_mut_obj(document);
                yyjson_mut_arr_append(rootArray, object);
                yyjson_mut_obj_add_int(document, object, "timestamp", timestamp);
                yyjson_mut_obj_add_int(document, object, "containers", containers);

                // ingress
                yyjson_mut_val *ingress = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "ingress", ingress);
                yyjson_mut_obj_add_int(document, ingress, "total", total.ingress);
                yyjson_mut_obj_add_int(document, ingress, "top", top.ingress);
                yyjson_mut_obj_add_int(document, ingress, "bottom", bottom.ingress == INT64_MAX ? 0 : bottom.ingress);
                yyjson_mut_obj_add_int(document, ingress, "topat", topAt.ingress);
                yyjson_mut_obj_add_int(document, ingress, "bottomat", bottomAt.ingress);

                // egress
                yyjson_mut_val *egress = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "egress", egress);
                yyjson_mut_obj_add_int(document, egress, "total", total.egress);
                yyjson_mut_obj_add_int(document, egress, "top", top.egress);
                yyjson_mut_obj_add_int(document, egress, "bottom", bottom.egress == INT64_MAX ? 0 : bottom.egress);
                yyjson_mut_obj_add_int(document, egress, "topat", topAt.egress);
                yyjson_mut_obj_add_int(document, egress, "bottomat", bottomAt.egress);

                // local
                yyjson_mut_val *local = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "local", local);
                yyjson_mut_obj_add_int(document, local, "total", total.local);
                yyjson_mut_obj_add_int(document, local, "top", top.local);
                yyjson_mut_obj_add_int(document, local, "bottom", bottom.local == INT64_MAX ? 0 : bottom.local);
                yyjson_mut_obj_add_int(document, local, "topat", topAt.local);
                yyjson_mut_obj_add_int(document, local, "bottomat", bottomAt.local);

                // other
                yyjson_mut_val *other = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "other", other);
                yyjson_mut_obj_add_int(document, other, "total", total.other);
                yyjson_mut_obj_add_int(document, other, "top", top.other);
                yyjson_mut_obj_add_int(document, other, "bottom", bottom.other == INT64_MAX ? 0 : bottom.other);
                yyjson_mut_obj_add_int(document, other, "topat", topAt.other);
                yyjson_mut_obj_add_int(document, other, "bottomat", bottomAt.other);

                // reset data container variables
                timestamp += bindValue;
                next += bindValue;
                containers = 0;
                total = {0, 0, 0, 0, 0};
                top = {0, 0, 0, 0, 0};
                topAt = Timestamps{timestamp, timestamp, timestamp, timestamp};
                bottom = Stats{0, INT64_MAX, INT64_MAX, INT64_MAX, INT64_MAX};
                bottomAt = {timestamp, timestamp, timestamp, timestamp};
            }

            // accumulate & evaluate values
            total += record;
            if (record.ingress > top.ingress) {
                top.ingress = record.ingress;
                topAt.ingress = record.second;
            }
            if (record.egress > top.egress) {
                top.egress = record.egress;
                topAt.egress = record.second;
            }
            if (record.local > top.local) {
                top.local = record.local;
                topAt.local = record.second;
            }
            if (record.other > top.other) {
                top.other = record.other;
                topAt.other = record.second;
            }
            if (record.ingress < bottom.ingress) {
                bottom.ingress = record.ingress;
                bottomAt.ingress = record.second;
            }
            if (record.egress < bottom.egress) {
                bottom.egress = record.egress;
                bottomAt.egress = record.second;
            }
            if (record.local < bottom.local) {
                bottom.local = record.local;
                bottomAt.local = record.second;
            }
            if (record.other < bottom.other) {
                bottom.other = record.other;
                bottomAt.other = record.second;
            }

            ++containers; // container is always counted up, regardless of existence of the record itself
        }

        // write final object
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(rootArray, object);
        yyjson_mut_obj_add_int(document, object, "timestamp", timestamp);
        yyjson_mut_obj_add_int(document, object, "containers", containers);

        // ingress
        yyjson_mut_val *ingress = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, object, "ingress", ingress);
        yyjson_mut_obj_add_int(document, ingress, "total", total.ingress);
        yyjson_mut_obj_add_int(document, ingress, "top", top.ingress);
        yyjson_mut_obj_add_int(document, ingress, "bottom", bottom.ingress == INT64_MAX ? 0 : bottom.ingress);
        yyjson_mut_obj_add_int(document, ingress, "topat", topAt.ingress);
        yyjson_mut_obj_add_int(document, ingress, "bottomat", bottomAt.ingress);

        // egress
        yyjson_mut_val *egress = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, object, "egress", egress);
        yyjson_mut_obj_add_int(document, egress, "total", total.egress);
        yyjson_mut_obj_add_int(document, egress, "top", top.egress);
        yyjson_mut_obj_add_int(document, egress, "bottom", bottom.egress == INT64_MAX ? 0 : bottom.egress);
        yyjson_mut_obj_add_int(document, egress, "topat", topAt.egress);
        yyjson_mut_obj_add_int(document, egress, "bottomat", bottomAt.egress);

        // local
        yyjson_mut_val *local = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, object, "local", local);
        yyjson_mut_obj_add_int(document, local, "total", total.local);
        yyjson_mut_obj_add_int(document, local, "top", top.local);
        yyjson_mut_obj_add_int(document, local, "bottom", bottom.local == INT64_MAX ? 0 : bottom.local);
        yyjson_mut_obj_add_int(document, local, "topat", topAt.local);
        yyjson_mut_obj_add_int(document, local, "bottomat", bottomAt.local);

        // other
        yyjson_mut_val *other = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, object, "other", other);
        yyjson_mut_obj_add_int(document, other, "total", total.other);
        yyjson_mut_obj_add_int(document, other, "top", top.other);
        yyjson_mut_obj_add_int(document, other, "bottom", bottom.other == INT64_MAX ? 0 : bottom.other);
        yyjson_mut_obj_add_int(document, other, "topat", topAt.other);
        yyjson_mut_obj_add_int(document, other, "bottomat", bottomAt.other);

        // finalize
        Civet7::respond200(connection, document);
    } else if (bindValue == -1) {
        struct SummaryPack
        {
            TimeValuePair min{0, INT64_MAX}, max{};
            unsigned long long sum = 0;
        } records[5]; // totla, ingress, egress, local, other

        // read record
        std::function<void(const uint32_t, const int64_t, SummaryPack &)> setRecords = [](const uint32_t timestamp, const int64_t value, SummaryPack &target) {
            if (value > target.max.value)
                target.max = TimeValuePair{timestamp, value};
            if (value > 0 && value < target.min.value)
                target.min = TimeValuePair{timestamp, value};
            target.sum += value;
        };
        for (size_t i = 0; i < finalSize; ++i) {
            const auto &readBuffer = final[i];
            int64_t sum = readBuffer.ingress + readBuffer.egress + readBuffer.local + readBuffer.other;
            setRecords(readBuffer.second, sum, records[0]);
            setRecords(readBuffer.second, readBuffer.ingress, records[1]);
            setRecords(readBuffer.second, readBuffer.egress, records[2]);
            setRecords(readBuffer.second, readBuffer.local, records[3]);
            setRecords(readBuffer.second, readBuffer.other, records[4]);
        }

        // write JSON
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        std::function<void(yyjson_mut_val *, const SummaryPack &)> writeJson = [&](yyjson_mut_val *object, const SummaryPack &pack) {
            // minimum
            yyjson_mut_val *minimum = yyjson_mut_obj(document);
            yyjson_mut_obj_add_val(document, object, "minimum", minimum);
            yyjson_mut_obj_add_int(document, minimum, "timestamp", pack.min.second);
            yyjson_mut_obj_add_int(document, minimum, "value", pack.min.value);
            // maximum
            yyjson_mut_val *maximum = yyjson_mut_obj(document);
            yyjson_mut_obj_add_val(document, object, "maximum", maximum);
            yyjson_mut_obj_add_int(document, maximum, "timestamp", pack.max.second);
            yyjson_mut_obj_add_int(document, maximum, "value", pack.max.value);
            //sum
            yyjson_mut_obj_add_int(document, object, "sum", pack.sum);
        };
        yyjson_mut_val *rootObject = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootObject);
        // total
        writeJson(rootObject, records[0]);
        // ingress-egress-local-other
        yyjson_mut_val *object;
        object = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, rootObject, "ingress", object);
        writeJson(object, records[1]);
        object = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, rootObject, "egress", object);
        writeJson(object, records[2]);
        object = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, rootObject, "local", object);
        writeJson(object, records[3]);
        object = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, rootObject, "other", object);
        writeJson(object, records[4]);

        Civet7::respond200(connection, document);
    } else { // bindValue<0
        // prepare for reading file
        int ranksToInclude = bindValue * (-1);
        std::vector<TimeValuePair> ranks;
        ranks.reserve(ranksToInclude);

        // try to fill up records up to ranks to show
        for (size_t i = 0; i < finalSize; ++i) {
            const auto &readBuffer = final[i];
            ranks.push_back(TimeValuePair{readBuffer.second, static_cast<int64_t>(readBuffer.ingress + readBuffer.egress + readBuffer.local + readBuffer.other)});
        }
        std::sort(ranks.begin(), ranks.end(), [](const TimeValuePair &a, const TimeValuePair &b) { return a.value > b.value; });

        // write JSON
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);
        for (const auto &pair : ranks) {
            // write object
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(rootArray, object);
            yyjson_mut_obj_add_int(document, object, "timestamp", pair.second);
            yyjson_mut_obj_add_int(document, object, "value", pair.value);
        }

        Civet7::respond200(connection, document);
    }
}

void FeedRefinerBps2::dumpResults(mg_connection *connection)
{
    // send header
    std::string chunk("Timestamp\tIngress\tEgress\tLocal\tOther\n"s);
    chunk.reserve(110000000);
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // read records
    for (size_t i = 0; i < finalSize; ++i) {
        const auto &stats = final[i];
        // fill chunk buffer
        chunk.append(epochToIsoDate(stats.second) + '\t').append(std::to_string(stats.ingress) + '\t').append(std::to_string(stats.egress) + '\t').append(std::to_string(stats.local) + '\t').append(std::to_string(stats.other) + '\n');

        // flush chunk if its size is over 100MB
        if (chunk.size() > 100000000) {
            switch (mg_send_chunk(connection, chunk.data(), chunk.size())) {
            case 0:
                logger.log("Client closed socket. Cancelling operation."s);
                return;
            case -1:
                logger.log("Server encountered an error. Cancelling operation."s);
                return;
            default:
                chunk.clear();
            }
        }
    }

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

void FeedRefinerBps2::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    auto intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, std::vector<Stats>>(
        codices,
        [&](const SuperCodex::Loader *loader) -> std::vector<Stats> {
            int indexOffset = loader->secondStart;
            size_t resultSize = loader->secondEnd - indexOffset + 1;
            std::vector<Stats> result;
            result.reserve(resultSize);
            for (uint32_t i = 0; i < resultSize; ++i)
                result.push_back(Stats{i + indexOffset, 0, 0, 0, 0});

            for (const SuperCodex::Loader::BpsPpsItem *bps = loader->firstBpsPerSession(); bps; bps = loader->nextBpsPerSession(bps)) {
                // select target
                auto &thisSecond = result[bps->second - indexOffset];

                // count BPS
                const auto &session = loader->sessions.at(bps->sessionId);
                if (internalIps.contains(SuperCodex::sourceIp(*session))) { // source IP is in internal IPs -> ingress + egress or local
                    if (internalIps.contains(SuperCodex::destinationIp(*session))) // local
                        thisSecond.local += (bps->fromSmallToBig + bps->fromBigToSmall) * 8;
                    else { // ingress + egress
                        if (session->sourceIsSmall) { // small-to-big = source to destination = internal to external = egress
                            thisSecond.egress += bps->fromSmallToBig * 8;
                            thisSecond.ingress += bps->fromBigToSmall * 8;
                        } else {
                            thisSecond.ingress += bps->fromSmallToBig * 8;
                            thisSecond.egress += bps->fromBigToSmall * 8;
                        }
                    }
                } else if (internalIps.contains(SuperCodex::destinationIp(*session))) { // destination IP is in internal IPs -> ingress + egress only1
                    if (session->sourceIsSmall) { // small-to-big = source to destination = external to internal = ingress
                        thisSecond.ingress += bps->fromSmallToBig * 8;
                        thisSecond.egress += bps->fromBigToSmall * 8;
                    } else {
                        thisSecond.ingress += bps->fromBigToSmall * 8;
                        thisSecond.egress += bps->fromSmallToBig * 8;
                    }
                } else // other
                    thisSecond.other += (bps->fromSmallToBig + bps->fromBigToSmall) * 8;
            }

            return result;
        },
        affinityPartitioner);

    // merge data
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](std::vector<std::vector<Stats>> intermediatesFuture) {
            logger.log("Merging "s + std::to_string(intermediatesFuture.size()));
            for (const auto &intermediate : intermediatesFuture)
                for (const auto &pair : intermediate) {
                    auto offset = pair.second - conditions.from;
                    if (offset < 0 || offset >= finalSize)
                        break;
                    final[pair.second - conditions.from] += pair;
                }
        },
        std::move(intermediates));
}

void FeedRefinerBps2::finalize()
{
    // update target time frame
    secondStart = conditions.from;
    secondEnd = conditions.to;

    // declare finish
    logger.log("Result ready for BPS2: "s + std::to_string(secondStart) + " -> "s + std::to_string(secondEnd));
}
