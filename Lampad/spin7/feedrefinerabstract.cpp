#include "feedrefinerabstract.h"

#include "civet7.hpp"
#include "codexindex.h"
#include "subsystems.h"
#include "../featherlite.h"
#include <filesystem>
#include <sstream>
#include <fstream>
#include <yyjson.h>

using namespace std::string_literals;

// static variables
size_t FeedRefinerAbstract::maxPayloadSizeForRegex = 1024;
int64_t FeedRefinerAbstract::trafficThrottle = 100000000; // factory default: 100MB
std::string FeedRefinerAbstract::messyRoom;

FeedRefinerAbstract::FeedRefinerAbstract(const std::string &messyRoomName, const SuperCodex::Conditions &conditions)
    : conditions(conditions)
    , messyRoomName(messyRoomName)
    , userDefinedAppsCopy(SubSystems::copyUserDefinedApp())
    , logger(""s)
{
    // initialize messy room
    messyRoomPrefix = messyRoom + '/' + this->messyRoomName;
    if (std::filesystem::exists(messyRoomPrefix)) {
        logger.log("Remove existing messy room: "s + messyRoomPrefix);
        std::filesystem::remove_all(messyRoomPrefix);
    }
    std::filesystem::create_directory(messyRoomPrefix);

    // build tag store
    std::vector<std::string> targetTags;
    if (conditions.parameters.contains("tags"s)) {
        std::istringstream tokenizer(conditions.parameters.at("tags"s));
        for (std::string tag; std::getline(tokenizer, tag, ',');)
            targetTags.push_back(tag);
    }
}

FeedRefinerAbstract::~FeedRefinerAbstract()
{
    try {
        // clean up messy room
        std::filesystem::remove_all(messyRoomPrefix);
    } catch (std::exception &e) {
        logger.log("Exception occurred on destruction: "s + e.what());
    } catch (...) {
        logger.log("Exception occurred(reason unknown)"s);
    }
}

std::vector<std::string> FeedRefinerAbstract::codicesToLoad(SuperCodex::Conditions &conditions)
{
    // if the duration is too short, don't apply SuperCache
    if (conditions.to - conditions.from < 120)
        logger.log("Lookback window is too short to apply SuperCache.");
    else {
        // determine which duration can be covered by SuperCache
        if (!superCachePath.empty() && std::filesystem::exists(superCachePath) && std::filesystem::file_size(superCachePath) > 0 && cachedChapter != 0) { // check whether SuperCache file is applicable
            FeatherLite feather(superCachePath, SQLITE_OPEN_READONLY);
            feather.prepare("SELECT MIN(timestamp), MAX(timestamp) FROM rows WHERE timestamp>=? AND timestamp<=? AND chapter=?;"s);
            feather.bindInt(1, conditions.from);
            feather.bindInt(2, conditions.to - 60);
            feather.bindInt(3, cachedChapter);
            if (feather.next() == SQLITE_ROW) {
                conditions.cacheFrom = feather.getInt(0);
                conditions.cacheTo = feather.getInt(1) + 59;
                this->conditions.cacheFrom = conditions.cacheFrom;
                this->conditions.cacheTo = conditions.cacheTo;
                logger.log("Applying SuperCache from "s + std::to_string(conditions.cacheFrom) + " -> "s + std::to_string(conditions.cacheTo));
            } else
                logger.oops("Failed to apply SuperCache. Details: "s + feather.lastError());
        } else
            logger.log("Skip setting period for caching: "s + std::to_string(superCachePath.empty()) + ' ' + std::to_string(cachedChapter));
    }

    auto result = DataFeed::codexIndex->codices(conditions);
    conditions.codicesToGo = result;
    return result;
}

void FeedRefinerAbstract::consumeCodices(std::vector<SuperCodex::Loader *> &codices, const bool isFinalLap)
{
    if (!codices.empty()) {
        logger.log("Feed codices("s + std::to_string(codices.size()) + "): " + codices.front()->fileName + " -> "s + codices.back()->fileName);
        processCodices(codices);
    }

    if (isFinalLap) {
        // finalize refinery job. secondStart and secondEnd must be set before end of finalization
        logger.log("Finalize"s);
        if (mergeFuture.joinable())
            mergeFuture.join();
        updateTimestamp();
        finalize();

        // delete sessions
        if (sessions) {
            delete sessions;
            sessions = nullptr;
        }
        sessions2.clear();

        // flag that job is complete
        jobIsDone = true;
    }
}

void FeedRefinerAbstract::resultTimeFrame(uint32_t &from, uint32_t &to)
{
    if (!jobIsDone || secondStart == INT32_MAX) { // job is ongoing or secondStart is not set(=no data)
        from = -1;
        to = -1;
    } else {
        from = secondStart;
        to = secondEnd;
    }
}

void FeedRefinerAbstract::put(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // default: return HTTP 501 Not Implemented
    mg_send_http_error(connection, 501, "HTTP PUT is not supported");
}

void FeedRefinerAbstract::updateTimestampAndMergeSessions(const std::vector<SuperCodex::Session> &toMerge)
{
    if (!toMerge.empty())
        for (const auto &session : toMerge)
            updateTimestampAndMergeIndividualSession(session);
}

void FeedRefinerAbstract::updateTimestampAndMergeIndividualSession(const SuperCodex::Session &sessionToMerge)
{
    // update timestamp
    if (secondStart > sessionToMerge.first.second)
        secondStart = sessionToMerge.first.second;
    if (secondEnd < sessionToMerge.last.second)
        secondEnd = sessionToMerge.last.second;

    // merge sessions as needed
    if (sessions->count(sessionToMerge.id)) { // existing session: update
        // check authenticity of direction(client-server)
        SuperCodex::Session &mergeBase = (*sessions)[sessionToMerge.id];
        if (sessionToMerge.status & SuperCodex::Session::HASTCPSYN) { // authentic: overwrite session information
            memcpy(mergeBase.ips, sessionToMerge.ips, 32);
            mergeBase.sourcePort = sessionToMerge.sourcePort;
            mergeBase.destinationPort = sessionToMerge.destinationPort;
        }

        // update timestamp, status, and detected L7
        mergeBase.last = sessionToMerge.last;
        mergeBase.status = static_cast<SuperCodex::Session::Status>(mergeBase.status | sessionToMerge.status);
        if (sessionToMerge.detectedL7 != SuperCodex::Session::L7Protocol::NOL7DETECTED)
            mergeBase.detectedL7 = sessionToMerge.detectedL7;
    } else
        (*sessions)[sessionToMerge.id] = sessionToMerge; // new session
}

void FeedRefinerAbstract::mergeSession(const SuperCodex::Session *session)
{
    if (!session)
        return; // just in case

    tbb::concurrent_hash_map<uint64_t, SuperCodex::Session>::accessor a;
    if (sessions2.insert(a, session->id))
        a->second = *session; // introduce new session to the hashmap
    else { // merge with previous session data
        // update session timestamp
        bool fromPast = false;
        if (session->first.second < a->second.first.second || (session->first.second == a->second.first.second && session->first.nanosecond < a->second.first.nanosecond)) {
            a->second.first = session->first;
            fromPast = true;
        }
        if (session->last.second > a->second.last.second || (session->last.second == a->second.last.second && session->last.nanosecond > a->second.last.nanosecond))
            a->second.last = session->last;

        // overwrite session direction if TCP session contains SYN or UDP session from the past
        if ((session->status & SuperCodex::Session::HASTCPSYN) || (session->payloadProtocol == 0x11 && fromPast)) {
            memcpy(a->second.ips, session->ips, 32);
            a->second.sourcePort = session->sourcePort;
            a->second.destinationPort = session->destinationPort;
        }

        // update status and detected L7
        a->second.status = static_cast<SuperCodex::Session::Status>(a->second.status | session->status);
        if (session->detectedL7 != SuperCodex::Session::L7Protocol::NOL7DETECTED)
            a->second.detectedL7 = session->detectedL7;
    }
}

void FeedRefinerAbstract::updateTimestamp()
{
    for (const auto &pair : sessions2) {
        if (pair.second.first.second < secondStart)
            secondStart = pair.second.first.second;
        if (pair.second.last.second > secondEnd)
            secondEnd = pair.second.last.second;
    }
}

void FeedRefinerAbstract::summarize(mg_connection *connection, const std::string &fileName, const int32_t bindValue)
{
    // exception handling: file not found or file is empty
    if (!std::filesystem::exists(fileName)) {
        mg_send_http_error(connection, 400, ("File not found: "s + fileName).data());
        return;
    }
    size_t pairCount = std::filesystem::file_size(fileName);
    if (pairCount == 0) {
        mg_send_http_error(connection, 204, "\r\n\r\n");
        return;
    } else
        pairCount = pairCount / timeValuePairSize - 1;

    // prepare for reading file
    TimeValuePair record;
    std::ifstream file(fileName, std::ios::binary);
    uint32_t timestamp = conditions.from, next = timestamp + bindValue, topAt = timestamp, bottomAt = timestamp;
    int64_t top = 0, bottom = INT64_MAX, total = 0, containers = 0;

    // write JSON
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootArray = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, rootArray);

    // determine first record to read
    size_t recordCounter = 0;
    file.read((char *) &record, timeValuePairSize);
    while (!file.eof()) {
        if (record.second >= next) {
            // write object
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(rootArray, object);
            yyjson_mut_obj_add_int(document, object, "timestamp", timestamp + bindValue * recordCounter / pairCount);
            yyjson_mut_obj_add_int(document, object, "containers", containers);
            yyjson_mut_obj_add_int(document, object, "total", total);
            yyjson_mut_obj_add_int(document, object, "top", top);
            yyjson_mut_obj_add_int(document, object, "topat", topAt);
            yyjson_mut_obj_add_int(document, object, "bottom", bottom == INT64_MAX ? 0 : bottom);
            yyjson_mut_obj_add_int(document, object, "bottomat", bottomAt);
            ++recordCounter;

            // reset data container variables
            timestamp += bindValue;
            next += bindValue;
            top = 0;
            topAt = timestamp;
            bottom = INT64_MAX;
            bottomAt = timestamp;
            total = 0;
            containers = 0;
        }

        // accumulate & evaluate values
        total += record.value;
        if (record.value > top) {
            top = record.value;
            topAt = record.second;
        }
        if (record.value && record.value < bottom) {
            bottom = record.value;
            bottomAt = record.second;
        }

        // read next record
        if (!file.eof())
            file.read((char *) &record, timeValuePairSize);
        ++containers; // container is always counted up, regardless of existence of the record itself
    }

    // write final object
    yyjson_mut_val *object = yyjson_mut_obj(document);
    yyjson_mut_arr_append(rootArray, object);
    yyjson_mut_obj_add_int(document, object, "timestamp", timestamp + bindValue * recordCounter / pairCount);
    yyjson_mut_obj_add_int(document, object, "containers", containers);
    yyjson_mut_obj_add_int(document, object, "total", total);
    yyjson_mut_obj_add_int(document, object, "top", top);
    yyjson_mut_obj_add_int(document, object, "topat", topAt);
    yyjson_mut_obj_add_int(document, object, "bottom", bottom == INT64_MAX ? 0 : bottom);
    yyjson_mut_obj_add_int(document, object, "bottomat", bottomAt);

    // finalize
    file.close();
    if (connection)
        Civet7::respond200(connection, document);
    else
        lastInterativeResult = document;
}

void FeedRefinerAbstract::rankingPerSecond(mg_connection *connection, const std::string &fileName, const int32_t ranksToInclude)
{
    // prepare for reading file
    TimeValuePair record;
    std::ifstream file(fileName, std::ios::binary);
    std::vector<TimeValuePair> ranks;
    ranks.reserve(ranksToInclude);

    // try to fill up records up to ranks to show
    for (int i = 0; i < ranksToInclude; ++i) {
        file.read((char *) &record, timeValuePairSize);
        if (file.eof())
            break;
        else
            ranks.push_back(record);
    }
    std::sort(ranks.begin(), ranks.end(), [](const TimeValuePair &a, const TimeValuePair &b) { return a.value > b.value; });
    if (file.eof())
        goto writeJson; // if file hits EOF, write JSON immediately

    // read record
    file.read((char *) &record, timeValuePairSize);
    while (!file.eof()) {
        if (record.value > ranks.back().value) {
            ranks.back() = record;
            std::sort(ranks.begin(), ranks.end(), [](const TimeValuePair &a, const TimeValuePair &b) { return a.value > b.value; });
        }

        // read next record
        file.read((char *) &record, timeValuePairSize);
    }
    file.close();

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

void FeedRefinerAbstract::minAndMax(mg_connection *connection, const std::string &fileName)
{
    TimeValuePair min, max, record;
    min.value = INT64_MAX;
    std::ifstream file(fileName, std::ios::binary);
    // read record
    file.read((char *) &record, timeValuePairSize);
    while (!file.eof()) {
        if (record.value > max.value)
            max = record;
        if (record.value > 0 && record.value < min.value)
            min = record;

        // read next record
        file.read((char *) &record, timeValuePairSize);
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
}

void FeedRefinerAbstract::describeEdge(SubSystems::FqdnGetter &getter, yyjson_mut_doc *document, yyjson_mut_val *object, const std::string &ip, const uint16_t port)
{
    // write IP details
    std::string ipInHex = SuperCodex::stringToHex(ip), temp;
    yyjson_mut_obj_add_strncpy(document, object, "ip", ipInHex.data(), ipInHex.size());

    // write tags
    yyjson_mut_val *tagsArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, object, "tags", tagsArray);
    if (conditions.ipToTags.contains(ip)) {
        const std::vector<std::string> &tags = conditions.ipToTags[ip];
        for (const auto &tag : tags)
            yyjson_mut_arr_add_strncpy(document, tagsArray, tag.data(), tag.size());
    }

    // write domain names and user defined applications
    yyjson_mut_val *appsArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, object, "apps", appsArray);
    const std::string userDefinedAppName(userDefinedAppsCopy.getAlias(ip, port));
    if (!userDefinedAppName.empty()) // add user defined app first
        yyjson_mut_arr_add_strncpy(document, appsArray, userDefinedAppName.data(), userDefinedAppName.size());
    for (const auto &app : getter.get(ip)) // add FQDNs
        yyjson_mut_arr_add_strncpy(document, appsArray, app.data(), app.size());

    // write port information if it's nonzero
    if (port)
        yyjson_mut_obj_add_int(document, object, "port", port);
}

void FeedRefinerAbstract::describeEdge(SubSystems::FqdnGetter &getter, std::string &result, const std::string &ip, const uint16_t port)
{
    // write IP in human readable format
    result.append(SuperCodex::humanReadableIp(ip)).push_back('\t');

    // write tags
    if (conditions.ipToTags.contains(ip)) {
        const std::vector<std::string> &tags = conditions.ipToTags[ip];
        for (const auto &tag : tags)
            result.append(tag).push_back('|');
    }
    result.push_back('\t');

    // write domain names
    const std::string userDefinedAppName(userDefinedAppsCopy.getAlias(ip, port));
    if (!userDefinedAppName.empty()) // add user defined app first
        result.append(userDefinedAppName).push_back('|');
    for (const auto &app : getter.get(ip)) // add FQDNs
        result.append(app).push_back('|');
    result.push_back('\t');

    // write port information if it's nonzero
    if (port)
        result.append(std::to_string(port));
    result.push_back('\t');
}

std::string FeedRefinerAbstract::epochToIsoDate(const time_t epochTime, const char *format)
{
    struct tm nowInTm;
#ifdef __linux__
    localtime_r(&epochTime, &nowInTm); // Linux
#else
    localtime_s(&nowInTm, &epochTime); // Windows
#endif
    std::stringstream outStream;
    outStream << std::put_time(&nowInTm, format);
    return outStream.str();
}

std::string FeedRefinerAbstract::remarksValue(const std::string_view &remarks, const std::string &key)
{
    std::string keyWithEqualSign = key + '=';
    // find key and move cursor to start of the value
    size_t cursor = 0;
    if (remarks.substr(0, keyWithEqualSign.size()) != keyWithEqualSign) { // exception: the key resides at the first line
        cursor = remarks.find(keyWithEqualSign, keyWithEqualSign.size());
        while (cursor != std::string::npos) {
            if (remarks[cursor - 1] == '\n')
                break;
            else
                cursor = remarks.find(keyWithEqualSign, cursor + keyWithEqualSign.size());
        }
    }
    if (cursor == std::string::npos)
        return std::string();
    else
        cursor += keyWithEqualSign.size(); // move cursor to start of the value

    // find end of the value
    size_t cursorEnd = remarks.find('\n', cursor);
    if (cursorEnd == std::string::npos)
        cursorEnd = remarks.size();
    return std::string(remarks.data() + cursor, cursorEnd - cursor);
}

std::string FeedRefinerAbstract::remarksValueHttpHeader(const std::string_view &remarks, const std::string &key)
{
    // find key and move cursor to start of the value
    size_t cursor = remarks.find('\n' + key + ':');
    if (cursor == std::string::npos)
        return std::string();
    else
        cursor += key.size() + 2; // key+colon
    while (remarks[cursor] == ' ')
        ++cursor;

    // find end of the value
    size_t cursorEnd = remarks.find('\n', cursor);
    if (cursorEnd == std::string::npos)
        cursorEnd = remarks.size() - 1;
    while (remarks[cursorEnd] == '\r' || remarks[cursorEnd] == '\n')
        --cursorEnd;
    return std::string(remarks.data() + cursor, cursorEnd - cursor + 1);
}
