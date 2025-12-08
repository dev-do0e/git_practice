#include "datafeed.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <math.h>
#include <mutex>
#include <regex>
#include <sstream>
#include <utility>

#include <yyjson.h>
#include <tbb/parallel_for_each.h>
#include <tbb/parallel_for.h>

#include "../supercodex.h"
#include "../featherlite.h"
#include "civet7.hpp"
#include "codexindex.h"
#include "subsystems.h"
#include "event7.h"
#include "tcpservicemanager.h"

// static variables
ankerl::unordered_dense::map<std::string, DataFeed *> DataFeed::feeds;
CodexIndex *DataFeed::codexIndex;

DataFeed::DataFeed(const std::string &feedName)
    : feedPath(codexIndex->feedRoot + feedName)
    , feedName(feedName)
    , logger("DataFeed/"s + feedName)
    , tagsPath(feedPath + "/tags.json"s)
{
    logger.log("Initialize feed from "s + feedPath);

    // load tags
    std::string tagsRaw(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(tagsPath, std::ifstream::binary).rdbuf()).str());
    if (!tagsRaw.empty())
        tags = nlohmann::json::parse(tagsRaw);

    // initialize DNS cache
    initializeDnsCache();
}

DataFeed::~DataFeed() {}

std::vector<DataFeed::Description> DataFeed::describeFeeds()
{
    std::vector<Description> result;
    result.reserve(feeds.size());
    for (const auto &pair : feeds) {
        Description description;
        description.name = pair.first;
        codexIndex->availableTimeframe(pair.first, description.from, description.to);
        result.push_back(std::move(description));
    }
    return result;
}

std::string DataFeed::enumerateFeeds()
{
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);

    // prepare for enumeration
    std::vector<Description> descriptions = describeFeeds();
    std::sort(descriptions.begin(), descriptions.end(), [](const Description &a, const Description &b) -> bool { return a.name < b.name; });

    // build JSON
    yyjson_mut_val *rootArray = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, rootArray);
    for (const auto &description : descriptions) {
        if (description.from == 0)
            continue; // skip to next feed if there's nothing in the current feed
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(rootArray, object);
        yyjson_mut_obj_add_strncpy(document, object, "name", description.name.data(), description.name.size());
        yyjson_mut_obj_add_int(document, object, "from", description.from);
        yyjson_mut_obj_add_int(document, object, "to", description.to);
    }

    // return stringified result
    size_t size;
    char *resultRaw = yyjson_mut_write(document, YYJSON_WRITE_NOFLAG, &size);
    std::string result(resultRaw, size);
    free(resultRaw);
    yyjson_mut_doc_free(document);
    return result;
}

void DataFeed::getTag(mg_connection *connection)
{
    tagsLock.lock_shared();
    const std::string buffer = tags.dump();
    tagsLock.unlock_shared();

    if (buffer == "null"s)
        mg_send_http_error(connection, 204, "\r\n\r\n");
    else
        Civet7::respond200(connection, buffer.data(), buffer.size());
}

void DataFeed::putTag(mg_connection *connection, const std::string &path, ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // simple sanity check
    if (path.empty() || path.size() == 1) {
        mg_send_http_error(connection, 400, "Empty tag name");
        return;
    }
    std::string tagName = path.substr(1);

    std::unique_lock lockGuard(tagsLock);
    // create a tag if the name is new
    if (!tags.contains(tagName)) {
        tags[tagName] = nlohmann::json::object();
        tags[tagName]["ips"] = nlohmann::json::array();
        tags[tagName]["triggers"] = nlohmann::json::object();
    }

    // check tag name change
    if (parameters.contains("newname"s)) {
        const std::string &newName = parameters.at("newname"s);
        if (!newName.empty()) { // newname exists but can be empty, depending on GUI implementation
            tags[newName] = tags[tagName];
            tags.erase(tagName);
            tagName = newName;
        }
    }

    // replace current IP list with new list
    if (parameters.contains("ip"s)) {
        ankerl::unordered_dense::set<std::string> ips;

        // load additional IPs to deduplicator
        std::pair<size_t, size_t> validatedIps;
        SuperCodex::IpFilter ipValidator;
        std::istringstream tokenizer(parameters.at("ip"s));
        for (std::string ip; std::getline(tokenizer, ip, ',');) {
            // sanity check
            if (!SuperCodex::isValidHexadecimal(ip)) {
                logger.oops("Not valid hexadecimal number string: "s + ip);
                mg_send_http_error(connection, 400, "IP should be represented in hexadecimal number only: %s is not valid hexadecimal number.", ip.data());
                return;
            }

            // make the IP hexadecimal to lowercase
            std::transform(ip.begin(), ip.end(), ip.begin(), [](char c) -> char { return std::tolower(c); });

            // validate address

            if (ip.size() == 8 || ip.size() == 32) // single IP
                ips.insert(ip); // single IP
            else {
                ipValidator.registerNetwork(ip);
                const auto registered = ipValidator.registeredAddresses();
                if (validatedIps != registered) { // IP is accepted
                    validatedIps = registered;
                    ips.insert(ip);
                }
            }
        }

        // update IP list
        tags[tagName]["ips"].clear();
        for (const auto &ip : ips)
            tags[tagName]["ips"].push_back(ip);
    }

    // add event trigger
    if (parameters.contains("trigger_message"s)) {
        // check existence of required parameters
        if (!parameters.contains("trigger_severity"s) || !parameters.contains("trigger_datasource"s) || !parameters.contains("trigger_type"s) || !parameters.contains("trigger_lookbackwindowsize"s) || !parameters.contains("trigger_threshold"s)) {
            mg_send_http_error(connection, 400, "one or more required parameters(trigger_message, trigger_severity, trigger_datasource, trigger_type, trigger_lookbackwindowsize, trigger_threshold) are missing.");
            return;
        }

        // check general values
        const std::string &message = parameters.at("trigger_message"s), &severity = parameters.at("trigger_severity"s), &dataSource = parameters.at("trigger_datasource"s), &type = parameters.at("trigger_type"s);
        if (severity != "info"s && severity != "warning" && severity != "critical") {
            mg_send_http_error(connection, 400, "trigger_severity must be one of the following: info, warning, or critical.");
            return;
        }
        if (dataSource != "bps"s && dataSource != "pps"s && dataSource != "rtt"s && dataSource != "tcptimeouts"s && dataSource != "tcprequests"s && dataSource != "tcprsts"s && dataSource != "tcpzerowindows"s && dataSource != "tcpportsreused"s && dataSource != "tcpoutoforders"s && dataSource != "tcpdupacks"s && dataSource != "tcpretransmissions"s && dataSource != "tcpspuriousretransmissions"s && dataSource != "udphits"s && dataSource != "httpsessionswitherrors"s && dataSource != "ftpsessionswitherrors"s && dataSource != "smtpsessionswitherrors"s && dataSource != "imapsessionswitherrors"s && dataSource != "pop3sessionswitherrors") {
            mg_send_http_error(connection, 400, "trigger_datasource must be one of the following: bps, pps, rtt, tcptimeouts, tcprequests, tcprsts, tcpzerowindows, tcpportsreused, tcpoutoforders, tcpdupacks, tcpretransmissions, tcpspuriousretransmissions, udphits, httpsessionswitherrors, ftpsessionswitherrors, smtpsessionswitherrors, imapsessionswitherrors, pop3sessionswitherrors.");
            return;
        }
        if (type != "overthreshold"s && type != "underthreshold"s && type != "delta"s) {
            mg_send_http_error(connection, 400, "trigger_type must be one of the following: overthreshold, underthreshold, delta.");
            return;
        }

        int64_t lookBackWindowSize, threshold, delta = 0;
        try {
            lookBackWindowSize = std::stoll(parameters.at("trigger_lookbackwindowsize"s));
            if (lookBackWindowSize <= 0)
                lookBackWindowSize = 1;
            threshold = std::stoll(parameters.at("trigger_threshold"s));
            if (threshold <= 0)
                throw "Threshold underflow";
        } catch (...) {
            mg_send_http_error(connection, 400, "invalid parameter: trigger_lookbackwindowsize or trigger_threshold.");
            return;
        }

        // check delta-specific values
        if (parameters.at("trigger_type"s) == "delta"s) {
            if (!parameters.contains("trigger_delta"s)) {
                mg_send_http_error(connection, 400, "required parameter(trigger_delta) on type delta is missing.");
                return;
            }
            try {
                delta = std::stoll(parameters.at("trigger_delta"s));
                if (delta <= 0)
                    throw "Delta underflow";
            } catch (...) {
                mg_send_http_error(connection, 400, "invalid parameter: trigger_delta.");
                return;
            }
        }

        // remove previous trigger
        if (tags[tagName]["triggers"].contains(message))
            tags[tagName]["triggers"].erase(message);

        // add trigger
        tags[tagName]["triggers"][message]["severity"s] = severity;
        tags[tagName]["triggers"][message]["datasource"s] = dataSource;
        tags[tagName]["triggers"][message]["type"s] = type;
        tags[tagName]["triggers"][message]["lookbackwindowsize"s] = lookBackWindowSize;
        tags[tagName]["triggers"][message]["threshold"s] = threshold;
        tags[tagName]["triggers"][message]["delta"s] = delta;
    }

    // save changes to file and unlock mutex
    saveTags();

    // prepare for return code
    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void DataFeed::deleteTag(mg_connection *connection, const std::string &path)
{
    if (path.empty()) {
        mg_send_http_error(connection, 400, "Tag name must be provided.");
        return;
    }
    // divide tag namd and IP
    std::string tag, detail, path1 = path;
    path1.erase(0, 1); // remove first slash
    auto slash = path1.find('/');
    if (slash != std::string::npos) {
        tag = path1.substr(0, slash);
        detail = path1.substr(slash + 1);
    } else
        tag = path1;

    // check existence of the tag name
    if (!tags.contains(tag)) {
        mg_send_http_error(connection, 400, "Unknown tag name: %s. Check the name and try again.", tag.data());
        return;
    }

    // remove item per condition
    std::unique_lock locker(tagsLock);
    if (detail.empty()) { // remove a tag(=a group in tag details) entirely
        tags.erase(tag);
    } else if (detail.at(0) == '_') { // remove a trigger
        try {
            detail.erase(0, 1);
            if (tags[tag]["triggers"s].contains(detail))
                tags[tag]["triggers"s].erase(detail);
        } catch (...) {
            // ignore any exception
        }
    } else { // remove an IP in a tag
        // check validity of received IP
        if (detail.size() != 8 && detail.size() != 10 && detail.size() != 32 && detail.size() != 34) {
            mg_send_http_error(connection, 400, "Provided IP is not valid.");
            return;
        }

        // update IPs to tag details
        for (auto i = tags[tag]["ips"s].cbegin(), iEnd = tags[tag]["ips"s].cend(); i != iEnd; i++) {
            if (detail == i->get<std::string>()) {
                tags[tag]["ips"s].erase(i);
                break;
            }
        }
    }

    // save changes to file and unlock mutex
    saveTags();

    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void DataFeed::getIp(mg_connection *connection, const std::string &ipInHex)
{
    // parameter sanity check
    if (ipInHex.size() != 8 && ipInHex.size() != 10 && ipInHex.size() != 32 && ipInHex.size() != 34) {
        mg_send_http_error(connection, 400, "IP is invalid(either IP is not in heaxdecimal format or the size doesn't fit to any IP version(neither 4 nor 6).");
        return;
    }

    // build list of tags the IP belongs to
    nlohmann::json result = nlohmann::json::array();
    tagsLock.lock_shared();
    for (auto tag = tags.cbegin(), tagEnd = tags.cend(); tag != tagEnd; ++tag)
        if (tag.value().contains("ips"s)) {
            for (auto ip = tag.value()["ips"].cbegin(), ipEnd = tag.value()["ips"].cend(); ip != ipEnd; ++ip)
                if (ipInHex == ip->get<std::string>()) {
                    result.push_back(tag.key());
                    break;
                }
        }
    tagsLock.unlock_shared();
    std::string dump = result.dump();
    Civet7::respond200(connection, dump.data(), dump.size());
}

void DataFeed::saveTags()
{
    std::string dump = tags.dump();
    std::ofstream saveFile(tagsPath, std::ios::trunc);
    saveFile.write(dump.data(), dump.size());
}

void DataFeed::getPcap(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check required parameters
    if (!parameters.contains("from"s) || !parameters.contains("to"s)) {
        mg_send_http_error(connection, 400, "The request doesn't contain at least one of necessary parameters: 'from', 'to'");
        return;
    }

    // build filter conditions
    SuperCodex::Conditions filter;
    std::string filterCreationError = buildSuperCodexConditions(parameters, filter);
    if (!filterCreationError.empty()) {
        mg_send_http_error(connection, 400, filterCreationError.data());
        return;
    }
    filter.dataFeed = feedName;

    // double check the request
    logger.log("Building from "s + std::to_string(filter.from) + " to "s + std::to_string(filter.to));

    // check existence of index
    int32_t index = -1;
    if (parameters.contains("index"s))
        try {
            index = stoi(parameters.at("index"s));
        } catch (...) {
            // silently skip any exceptions
        }

    // initialize block size for flushing
    size_t blockSize = 115343360; // 110MB

    // is filename required?
    std::string additionalHeader = "application/octet-stream"s;
    if (parameters.contains("filename"))
        additionalHeader.append("\r\nContent-Disposition: attachment; filename=\""s + parameters.at("filename"s) + '"');

    // prepare for chunked mode
    Civet7::respond200(connection, nullptr, -1, additionalHeader);

    // send PCAP global header
    std::string pcapGlobalHeader("\x4d\x3c\xb2\xa1" // magic number: nanosecond, swapped
                                 "\x02\x00\x04\x00" // version number(2.4)
                                 "\x00\x00\x00\x00" // thiszone
                                 "\x00\x00\x00\x00" // sigfigs
                                 "\xff\xff\x00\x00" // snaplen
                                 "\x01\x00\x00\x00", // network
                                 24),
        pcapRecords;
    pcapRecords.reserve(blockSize);
    mg_send_chunk(connection, pcapGlobalHeader.data(), pcapGlobalHeader.size());

    // read codices
    auto codices = codexIndex->codices(filter);
    while (!codices.empty()) {
        std::function<std::vector<SuperCodex::Packet>(const std::string &)> gatherParts = [&](const std::string &codexFile) -> std::vector<SuperCodex::Packet> {
            // load codex
            SuperCodex::Loader codex(codexFile, static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::PACKETS), filter);

            // build packet list
            std::vector<SuperCodex::Packet> packets;
            for (const SuperCodex::Packet *packet = codex.firstPacket(); packet; packet = codex.nextPacket(packet))
                if (index == -1 || index == packet->index)
                    packets.push_back(*packet);

            return packets;
        };

        // determine codex to process in parallel
        int codicesToGoSize = std::min(static_cast<size_t>(std::thread::hardware_concurrency() * 4), codices.size());
        auto i = codices.begin(), iEnd = codices.begin();
        std::advance(iEnd, codicesToGoSize);
        std::vector<std::string> codicesToGo(i, iEnd);
        codices.erase(i, iEnd);
        auto streams = SuperCodex::parallel_convert<>(codicesToGo, gatherParts);
        for (int i = 0, iEnd = streams.size(); i < iEnd; i++) {
            // check whether packet list is empty
            if (streams[i].empty()) {
                logger.log("Skipping "s + codicesToGo[i] + " (no data)."s);
                continue;
            } else
                logger.log("Starting "s + codicesToGo[i] + ' ' + std::to_string(streams[i].size()));

            // initialize a few variables for repeated use
            struct
            {
                uint32_t second, nanosecond, savedLength, actualLength;
            } pcapRecordHeader;
            const char *payloadData;
            std::function<void(const SuperCodex::Packet &)> writePcapRecord;

            // locate payload
            std::string payloadPath(codicesToGo[i]), payload;
            payloadPath.erase(payloadPath.size() - 11); // remove ".supercodex"
            if (std::filesystem::exists(payloadPath + ".pcap"s)) {
                payload = std::string(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(payloadPath + ".pcap"s, std::ifstream::binary).rdbuf()).str());
                payload.erase(0, 24); // remove PCAP global header
                writePcapRecord = [&](const SuperCodex::Packet &packet) {
                    // determine saved packet size
                    pcapRecordHeader.savedLength = packet.savedLength;

                    // build stream
                    pcapRecords
                        .append((const char *) &pcapRecordHeader, 16) // PCAP record header
                        .append(payloadData + packet.fileOffset, packet.savedLength); // actual packet payload
                };
            } else if (std::filesystem::exists(payloadPath + ".appendix"s)) {
                payload = std::string(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(payloadPath + ".appendix"s, std::ifstream::binary).rdbuf()).str());
                writePcapRecord = [&](const SuperCodex::Packet &packet) {
                    // determine saved packet size
                    pcapRecordHeader.savedLength = packet.savedLength;

                    // build stream
                    pcapRecords
                        .append((const char *) &pcapRecordHeader, 16) // PCAP record header
                        .append(payloadData + packet.fileOffset, packet.savedLength); // actual packet payload
                };
            } else if (std::filesystem::exists(payloadPath + ".slice64"s)) {
                payload = std::string(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(payloadPath + ".slice64"s, std::ifstream::binary).rdbuf()).str());
                writePcapRecord = [&](const SuperCodex::Packet &packet) {
                    // determine saved packet size
                    pcapRecordHeader.savedLength = std::min(packet.savedLength, static_cast<uint32_t>(64));
                    size_t offset = packet.index * 64;

                    // build stream
                    pcapRecords
                        .append((const char *) &pcapRecordHeader, 16) // PCAP record header
                        .append(payloadData + offset, pcapRecordHeader.savedLength);
                };
            } else if (std::filesystem::exists(payloadPath + ".slice128"s)) {
                payload = std::string(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(payloadPath + ".slice128"s, std::ifstream::binary).rdbuf()).str());
                writePcapRecord = [&](const SuperCodex::Packet &packet) {
                    // determine saved packet size
                    pcapRecordHeader.savedLength = std::min(packet.savedLength, static_cast<uint32_t>(128));
                    size_t offset = packet.index * 128;

                    // build stream
                    pcapRecords
                        .append((const char *) &pcapRecordHeader, 16) // PCAP record header
                        .append(payloadData + offset, pcapRecordHeader.savedLength);
                };
            } else if (std::filesystem::exists(payloadPath + ".slice192"s)) {
                payload = std::string(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(payloadPath + ".slice192"s, std::ifstream::binary).rdbuf()).str());
                writePcapRecord = [&](const SuperCodex::Packet &packet) {
                    // determine saved packet size
                    pcapRecordHeader.savedLength = std::min(packet.savedLength, static_cast<uint32_t>(192));
                    size_t offset = packet.index * 192;

                    // build stream
                    pcapRecords
                        .append((const char *) &pcapRecordHeader, 16) // PCAP record header
                        .append(payloadData + offset, pcapRecordHeader.savedLength);
                };
            } else {
                logger.log("Get PCAP: payload file not found - "s + payloadPath);
                continue;
            }
            payloadData = payload.data();

            // build download buffer
            for (const SuperCodex::Packet &packet : streams[i]) {
                // build PCAP record header
                pcapRecordHeader.second = packet.second;
                pcapRecordHeader.nanosecond = packet.nanosecond;
                pcapRecordHeader.actualLength = packet.savedLength;
                writePcapRecord(packet);

                // send a chunk if it's bigger than 100MB
                if (pcapRecords.size() > blockSize) {
                    logger.log("Chunk size: "s + std::to_string(pcapRecords.size()));
                    auto returnValue = mg_send_chunk(connection, pcapRecords.data(), pcapRecords.size());
                    pcapRecords.clear();
                    if (returnValue == -1) { // actually, this is -1(=error on transferring) when expressed as signed integer
                        logger.log("Detected a socket error on flushing. Cancelling transfer."s);
                    } else
                        logger.log("Flushing chunk. Processed "s + std::to_string(returnValue) + " bytes");
                }
            }
        }
    }

    // send last stream and closing chunk(=size 0)
    logger.log("Flushing final chunk. Sent: "s + std::to_string(mg_send_chunk(connection, pcapRecords.data(), pcapRecords.size())));
    logger.log("Closing chunked transfer. Return(expects 5): "s + std::to_string(mg_send_chunk(connection, "", 0)));
}

void DataFeed::getBpms(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check required parameters
    if (!parameters.contains("from"s)) {
        mg_send_http_error(connection, 400, "The request doesn't contain necessary parameter: 'from'");
        return;
    }

    // build filter conditions
    SuperCodex::Conditions filter;
    std::string filterCreationError = buildSuperCodexConditions(parameters, filter);
    if (!filterCreationError.empty()) {
        mg_send_http_error(connection, 400, filterCreationError.data());
        return;
    }
    filter.dataFeed = feedName;
    uint32_t timestamp = filter.from;
    filter.to = timestamp;

    // read SuperCodex file(s)
    uint64_t bits[1000]{};
    for (const auto &file : codexIndex->codices(filter)) {
        // open SuperCodex file
        SuperCodex::Loader codex(file, static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::PACKETS), filter);
        for (auto packet = codex.firstPacket(); packet; packet = codex.nextPacket(packet))
            if (packet->second == timestamp)
                bits[packet->nanosecond / 1000000] += packet->savedLength;
    }

    // build result
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootArray = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, rootArray);
    for (size_t i = 0; i < 1000; ++i)
        yyjson_mut_arr_add_uint(document, rootArray, bits[i] * 8); // change bytes to bits

    // return
    Civet7::respond200(connection, document);
}

void DataFeed::getEvents(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // lookback window
    uint32_t from = 0, to = INT32_MAX;
    try {
        if (parameters.contains("from"s))
            from = std::stoi(parameters.at("from"s));
        if (parameters.contains("to"s))
            to = std::stoi(parameters.at("to"s));
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to organize input timestamps(either \"from\" or \"to\").");
        return;
    }

    // build request-specific filter parameters
    ankerl::unordered_dense::set<std::string> filterTags;
    if (parameters.contains("tags"s)) { // tag name
        std::istringstream tokenizer(parameters.at("tags"s));
        for (std::string tag; std::getline(tokenizer, tag, ',');)
            filterTags.insert(tag);
    }
    Event7::Description::Trigger::Severity filterSeverity = Event7::Description::Trigger::SEVERITYALL;
    if (parameters.contains("severity"s)) { // severity
        const std::string &string = parameters.at("severity"s);
        if (string == "info"s)
            filterSeverity = Event7::Description::Trigger::INFO;
        else if (string == "warning"s)
            filterSeverity = Event7::Description::Trigger::WARNING;
        else if (string == "critical"s)
            filterSeverity = Event7::Description::Trigger::CRITICAL;
    }
    SuperCodex::ChapterType filterDataSource = SuperCodex::ChapterType::EVENTS;
    if (parameters.contains("datasource"s)) // data source
        filterDataSource = Event7::determineDataSource(parameters.at("datasource"s).data());
    std::string filterMessage;
    if (parameters.contains("message"s)) // message
        filterMessage = parameters.at("message"s);
    unsigned int limit = UINT32_MAX; // maximum number of messages
    if (parameters.contains("limit"s))
        try {
            limit = std::stoul(parameters.at("limit"s));
        } catch (...) {
            // ignore any exceptionm
        }

    // build result
    unsigned int recordsCount = 0;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    std::function<yyjson_mut_val *(const std::string &)> buildResultArray = [&](const std::string &dbPath) -> yyjson_mut_val * {
        yyjson_mut_val *result = yyjson_mut_arr(document);

        // read from Event7 database
        FeatherLite feather(dbPath, SQLITE_OPEN_READONLY);
        feather.prepare("SELECT occurredat, severity, datasource, lookbackwindow, type, value, threshold, tag, description FROM rows WHERE occurredat>=? AND occurredat<=? ORDER BY occurredat,description;");
        feather.bindInt(1, from);
        feather.bindInt(2, to);
        while (feather.next() == SQLITE_ROW) {
            // check maximum record count
            if (recordsCount >= limit)
                break;

            // filter record: tag, severity, data source, message
            const std::string_view tag(feather.getText(7));
            if (!filterTags.empty() && !filterTags.contains(std::string(tag)))
                continue;
            const Event7::Description::Trigger::Severity severity = static_cast<Event7::Description::Trigger::Severity>(feather.getInt(1));
            if (filterSeverity != Event7::Description::Trigger::SEVERITYALL && filterSeverity != severity)
                continue;
            const SuperCodex::ChapterType dataSource = static_cast<SuperCodex::ChapterType>(feather.getInt(2));
            if (filterDataSource != SuperCodex::ChapterType::EVENTS && filterDataSource != dataSource)
                continue;
            const std::string_view message = feather.getText(8);
            if (!filterMessage.empty() && filterMessage != message)
                continue;

            // register and build new object to the array
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(result, object);
            yyjson_mut_obj_add_int(document, object, "occurredat", feather.getInt(0));
            switch (severity) {
            case Event7::Description::Trigger::Severity::INFO:
                yyjson_mut_obj_add_strn(document, object, "severity", "INFO", 4);
                break;
            case Event7::Description::Trigger::Severity::WARNING:
                yyjson_mut_obj_add_strn(document, object, "severity", "WARNING", 7);
                break;
            case Event7::Description::Trigger::Severity::CRITICAL:
                yyjson_mut_obj_add_strn(document, object, "severity", "CRITICAL", 8);
                break;
            default:
                yyjson_mut_obj_add_strn(document, object, "severity", "unknown", 7);
            }
            switch (dataSource) {
            case SuperCodex::ChapterType::BPSPERSESSION:
                yyjson_mut_obj_add_strn(document, object, "datasource", "BPS", 3);
                break;
            case SuperCodex::ChapterType::PPSPERSESSION:
                yyjson_mut_obj_add_strn(document, object, "datasource", "PPS", 3);
                break;
            case SuperCodex::ChapterType::RTTS:
                yyjson_mut_obj_add_strn(document, object, "datasource", "RTT", 3);
                break;
            case SuperCodex::ChapterType::TIMEOUTS:
                yyjson_mut_obj_add_strn(document, object, "datasource", "TCP timeouts", 12);
                break;
            case SuperCodex::ChapterType::TCPRSTS:
                yyjson_mut_obj_add_strn(document, object, "datasource", "TCP rsts", 7);
                break;
            case SuperCodex::ChapterType::TCPRETRANSMISSIONS:
                yyjson_mut_obj_add_strn(document, object, "datasource", "TCP retransmissions", 19);
                break;
            case static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPZEROWINDOW):
                yyjson_mut_obj_add_strn(document, object, "datasource", "TCP zero windows", 16);
                break;
            case static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPPORTSREUSED):
                yyjson_mut_obj_add_strn(document, object, "datasource", "TCP ports reused", 16);
                break;
            case static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPOUTOFORDER):
                yyjson_mut_obj_add_strn(document, object, "datasource", "TCP out of orders", 17);
                break;
            case SuperCodex::ChapterType::TCPDUPACKS:
                yyjson_mut_obj_add_strn(document, object, "datasource", "TCP dup acks", 11);
                break;
            default:
                yyjson_mut_obj_add_strn(document, object, "datasource", "unknown", 7);
            }
            switch (static_cast<Event7::Description::Trigger::Type>(feather.getInt(4))) {
            case Event7::Description::Trigger::OVERTHRESHOLD:
                yyjson_mut_obj_add_strn(document, object, "type", "Over threshold", 14);
                break;
            case Event7::Description::Trigger::UNDERTHRESHOLD:
                yyjson_mut_obj_add_strn(document, object, "type", "Under threshold", 15);
                break;
            case Event7::Description::Trigger::DELTA:
                yyjson_mut_obj_add_strn(document, object, "type", "Delta", 5);
                break;
            }
            yyjson_mut_obj_add_sint(document, object, "lookbackwindow", feather.getInt(3));
            yyjson_mut_obj_add_sint(document, object, "value", feather.getInt64(5));
            yyjson_mut_obj_add_sint(document, object, "threshold", feather.getInt64(6));
            yyjson_mut_obj_add_strncpy(document, object, "tag", tag.data(), tag.size());
            yyjson_mut_obj_add_strncpy(document, object, "description", message.data(), message.size());
        }

        // return result
        return result;
    };

    if (parameters.contains("include"s) && parameters.at("include"s) == "all"s) {
        // initialize JSON object in root
        yyjson_mut_val *rootObject = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootObject);

        // register JSON arrays
        for (const auto &pair : feeds) {
            const std::string dbPath = CodexIndex::feedRoot + pair.first + Event7::dbs[0];
            yyjson_mut_obj_add_val(document, rootObject, pair.first.data(), buildResultArray(dbPath));
        }
    } else
        yyjson_mut_doc_set_root(document, buildResultArray(feedPath + Event7::dbs[0]));

    Civet7::respond200(connection, document);
}

void DataFeed::getSchrodinger(mg_connection *connection, ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // enumerate target SuperCodex files
    SuperCodex::Conditions conditions;
    try {
        if (parameters.contains("from"s))
            conditions.from = std::stoi(parameters.at("from"s));
        if (parameters.contains("to"s))
            conditions.to = std::stoi(parameters.at("to"s));
    } catch (...) {
        mg_send_http_error(connection, 400, "Error occurred on converting epoch timestamp.");
        return;
    }
    conditions.dataFeed = feedName;
    auto codicesToGo = codexIndex->codices(conditions);

    // get summary from each SuperCodex files
    tbb::affinity_partitioner partitioner;
    auto summaries = SuperCodex::parallel_convert<std::string, SuperCodex::Loader::SchrodingerSummary>(codicesToGo, &SuperCodex::Loader::schrodingerSummary, partitioner);

    // merge and deduplicate
    ankerl::unordered_dense::set<uint16_t> deduplicated8021QTags, deduplicatedMplsLabels;
    for (const auto &summary : summaries) {
        for (const auto &tag : summary.vlanQs)
            deduplicated8021QTags.insert(tag);
        for (const auto &label : summary.mplsLabels)
            deduplicatedMplsLabels.insert(label);
    }

    // build result
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);
    // add 802.1Q VLAN tags
    yyjson_mut_val *vlanQTags = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "vlanqtags", vlanQTags);
    for (const auto &tag : deduplicated8021QTags)
        yyjson_mut_arr_add_int(document, vlanQTags, tag);
    // add MPLS labels
    yyjson_mut_val *mplsLabels = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "mplslabels", mplsLabels);
    for (const auto &label : deduplicatedMplsLabels)
        yyjson_mut_arr_add_int(document, mplsLabels, label);

    // return result
    Civet7::respond200(connection, document);
}

void DataFeed::initializeDnsCache()
{
    // determine until when the cache is built
    int lastTimestampFromFile = 0;
    std::string appsLast = feedPath + "/apps.last"s;
    if (std::filesystem::exists(appsLast)) {
        std::ifstream lastRead(appsLast, std::ios::binary);
        lastRead.read((char *) &lastTimestampFromFile, 4);
        lastRead.close();
    }
    // start caching thread
    std::thread(
        [&](int32_t lastTimestamp) {
            // prepare for variables
            const std::string appsLast = feedPath + "/apps.last"s;
            ankerl::unordered_dense::set<std::pair<std::string, std::string>> deduplicatedFqdns; // domain name + IP address

            while (true) {
                // prepare for a few stuff
                auto oneMinuteAfter = std::chrono::steady_clock::now() + std::chrono::minutes(1);
                deduplicatedFqdns.clear();

                // determine the lookback window
                SuperCodex::Conditions conditions;
                conditions.l7Protocol = SuperCodex::Session::DNS; // DNS only
                codexIndex->availableTimeframe(feedName, conditions.from, conditions.to);
                conditions.from = lastTimestamp;
                conditions.dataFeed = feedName;
                if (conditions.from < conditions.to) {
                    // prepare to open SuperCodex files
                    const SuperCodex::ChapterType chaptersToOpen = SuperCodex::REMARKS;
                    auto codicesToGo = codexIndex->codices(conditions);

                    while (!codicesToGo.empty()) {
                        // determine how many SuperCodex files will be opened
                        std::vector<std::string> codicesThisTime;
                        codicesThisTime.reserve(std::thread::hardware_concurrency());
                        auto iterator = codicesToGo.begin();
                        for (int i = 0, iEnd = std::min(codicesToGo.size(), codicesThisTime.capacity()); i < iEnd; ++i)
                            codicesThisTime.push_back(*iterator++);
                        codicesToGo.erase(codicesToGo.begin(), iterator);

                        // open SuperCodex files in parallel
                        std::vector<ankerl::unordered_dense::set<std::pair<std::string, std::string>>> toMerge = SuperCodex::parallel_convert<std::string, ankerl::unordered_dense::set<std::pair<std::string, std::string>>>(codicesThisTime, [&](const std::string &filename) -> ankerl::unordered_dense::set<std::pair<std::string, std::string>> {
                            ankerl::unordered_dense::set<std::pair<std::string, std::string>> results;

                            // read chapter "remarks" and find out new FQDNs
                            SuperCodex::Loader loader(filename, chaptersToOpen, conditions);
                            std::thread tcpServicesUpdateThread([&]() { TcpServiceManager::updateServices(loader); }); // update TCP services in the background
                            for (auto remarks = loader.firstRemarks(); remarks.content; remarks = loader.nextRemarks(remarks)) {
                                // find the line for DnsAnswerRRs
                                std::string_view finder(remarks.content, remarks.size);
                                size_t from = finder.find("DnsAnswerRRs="s); // this occurs only once per session
                                if (from != std::string_view::npos) {
                                    size_t to = finder.find('\n', from + 13);
                                    if (to != std::string_view::npos) {
                                        // declare actual data: skip "DnsAswerRRs=" header in front
                                        const std::string_view source = finder.substr(from + 13, to - from - 13);
                                        // get domain name in question
                                        const std::string queriedName(source.substr(0, source.find(',')));

                                        // extract records to get IP addresses for that FQDN
                                        std::istringstream divider((std::string(source)));
                                        for (std::string record; std::getline(divider, record, ' ');)
                                            if (record.find(",1,") != std::string::npos) { // found DNS "A" type record
                                                std::string ip = SuperCodex::stringFromHex(record.substr(record.size() - 8));
                                                results.insert(std::make_pair(queriedName, ip));
                                            } else if (record.find(",28,") != std::string::npos) { // found DNS AAAA type record
                                                std::string ip = SuperCodex::stringFromHex(record.substr(record.size() - 32));
                                                results.insert(std::make_pair(queriedName, ip));
                                            } // we ignore others, e.g. MX
                                    }
                                }
                            }

                            // wait for TCP service update thread to finish
                            tcpServicesUpdateThread.join();
                            TcpServiceManager::saveServices();
                            return results;
                        });

                        // merge to final results
                        for (const auto &set : toMerge)
                            for (const auto &pair : set)
                                deduplicatedFqdns.insert(pair);
                    }
                }

                // push records
                SubSystems::fqdnMutex.lock();
                { // without this bracket, "feather" will live until end of this loop, which leaves unnecessary WAL files on the disk
                    FeatherLite feather("apps.fqdns"s);
                    feather.useWal();
                    feather.prepare("INSERT OR IGNORE INTO fqdns(name,ip) VALUES(?,?);"); // existing records are ignored
                    for (const auto &pair : deduplicatedFqdns) {
                        feather.bindText(1, pair.first);
                        feather.bindBlob(2, pair.second);
                        feather.next();
                        feather.reset();
                    }
                    feather.finalize();
                }
                SubSystems::fqdnMutex.unlock();

                // update last timestamp this job read
                lastTimestamp = conditions.to;
                std::ofstream writeLastRead(appsLast, std::ios::binary | std::ios::trunc);
                writeLastRead.write((const char *) &lastTimestamp, 4);
                writeLastRead.close();

                // wait until next timing
                std::this_thread::sleep_until(oneMinuteAfter);
            } // end of one-minute loop
        },
        lastTimestampFromFile)
        .detach();
}

std::string DataFeed::buildSuperCodexConditions(const ankerl::unordered_dense::map<std::string, std::string> &parameters, SuperCodex::Conditions &conditions)
{
    // tags
    if (parameters.contains("tags"s)) { // get IPs from tags
        std::istringstream tokenizer(parameters.at("tags"s));
        for (std::string tag; std::getline(tokenizer, tag, ',');)
            if (tags.contains(tag)) {
                for (auto ipInHex = tags[tag]["ips"].cbegin(), ipInHexEnd = tags[tag]["ips"].cend(); ipInHex != ipInHexEnd; ++ipInHex) {
                    const std::string ipRaw = ipInHex->get<std::string>();
                    conditions.allowedIps.registerNetwork(ipRaw);
                }
            }
    }

    // apps
    if (parameters.contains("apps"s)) {
        const std::string &apps = parameters.at("apps"s);
        if (!apps.empty()) {
            FeatherLite fqdns("apps.fqdns"s, SQLITE_OPEN_READONLY), userDefined("apps.user"s, SQLITE_OPEN_READONLY);
            fqdns.useWal();
            userDefined.useWal();
            std::istringstream tokenizer(apps);
            for (std::string app; std::getline(tokenizer, app, ',');) {
                fqdns.prepare("SELECT ip,name FROM fqdns WHERE name LIKE '%"s + app + "%'"s);
                while (fqdns.next() == SQLITE_ROW)
                    conditions.allowedIps.registerNetwork(std::string(fqdns.getBlob(0)));
                userDefined.prepare("SELECT ips FROM raw WHERE name LIKE '%"s + app + "%'"s);
                while (userDefined.next() == SQLITE_ROW) {
                    std::istringstream ipSplitter(std::string(userDefined.getText(0)));
                    for (std::string ip; std::getline(ipSplitter, ip, ',');)
                        conditions.allowedIps.registerNetwork(ip);
                }
            }

            // exception handling: no associated IP addresses found
            if (conditions.allowedIps.isEmpty)
                return "No IP addresses associted with given application search condition"s;
        }
    }

    // IPs
    std::function<bool(const std::string &, SuperCodex::IpFilter &)> pushToIpList = [&](const std::string &tokensRaw, SuperCodex::IpFilter &targetToPush) -> bool {
        std::istringstream tokenizer(tokensRaw);
        for (std::string ipRaw; std::getline(tokenizer, ipRaw, ',');) {
            // check validity of IP
            bool ipValid = true;
            if (ipRaw.size() != 8 && ipRaw.size() != 10 && ipRaw.size() != 32 && ipRaw.size() != 34)
                ipValid = false;
            for (const char &ch : ipRaw)
                if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f'))) {
                    ipValid = false;
                    break;
                }
            if (ipValid)
                targetToPush.registerNetwork(ipRaw);
            else
                return false;
        }
        return true;
    };
    if (parameters.contains("ips"s)) {
        if (!pushToIpList(parameters.at("ips"s), conditions.allowedIps))
            return "ips: IP should be given as either 8- or 10-digit for IPv4, or 32- or 34-digit for IPv6 in hexadecimal."s;
    }

    // ports
    if (parameters.contains("ports"s)) {
        std::istringstream tokenizer(parameters.at("ports"s));
        for (std::string port; std::getline(tokenizer, port, ',');) {
            try {
                if (port.find('-')) { // ports selected in range
                    auto separator = port.find('-');
                    std::string portFrom = port.substr(0, separator), portTo = port.substr(separator + 1);
                    int i = std::stoi(portFrom), iEnd = std::stoi(portTo);
                    // simple sanity check
                    if (i > 65535 || iEnd > 65535 || i <= 0 || iEnd <= 0)
                        throw "Port number out of range.";
                    if (std::stoi(portFrom) > std::stoi(portTo))
                        throw "Range header is bigger than range tail.";
                    for (; i <= iEnd; i++)
                        conditions.ports.insert(i);
                } else { // individual port filter
                    int portNumber = std::stoi(port);
                    if (portNumber > 65535 || portNumber <= 0)
                        throw "Port number out of range.";
                    conditions.ports.insert(portNumber);
                }
            } catch (const char *message) {
                std::string errorMessage("Exception on setting up port filter. Details: "s);
                errorMessage.append(message);
                return errorMessage;
            } catch (std::exception &e) {
                std::string errorMessage("Exception on setting up port filter. Details: "s);
                errorMessage.append(e.what());
                return errorMessage;
            } catch (...) {
                return "Unknown exception occurred on setting up port filter. Check the parameters and try again."s;
            }
        }
    }

    std::string value;
    // payload protocol
    if (parameters.contains("payloadprotocol"s)) {
        value = parameters.at("payloadprotocol"s);
        if (value == "tcp"s)
            conditions.payloadProtocol = 0x06;
        else if (value == "udp"s)
            conditions.payloadProtocol = 0x11;
        else if (value == "icmp"s)
            conditions.payloadProtocol = 0x1;
    }

    // detected L7 protocols
    if (parameters.contains("detectedl7"s)) {
        value = parameters.at("detectedl7"s);
        if (value.empty())
            conditions.l7Protocol = SuperCodex::Session::NOL7DETECTED;
        // base protocols
        else if (value == "dns"s)
            conditions.l7Protocol = SuperCodex::Session::DNS;
        else if (value == "http"s)
            conditions.l7Protocol = SuperCodex::Session::HTTP;
        else if (value == "tls"s)
            conditions.l7Protocol = SuperCodex::Session::TLS;
        else if (value == "ftp"s)
            conditions.l7Protocol = SuperCodex::Session::FTP;
        else if (value == "smtp"s)
            conditions.l7Protocol = SuperCodex::Session::SMTP;
        else if (value == "imap"s)
            conditions.l7Protocol = SuperCodex::Session::IMAP;
        else if (value == "pop3"s)
            conditions.l7Protocol = SuperCodex::Session::POP3;
        // AV streaming
        else if (value == "rtp"s)
            conditions.l7Protocol = SuperCodex::Session::RTP;
        else if (value == "rtcp"s)
            conditions.l7Protocol = SuperCodex::Session::RTCP;
        else if (value == "rtsp"s)
            conditions.l7Protocol = SuperCodex::Session::RTSP;
        // VoIP and teleconference
        else if (value == "sip"s)
            conditions.l7Protocol = SuperCodex::Session::SIP;
    }

    // include packets from/to external network
    if (parameters.contains("includeexternal"s))
        conditions.includeExternalTransfer = (parameters.at("includeexternal"s) == "true"s);
    else
        conditions.includeExternalTransfer = true;

    // time frames(from, to)
    try {
        codexIndex->availableTimeframe(feedName, conditions.from, conditions.to);
        if (parameters.contains("from"s))
            conditions.from = std::stoi(parameters.at("from"s));
        if (parameters.contains("to"s))
            conditions.to = std::stoi(parameters.at("to"s));
    } catch (...) {
        return "Failed to organize input timestamps(either \"from\" or \"to\"."s;
    }

    // Schrodinger optional filters
    try {
        if (parameters.contains("vlanq")) {
            std::istringstream tokenizer(parameters.at("vlanq"s));
            for (std::string tag; std::getline(tokenizer, tag, ',');)
                conditions.vlanQTags.insert(stoi(tag));
        }
        if (parameters.contains("mpls")) {
            std::istringstream tokenizer(parameters.at("mpls"s));
            for (std::string label; std::getline(tokenizer, label, ',');)
                conditions.mplsLabels.insert(stoi(label));
        }
    } catch (...) {
        return "Failed to build conditions for Schrodinger"s;
    }

    return std::string();
}

DataFeed::JobStatus DataFeed::jobStatus(const std::string username, const uint64_t jobId)
{
    std::shared_lock lock(refinery.jobsQueueMutex);
    for (const auto &job : refinery.jobsQueue)
        if (jobId == job->conditions.jobId && username == job->username) {
            if (job->progress == -1)
                return COMPLETE;
            else if (job->progress)
                return INPROGRESS;
            else
                return INQUEUE;
        }

    return NOTFOUND;
}

void DataFeed::postRefinery(mg_connection *connection, const std::string &username, ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // prepare for filter conditions
    SuperCodex::Conditions conditions;

    // set request type
    if (!parameters.contains("type"s)) {
        mg_send_http_error(connection, 400, "Refining type not found.");
        return;
    }

    // per-type integrity check
    const std::string &type = parameters.at("type"s);
    if (type == "datastreams"s || type == "httptracker"s) {
        // add regular expression if one exists
        if (parameters.contains("regex"s)) {
            // check validity of the regex
            try {
                std::regex validityTester(parameters["regex"]);
            } catch (...) {
                mg_send_http_error(connection, 400, "Invalid regular expression");
                return;
            }
        }
    } else if (type == "topn"s) {
        // check and set required additional parameters(base)
        if (!parameters.contains("base"s)) { // required parameter is missing
            mg_send_http_error(connection, 400, "Required parameter(base) is missing");
            return;
        }
    } else if (type == "overview"s) {
        if (!parameters.contains("gatherby"s) || parameters.at("gatherby"s).empty()) {
            mg_send_http_error(connection, 400, "Essential parameter(gatherby) is missing or sent but empty");
            return;
        }
    } else if (type == "lowhoplimits"s) {
        if (parameters.contains("n"s)) {
            try {
                int n;
                n = std::stoi(parameters.at("n"s));
                if (n < 0)
                    throw "NEGATIVE";
            } catch (...) {
                mg_send_http_error(connection, 400, "n is invalid(either negative or non-number)");
                return;
            }
        }
    } else if (type == "bps2"s) {
        if (!parameters.contains("internalips"s) || parameters.at("internalips"s).empty()) { // required parameter is missing or empty
            mg_send_http_error(connection, 400, "Required parameter(internalips) is missing or empty");
            return;
        }
    }

    // prepare for conditions
    std::string conditionsCreationError = buildSuperCodexConditions(parameters, conditions);
    if (!conditionsCreationError.empty()) {
        mg_send_http_error(connection, 400, conditionsCreationError.data());
        return;
    }
    conditions.parameters = std::move(parameters);
    conditions.dataFeed = feedName;

    // conditions are recognized. now create job ID
    conditions.jobId = DataFeedRefinery::jobId(username, feedName, conditions);
    std::lock_guard locker(deleteRefineryMutex); // wait for any previous delete job to complete before new job is added
    auto status = jobStatus(username, conditions.jobId);
    if (status != NOTFOUND) { // check duplication against jobs queue
        logger.log("Duplicate job. Do nothing: "s + std::to_string(status));
    } else { // this is brand new job
        // fine-tune conditions per request
        if ((type == "topn"s && conditions.parameters.at("base") == "httperrors"s) || type == "httptracker"s || type == "httt")
            conditions.l7Protocol = SuperCodex::Session::HTTP; // HTTP
        else if (type == "icmpwalk"s)
            conditions.payloadProtocol = 0x01; // ICMP
        else if (type == "icmp6walk"s)
            conditions.payloadProtocol = 0x3a; // ICMPv6
        else if (type == "dnstracker"s)
            conditions.l7Protocol = SuperCodex::Session::DNS; // DNS
        else if (type == "tlstracker"s)
            conditions.l7Protocol = SuperCodex::Session::TLS; // TLS
        else if (type == "voipmonitor"s)
            conditions.l7Protocol = SuperCodex::Session::SIP; // SIP
        else if (type == "tcphandshake"s)
            conditions.payloadProtocol = 0x06; // TCP
        else if (type == "raw"s && conditions.parameters.contains("buildpackethash"s) && conditions.parameters.at("buildpackethash"s) == "true") // "raw" with packet hash generation
            conditions.payloadProtocol = 0x06; // TCP
        else if (type == "sessiondetails"s) {
            const auto ipsRegistered = conditions.allowedIps.registeredAddresses();
            if (!((ipsRegistered.first == 2 || ipsRegistered.second == 2) && conditions.ports.size() == 1)) { // one pair of IP addresses + one port only
                mg_send_http_error(connection, 400, "There must be only two IPs and one port number in the filter");
                return;
            }
            conditions.includeExternalTransfer = false;
        }

        // introduce a new job to the queue
        refinery.queueAJob(username, conditions);
    }

    mg_send_http_error(connection, 202, "%u", conditions.jobId);
}

void DataFeed::getProgress(mg_connection *connection, const std::string &username)
{
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootArray = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, rootArray);

    refinery.jobsQueueMutex.lock_shared();
    for (const auto &job : refinery.jobsQueue)
        if (job->username == username) {
            auto originalParamters = job->conditions.parameters;
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(rootArray, object);
            yyjson_mut_obj_add_int(document, object, "jobid", job->conditions.jobId);
            yyjson_mut_obj_add_int(document, object, "progress", job->progress);
            // target lookback window
            uint32_t from = 0, to = 0;
            if (job->progress == -1)
                job->refiner->resultTimeFrame(from, to);
            else {
                if (originalParamters.contains("from"s))
                    from = std::stoi(originalParamters["from"s]);
                if (originalParamters.contains("to"s))
                    to = std::stoi(originalParamters["to"s]);
            }
            yyjson_mut_obj_add_int(document, object, "from", from);
            yyjson_mut_obj_add_int(document, object, "to", to);
            // original parameters
            yyjson_mut_val *originalCondition = yyjson_mut_obj(document);
            yyjson_mut_obj_add(object, yyjson_mut_str(document, "originalcondition"), originalCondition);
            for (auto j = originalParamters.cbegin(), jEnd = originalParamters.cend(); j != jEnd; ++j)
                yyjson_mut_obj_add(originalCondition, yyjson_mut_strncpy(document, j->first.data(), j->first.size()), yyjson_mut_strncpy(document, j->second.data(), j->second.size()));
        }
    refinery.jobsQueueMutex.unlock_shared();

    size_t resultSize;
    char *resultRaw = yyjson_mut_write(document, YYJSON_WRITE_NOFLAG, &resultSize);
    Civet7::respond200(connection, resultRaw, resultSize);
    free(resultRaw);
    yyjson_mut_doc_free(document);
}

void DataFeed::getRefinery(mg_connection *connection, const std::string &username, const std::string &path, ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // get job ID
    unsigned int key;
    try {
        key = std::stoul(path.substr(1));
    } catch (...) {
        logger.log("Invalid job ID(not an integer)");
        mg_send_http_error(connection, 400, "Invalid job ID(not an integer)");
        return;
    }

    // check status
    auto status = jobStatus(username, key); // jobStatus() uses jobQueueMutex too
    switch (status) {
    // INQUEUE, INPROGRESS, NOTFOUND: return error message
    case INPROGRESS:
        mg_send_http_error(connection, 202, "Still in progress: %i%%", refinery.job(username, key)->progress.load());
        return;
    case INQUEUE: // do nothing
        mg_send_http_error(connection, 202, "Still in queue: 0%");
        return;
    case NOTFOUND: // do nothing
        mg_send_http_error(connection, 404, "No such job ID: %u", key);
        return;

    // COMPLETE - continue processing
    case COMPLETE:
        logger.log("Result generated. Sending result");
        break;
    }

    // obtain job
    refinery.jobsQueueMutex.lock();
    auto job = refinery.job(username, key);
    if (!job) {
        logger.log("Job ID not found."s);
        mg_send_http_error(connection, 404, "Job ID not found. Maybe because of deletion request?");
        return;
    }
    job->refiner->lastAccess = time(nullptr); // update last access timestamp
    refinery.jobsQueueMutex.unlock();

    // determine result type and send result accordingly
    try {
        if (parameters.contains("type"s) && parameters.at("type"s) == "tabseparated"s) { // text/tab-separated-values. dump all the results; always send in chunked mode
            Civet7::respond200(connection, nullptr, 0, "text/tab-separated-values"s);
            job->refiner->dumpResults(connection);
        } else { // everything else
            // parse and validate essential parameters
            uint32_t from = 0, to = UINT32_MAX, bindValue = 0;
            try {
                if (parameters.contains("from"s))
                    from = std::stoul(parameters.at("from"s));
                if (parameters.contains("to"s))
                    to = std::stoul(parameters.at("to"s));
                if (parameters.contains("bind"s))
                    bindValue = std::stoi(parameters.at("bind"s));
            } catch (...) {
                mg_send_http_error(connection, 400, "Failed to convert values to numbers.");
                return;
            }
            if (from > to) {
                mg_send_http_error(connection, 400, "Parameter 'from' must be equal to or smaller than parameter 'to'.");
                return;
            }

            // generate result
            job->refiner->resultsInteractive(connection, from, to, bindValue, parameters);
        }
    } catch (std::exception &e) {
        logger.log("Exception occurred: "s + e.what());
        mg_send_http_error(connection, 500, e.what());
    } catch (...) {
        logger.log("Exception occurred. Details unknown."s);
        mg_send_http_error(connection, 500, "Details unknown.");
    }
}

void DataFeed::deleteRefinery(mg_connection *connection, const std::string &username, const std::string &path)
{
    std::lock_guard locker(deleteRefineryMutex);
    unsigned int key = 0;
    try {
        logger.log("Remove job: "s + path);
        // basic sanity check
        if (path.empty())
            throw "Job ID blank";

        // determine mode
        bool deleteQueued = false, deleteCurrent = false, deleteCompletes = false;
        if (path == "/all"s) { // delete "practically all TODOs"
            deleteQueued = true;
            deleteCurrent = true;
        } else if (path == "/completes"s) { // delete all complete jobs
            deleteCompletes = true;
        } else if (path == "/nuke"s) { // delete everything
            deleteQueued = true;
            deleteCurrent = true;
            deleteCompletes = true;
        } else
            key = std::stoul(path.substr(1));

        // delete job(s) as requested
        std::lock_guard lock(refinery.jobsQueueMutex);
        if (key) { // delete single job: try to find from jobs queue
            for (auto i = refinery.jobsQueue.begin(); i != refinery.jobsQueue.end();)
                if ((*i)->conditions.jobId == key) {
                    i = refinery.jobsQueue.erase(i);
                    break;
                } else
                    i++;
            logger.log("Removed job from job queue."s);
        } else { // delete multiple jobs at once based on status
            if (deleteQueued) {
                logger.log("Clear queued jobs"s);
                for (auto i = refinery.jobsQueue.begin(); i != refinery.jobsQueue.end();)
                    if ((*i)->progress == 0) {
                        if ((*i)->username == username)
                            i = refinery.jobsQueue.erase(i);
                        else
                            ++i;
                    } else
                        ++i;
            }

            if (deleteCurrent) {
                logger.log("Cancel current job"s);
                refinery.cancelCurrentJob(username);
            }

            if (deleteCompletes) {
                logger.log("Clear complete jobs"s);
                for (auto i = refinery.jobsQueue.begin(); i != refinery.jobsQueue.end();)
                    if ((*i)->username == username && (*i)->progress == -1)
                        i = refinery.jobsQueue.erase(i);
                    else
                        ++i;
            }
        }
        mg_send_http_error(connection, 204, "\r\n\r\n");
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to obtain job ID to delete. It should be decimal number.");
    }
}

void DataFeed::putRefinery(mg_connection *connection, const std::string &username, const std::string &path, ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // get job ID
    unsigned int key;
    try {
        key = std::stoul(path.substr(1));
    } catch (...) {
        logger.log("Invalid job ID(not an integer)");
        mg_send_http_error(connection, 400, "Invalid job ID(not an integer)");
        return;
    }

    // check status
    std::function<int(const DataFeed::JobStatus)> statusCode = [](const DataFeed::JobStatus status) -> int {
        switch (status) {
        case INQUEUE:
            return 202;
        case INPROGRESS:
            return 202;
        case NOTFOUND:
            return 404;
        case COMPLETE:
            return 0; // continue processing
        }
    };
    std::function<std::string(const DataFeed::JobStatus)> returnMessage = [&](const DataFeed::JobStatus status) -> std::string {
        switch (status) {
        case INQUEUE:
            return "Still in queue: 0"s;
        case INPROGRESS:
            return "Still in progress: "s;
        case NOTFOUND:
            return "No such job ID"s;
        case COMPLETE:
            return ""s; // continue processing
        }
    };

    auto status = jobStatus(username, key);
    int code = statusCode(status);
    std::string message = returnMessage(status);
    switch (status) {
    // INQUEUE, INPROGRESS, NOTFOUND: return error message
    case INPROGRESS:
        // add progress in percentage
        refinery.jobsQueueMutex.lock_shared();
        message.append(std::to_string(refinery.job(username, key)->progress));
        refinery.jobsQueueMutex.unlock_shared();
    case INQUEUE: // do nothing
    case NOTFOUND: // do nothing
        logger.log(message + '%');
        mg_send_http_error(connection, code, message.c_str());
        return;

    // COMPLETE - continue processing
    case COMPLETE:
        logger.log("Complete. Continue processing");
        break;
    }

    refinery.jobsQueueMutex.lock();
    auto job = refinery.job(username, key);
    if (!job) {
        refinery.jobsQueueMutex.unlock();
        logger.log("Job ID not found."s);
        mg_send_http_error(connection, 404, "Job ID not found. Maybe because of deletion request?");
        return;
    }
    job->refiner->lastAccess = time(nullptr); // update last access timestamp
    refinery.jobsQueueMutex.unlock();

    // run PUT
    job->refiner->put(connection, parameters);
}
