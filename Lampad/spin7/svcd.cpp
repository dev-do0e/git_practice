#include "svcd.h"
#include "datafeed.h"
#include "subsystems.h"
#include "codexindex.h"
#include "civet7.hpp"
#include "supercache.h"
#include "../featherlite.h"
#include "../supercodex.h"

#include <ankerl/unordered_dense.h>
#include <yyjson.h>
#include <chrono>
#include <thread>
#include <future>
#include <fstream>
#include <sstream>

// extern variables
std::vector<std::pair<std::string, std::string>> ServiceDashboard::jsonStrings;
std::mutex ServiceDashboard::jsonStringMutex;
std::mutex ServiceDashboard::clientIpGroupsMutex;
Logger ServiceDashboard::logger("SVCD"s);

void ServiceDashboard::start()
{
    logger.log("Startup"s);
    while (true) {
        // update dashboard every one minute
        auto oneMinuteLater = std::chrono::steady_clock::now() + std::chrono::minutes(1);

        // enumerate services and associated thresholds
        logger.log("Build signature prototypes"s);
        SuperCodex::IpFilter clientIpGroups = buildClientIpGroups(), services;
        ankerl::unordered_dense::map<uint32_t, std::string> serviceSignatures; // signature for each service + service name
        ankerl::unordered_dense::map<std::string, SubSystems::Thresholds> thresholds; // service name + thresholds
        {
            FeatherLite feather("apps.user"s, SQLITE_OPEN_READONLY);
            feather.prepare("SELECT name,ips,port,thresholds FROM raw;"s);
            while (feather.next() == SQLITE_ROW) {
                // read service information
                SuperCodex::IpFilter signatureGenerator;
                std::string name(feather.getText(0));
                uint16_t port = feather.getInt(2);
                std::istringstream ips(std::string(feather.getText(1)));
                for (std::string ip; std::getline(ips, ip, ',');) {
                    services.registerNetwork(ip, port, name);
                    signatureGenerator.registerNetwork(ip, 0, ""s);
                }

                // set thresholds
                if (feather.isNull(3))
                    thresholds[std::string(feather.getText(0))] = SubSystems::Thresholds{};
                else
                    thresholds[std::string(feather.getText(0))] = *(const SubSystems::Thresholds *) feather.getBlob(3).data();

                // register signature for given application/service
                serviceSignatures[signatureGenerator.signature()] = name;
            }
            feather.reset();
            feather.finalize();
        }

        // iterate data feeds
        std::vector<std::pair<std::string, std::string>> newJsonStrings;
        for (const auto &entry : std::filesystem::directory_iterator(CodexIndex::feedRoot))
            if (entry.is_directory()) {
                // initialize variables and check data feed structure
                const auto feedPath = entry.path();
                std::string feedName = feedPath.filename().string(); // feed name
                if (feedName[0] == '.')
                    continue;
                std::string pmpiFile = feedPath.string() + "/supercache.pmpi"; // path for SuperCache PMPI
                uint32_t pmpiLatestTimestamp = 0;
                if (std::filesystem::exists(pmpiFile)) {
                    FeatherLite feather(pmpiFile, SQLITE_OPEN_READONLY);
                    feather.prepare("SELECT MAX(timestamp) FROM rows;"s);
                    if (feather.next() == SQLITE_ROW) // latest timestamp saved in SuperCache PMPI
                        pmpiLatestTimestamp = feather.getInt64(0);
                    feather.reset();
                    feather.finalize();
                }
                if (pmpiLatestTimestamp == 0) {
                    logger.oops("Skip data feed with SuperCache PMPI not initialized: "s + feedName);
                    continue;
                }

                // declare reading database
                logger.log("Build dashboard data for "s + feedName);

                // build BPS and list of deduplicated client IPs in the background
                std::future fromRawFuture = std::async(dataFromRaw, feedName, pmpiLatestTimestamp + 59, thresholds, clientIpGroups, services);

                // foreground: prepare to read SuperCache PMPI and extract statistics
                struct ResultPack
                {
                    std::array<std::pair<uint64_t, uint64_t>, 5> timeouts{}, tcpRetransmissions{}, tcpZeroWindows{}; // value, value2
                    struct RttTriplet // data storage for RTT
                    {
                        uint64_t top = 0, bottom = UINT64_MAX, average = 0;
                    } rtts[5]{};
                };
                ankerl::unordered_dense::map<std::string, ResultPack> results; // service name + result pack
                for (const auto &pair : thresholds)
                    results[pair.first];

                // read SuperCodex PMPI
                for (const auto &pair : readPmpi(feedName, pmpiLatestTimestamp, SuperCodex::ChapterType::TIMEOUTS, services))
                    results[pair.first].timeouts = pair.second;
                for (const auto &pair : readPmpi(feedName, pmpiLatestTimestamp, SuperCodex::ChapterType::TCPRETRANSMISSIONS, services))
                    results[pair.first].tcpRetransmissions = pair.second;
                for (const auto &pair : readPmpi(feedName, pmpiLatestTimestamp, SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPZEROWINDOW, services))
                    results[pair.first].tcpZeroWindows = pair.second;

                // SuperCodex::ChapterType::RTTS
                {
                    // prepare for stuff
                    uint32_t timings[5] = {60, 600, 1800, 3600, 21600}; // 1min, 10min, 30min, 1h, 6h
                    FeatherLite feather(CodexIndex::feedRoot + feedName + "/supercache.ps2"s, SQLITE_OPEN_READONLY);
                    feather.prepare("SELECT value,timestamp FROM rows WHERE chapter=16 AND timestamp>=? AND timestamp<=? AND signature=? ORDER BY timestamp DESC;");

                    // for each service
                    for (const auto &signaturePair : serviceSignatures) {
                        // bind values
                        feather.bindInt64(1, pmpiLatestTimestamp - timings[4]);
                        feather.bindInt64(2, pmpiLatestTimestamp);
                        feather.bindInt64(3, signaturePair.first);
                        auto &target = results[signaturePair.second].rtts;

                        // read data to fill min-max-average
                        ResultPack::RttTriplet accumulated;
                        size_t recordCounter = 0;
                        size_t index = 0;
                        while (feather.next() == SQLITE_ROW && index < 5) {
                            const auto rawStream = feather.getBlob(0);
                            const FeedRefinerAbstract::ValuesRtt *cursor = (const FeedRefinerAbstract::ValuesRtt *) rawStream.data();
                            for (int i = 0; i < 60; ++i) {
                                const auto value = cursor->represent();
                                accumulated.average += value;
                                if (accumulated.top < value)
                                    accumulated.top = value;
                                if (value > 0 && accumulated.bottom > value)
                                    accumulated.bottom = value;
                                ++recordCounter;
                                ++cursor;
                            }
                            if (recordCounter >= timings[index]) {
                                target[index] = accumulated;
                                target[index].average /= recordCounter != 0 ? recordCounter : 1;
                                ++index;
                            }
                        }

                        // fill any blank slots
                        for (; index < 5; ++index) {
                            target[index] = accumulated;
                            target[index].average /= recordCounter != 0 ? recordCounter : 1;
                        }

                        // prepare for reading data from next service
                        feather.reset();
                    }
                    feather.finalize();
                }

                // finally, build result
                yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
                yyjson_mut_val *rootObject = yyjson_mut_obj(document);
                yyjson_mut_doc_set_root(document, rootObject);

                // describe common stuff
                yyjson_mut_obj_add_int(document, rootObject, "from", pmpiLatestTimestamp - 541); // +59-600=541

                // describe per service data
                yyjson_mut_val *servicesArray = yyjson_mut_arr(document);
                yyjson_mut_obj_add_val(document, rootObject, "services", servicesArray);
                auto results2 = fromRawFuture.get();
                for (const auto &pair : results) {
                    // register object to describe status per service
                    yyjson_mut_val *object = yyjson_mut_obj(document);
                    yyjson_mut_arr_append(servicesArray, object);
                    yyjson_mut_obj_add_strncpy(document, object, "name", pair.first.data(), pair.first.size());

                    // describe BPS and active clients from future
                    {
                        auto &target = results2[pair.first]; // create one if it doesn't exist. this is for maintainability
                        // BPS
                        yyjson_mut_val *bpsArray = yyjson_mut_arr(document);
                        yyjson_mut_obj_add_val(document, object, "bps", bpsArray);
                        for (int i = 0; i < 600; ++i)
                            yyjson_mut_arr_add_sint(document, bpsArray, target.bps[i] * 8); // change bytes to bits

                        // active clients
                        yyjson_mut_val *activeClientsObject = yyjson_mut_obj(document);
                        yyjson_mut_obj_add_val(document, object, "activeclients", activeClientsObject);
                        if (target.activeClients.empty()) // if active clients are empty for some reason, fill with zeros
                            target.activeClients["Etc."];
                        for (const auto &pair : target.activeClients) {
                            yyjson_mut_val *activeClientsArray = yyjson_mut_arr(document);
                            yyjson_mut_obj_add_val(document, activeClientsObject, pair.first.data(), activeClientsArray);
                            for (size_t i = 0; i < 600; ++i)
                                yyjson_mut_arr_add_uint(document, activeClientsArray, pair.second[i]);
                        }
                    }

                    // describe others from the PMPI
                    {
                        const auto &target = results[pair.first]; // create one if it doesn't exist. this is for maintainability
                        std::function<void(const char *, const std::array<std::pair<uint64_t, uint64_t>, 5>)> putValues = [&](const char *key, const std::array<std::pair<uint64_t, uint64_t>, 5> pairs) {
                            yyjson_mut_val *innerArray = yyjson_mut_arr(document);
                            yyjson_mut_obj_add_val(document, object, key, innerArray);
                            for (size_t i = 0; i < 5; ++i) {
                                yyjson_mut_val *values = yyjson_mut_obj(document);
                                yyjson_mut_arr_add_val(innerArray, values);
                                yyjson_mut_obj_add_uint(document, values, "value", pairs[i].first);
                                yyjson_mut_obj_add_uint(document, values, "value2", pairs[i].second);
                            }
                        };

                        // timeouts, TCP retransmissions, TCP zero windows
                        putValues("timeouts", target.timeouts);
                        putValues("tcpretransmissions", target.tcpRetransmissions);
                        putValues("tcpzerowindows", target.tcpZeroWindows);

                        // rtts
                        yyjson_mut_val *innerArrayRtt = yyjson_mut_arr(document);
                        yyjson_mut_obj_add_val(document, object, "rtts", innerArrayRtt);
                        for (size_t i = 0; i < 5; ++i) {
                            yyjson_mut_val *values = yyjson_mut_obj(document);
                            yyjson_mut_arr_add_val(innerArrayRtt, values);
                            const auto top = target.rtts[i].top;
                            yyjson_mut_obj_add_uint(document, values, "top", top);
                            yyjson_mut_obj_add_uint(document, values, "bottom", top != 0 ? target.rtts[i].bottom : 0); // if top is zero, set bottom to zero(default: UINT64_MAX)
                            yyjson_mut_obj_add_uint(document, values, "average", target.rtts[i].average);
                        }
                    }
                }

                // update JSON string
                logger.log("Update result"s);
                size_t jsonLength;
                yyjson_write_err parserError;
                char *jsonRaw = yyjson_mut_write_opts(document, YYJSON_WRITE_ALLOW_INVALID_UNICODE, nullptr, &jsonLength, &parserError);
                if (jsonLength == 0)
                    logger.log("Result empty. JSON parser error: "s + parserError.msg);
                else
                    newJsonStrings.push_back(std::make_pair(feedName, std::string(jsonRaw, jsonLength)));

                // free memory for JSON
                free(jsonRaw);
                yyjson_mut_doc_free(document);
            }

        jsonStringMutex.lock();
        jsonStrings.swap(newJsonStrings);
        jsonStrings.shrink_to_fit();
        jsonStringMutex.unlock();

        // wait until one minute passes
        std::this_thread::sleep_until(oneMinuteLater);
    }
}

ankerl::unordered_dense::map<std::string, ServiceDashboard::DataPackFromRaw> ServiceDashboard::dataFromRaw(const std::string &feedName, const uint32_t last, const ankerl::unordered_dense::map<std::string, SubSystems::Thresholds> &thresholds, const SuperCodex::IpFilter &clientIpGroups, const SuperCodex::IpFilter &services)
{
    // initialize result
    ankerl::unordered_dense::map<std::string, DataPackFromRaw> results; // service name + counters
    results.reserve(thresholds.size());
    for (const auto &pair : thresholds)
        results[pair.first];

    // prepare for filter conditions (=read all)
    SuperCodex::Conditions conditions;
    conditions.from = last - 599;
    conditions.to = last;

    // enumerate target SuperCodex files
    conditions.dataFeed = feedName;
    conditions.codicesToGo = DataFeed::feeds.at(feedName)->codexIndex->codices(conditions);

    // read SuperCodex files to build BPS
    struct Intermediate
    {
        uint32_t from; // offset
        struct DataPack
        {
            unsigned long long bps = 0;
            ankerl::unordered_dense::set<std::string> clientIps;
        };
        ankerl::unordered_dense::map<std::string, std::vector<DataPack>> data; // service name + data
    };
    std::thread mergeThread;
    FeedConsumer::consumeByChunk(conditions, static_cast<SuperCodex::ChapterType>(SuperCodex::BPSPERSESSION | SuperCodex::SESSIONS), std::thread::hardware_concurrency() * 2, [&](std::vector<SuperCodex::Loader *> &codicesToGo, const bool continueLoop) -> bool {
        // read BPS from each data
        std::vector<Intermediate> intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, Intermediate>(codicesToGo, [&](const SuperCodex::Loader *loader) -> Intermediate {
            int32_t localOffset = loader->secondStart;
            Intermediate result;

            result.from = localOffset;
            const size_t vectorSize = loader->secondEnd - localOffset + 1;

            for (auto bps = loader->firstBpsPerSession(); bps; bps = loader->nextBpsPerSession(bps)) {
                const auto session = loader->sessions.at(bps->sessionId);
                const auto serverIp = SuperCodex::destinationIp(*session);
                const auto serverPort = session->destinationPort;
                std::string serviceName = services.getAlias(serverIp, serverPort);
                if (serviceName.empty()) // try again with port=0(any port)
                    serviceName = services.getAlias(serverIp, 0);
                if (!serviceName.empty()) { // by doing this we can exclude traffic that don't belong to any services
                    auto &target = result.data[serviceName];
                    if (target.size() < vectorSize) // brand new service: secure memory blocks
                        target.resize(vectorSize);
                    auto &targetElement = target[bps->second - localOffset];
                    targetElement.bps += bps->fromSmallToBig + bps->fromBigToSmall;
                    targetElement.clientIps.insert(SuperCodex::sourceIp(*session));
                }
            }

            return result;
        });

        // merge
        if (mergeThread.joinable())
            mergeThread.join();
        mergeThread = std::thread(
            [&](const std::vector<Intermediate> intermediatesFuture) {
                for (const auto &intermediate : intermediatesFuture) {
                    // calculate base offset
                    long long baseOffset = intermediate.from - conditions.from;
                    for (const auto &pair : intermediate.data) {
                        auto &targetService = results[pair.first];
                        const auto &vector = pair.second;
                        for (int i = 0, iEnd = vector.size(); i < iEnd; ++i) {
                            // check offset
                            int offset = baseOffset + i;
                            if (offset < 0 || offset >= 600) // check overflow / underflow
                                continue;
                            const auto targetVector = vector[i];
                            targetService.bps[offset] += targetVector.bps;
                            for (const auto &ip : targetVector.clientIps) {
                                // determine group name
                                std::string groupName = clientIpGroups.getAlias(ip, 0);
                                if (groupName.empty())
                                    groupName = "Etc."s;
                                ++targetService.activeClients[groupName][offset];
                            }
                        }
                    }
                }
            },
            std::move(intermediates));

        // continue reading more SuperCodex files
        return true;
    });

    // finalize
    if (mergeThread.joinable())
        mergeThread.join();

    return results;
}

ankerl::unordered_dense::map<std::string, std::array<std::pair<uint64_t, uint64_t>, 5>> ServiceDashboard::readPmpi(const std::string &feedName, const uint32_t last, const int32_t chapter, const SuperCodex::IpFilter &ipFilter)
{
    // prepare for results
    ankerl::unordered_dense::map<std::string, std::array<std::pair<uint64_t, uint64_t>, 5>> accumulated; // service name + <value type>
    uint32_t timings[5] = {60, 600, 1800, 3600, 21600}; // 1min, 10min, 30min, 1h, 6h
    size_t index = 0;

    // connect to the database and read records
    FeatherLite feather(CodexIndex::feedRoot + feedName + "/supercache.pmpi"s, SQLITE_OPEN_READONLY);
    feather.prepare("SELECT timestamp,originalsize,filepath FROM rows WHERE timestamp<=? AND chapter=? ORDER BY timestamp DESC;"s);
    feather.bindInt64(1, last);
    feather.bindInt(2, chapter);
    while (feather.next() == SQLITE_ROW) {
        // initialize variables
        SuperCache::PmpiTriplet triplet = SuperCache::getPmpiTriplet(std::string(feather.getText(2)), feather.getInt(1));

        // do stuff with decompressed data
        uint32_t timestamp = feather.getInt64(0);

        // check whether to move index
        if (timestamp <= last - timings[index] && index < 5)
            ++index;

        // check whether to break loop to contiue reading the record
        if (index >= 5) {
            delete[] triplet.decompressedRaw;
            break;
        }

        // read each item in the record and build data
        const size_t skipSize = sizeof(std::pair<FeedRefinerTopN::KeyIpToService, std::pair<uint64_t, uint64_t>>);
        for (auto cursor = triplet.perIpToServiceRaw.data(), cursorEnd = cursor + triplet.perIpToServiceRaw.size(); cursor < cursorEnd; cursor += skipSize) {
            auto itemIpToService = (const std::pair<FeedRefinerTopN::KeyIpToService, std::pair<uint64_t, uint64_t>> *) cursor;
            const auto &key = itemIpToService->first;
            if (key.ipLength != 4 && key.ipLength != 16 && key.ipLength != 0) { // some sanity check
                logger.log("Unexpected IP length("s + std::to_string(key.ipLength) + ") reading "s + std::string(feather.getText(2)));
                continue;
            }
            const std::string ip(key.ip2, key.ipLength);
            std::string serviceName = ipFilter.getAlias(ip, key.port2);
            if (serviceName.empty()) {
                // try again with port=0(any port)
                serviceName = ipFilter.getAlias(ip, 0);
                if (serviceName.empty()) { // try again with other IP
                    std::string ip2(key.ip1, key.ipLength);
                    serviceName = ipFilter.getAlias(ip2, key.port2);
                    if (serviceName.empty())
                        serviceName = ipFilter.getAlias(ip2, key.port2);
                }
            }
            if (!serviceName.empty()) {
                auto &source = itemIpToService->second;
                auto &target = accumulated[serviceName][index];
                target.first += source.first;
                target.second += source.second;
            }
        }
        delete[] triplet.decompressedRaw;
    }

    // fill the rest if there are less than given lookback window
    if (index < 5)
        for (auto &pair : accumulated) {
            const auto &source = pair.second[index];
            for (size_t i = index + 1; i < 5; ++i)
                pair.second[i] = source;
        }

    // finalize
    feather.reset();
    feather.finalize();

    return accumulated;
}

void ServiceDashboard::getSvcd(mg_connection *connection, const std::string &feedName)
{
    std::lock_guard jsonStringsGuard(jsonStringMutex);
    for (const auto &pair : jsonStrings)
        if (feedName == pair.first) { // found matching feed
            Civet7::respond200(connection, pair.second.data(), pair.second.size());
            return;
        }

    // feed not found
    mg_send_http_error(connection, 404, "No such data feed: %s", feedName.data());
}

void ServiceDashboard::postSvcdCips(mg_connection *connection, ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // determine raw data(=source)
    if (!parameters.contains("raw"s)) {
        mg_send_http_error(connection, 400, "Spin7 can't recognize input source. Please check whether Content-Type header is set to 'application/octet-stream'.");
        return;
    }
    const std::string &source = parameters.at("raw"s);

    // do some sanity check
    try {
        // parse JSON
        yyjson_doc *document = yyjson_read(source.data(), source.size(), YYJSON_READ_NOFLAG);
        if (document == nullptr)
            throw "document null";

        // check JSON root
        yyjson_val *rootArray = yyjson_doc_get_root(document);
        if (!yyjson_is_arr(rootArray))
            throw "root is not an array";

        // iterate array
        yyjson_val *element;
        yyjson_arr_iter iter = yyjson_arr_iter_with(rootArray);
        // for each key-value pair......
        while ((element = yyjson_arr_iter_next(&iter))) {
            // check data type
            if (!yyjson_is_obj(element))
                throw "element is not an object";

            // extract name and IPs
            std::string name(yyjson_get_str(yyjson_obj_get(element, "name"))), ips(yyjson_get_str(yyjson_obj_get(element, "ips")));

            // check sanity of the string
            std::istringstream splitter(ips);
            for (std::string ip; std::getline(splitter, ip, ',');) {
                if (!SuperCodex::isValidHexadecimal(ip))
                    throw "failed to decode hexadecimal numbers";
                const size_t elementLength = ip.size();
                if (elementLength != 8 && elementLength != 10 && elementLength != 32 && elementLength != 34)
                    throw "invalid IP length in hex(neither of 8/10/32/34)";
            }
        }
        yyjson_doc_free(document);
        clientIpGroupsMutex.lock();
        std::ofstream file("svcd-cips.json"s, std::ios::trunc);
        file << source;
        clientIpGroupsMutex.unlock();

        // return
        mg_send_http_error(connection, 204, "\r\n\r\n");
    } catch (const char *message) {
        mg_send_http_error(connection, 400, "Failed to parse input data. Details: %s", message);
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to parse input data. Details unknown.");
    }
}

void ServiceDashboard::getSvcdCips(mg_connection *connection)
{
    // read file
    std::string file;
    clientIpGroupsMutex.lock();
    if (std::filesystem::exists("svcd-cips.json"s))
        file = static_cast<std::stringstream const &>(std::stringstream() << std::ifstream("svcd-cips.json"s, std::ifstream::binary).rdbuf()).str();
    clientIpGroupsMutex.unlock();

    // return
    if (file.empty())
        mg_send_http_error(connection, 204, "\r\n\r\n");
    else
        Civet7::respond200(connection, file.data(), file.size());
}

SuperCodex::IpFilter ServiceDashboard::buildClientIpGroups()
{
    SuperCodex::IpFilter result;

    if (std::filesystem::exists("svcd-cips.json"s)) {
        // parse JSON
        clientIpGroupsMutex.lock();
        yyjson_doc *document = yyjson_read_file("svcd-cips.json", YYJSON_READ_NOFLAG, nullptr, nullptr);
        clientIpGroupsMutex.unlock();

        // iterate array
        yyjson_val *element;
        yyjson_arr_iter iter = yyjson_arr_iter_with(yyjson_doc_get_root(document));
        while ((element = yyjson_arr_iter_next(&iter))) { // for each key-value pair......
            // check data type
            if (!yyjson_is_obj(element))
                throw "element is not an object";

            // extract name and IPs
            std::string groupName(yyjson_get_str(yyjson_obj_get(element, "name"))), ips(yyjson_get_str(yyjson_obj_get(element, "ips")));
            std::istringstream splitter(ips);
            for (std::string element; std::getline(splitter, element, ',');)
                result.registerNetwork(element, 0, groupName);
        }
        yyjson_doc_free(document);
    }

    return result;
}
