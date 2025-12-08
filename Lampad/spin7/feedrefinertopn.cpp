#include "feedrefinertopn.h"
#include <filesystem>
#include <fstream>
#include <tbb/parallel_for.h>
#include <tbb/parallel_for_each.h>

#include "civet7.hpp"
#include "codexindex.h"
#include "supercache.h"
#include "../featherlite.h"

// static variables
int64_t FeedRefinerTopN::greedFactorProto = 10000; // determines how many items Top N will retain during the finalization
int64_t FeedRefinerTopNLatencies::rttIgnoreFrom = 10000000000; // 10 seconds

FeedRefinerTopN::FeedRefinerTopN(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerTopN"s);
    greedFactor = greedFactorProto;
    total = new Pack();

    // initialize session store
    sessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();

    // initialize environment based on "base"
    base = conditions.parameters.at("base"s);
    logger.setLogHeader("FeedRefinerTopN/"s + base);
    if (base == "bytes"s) {
        gatherData = &FeedRefinerTopN::gatherBytes;
        cachedChapter = SuperCodex::BPSPERSESSION;
    } else if (base == "packets"s) {
        gatherData = &FeedRefinerTopN::gatherPackets;
        cachedChapter = SuperCodex::PPSPERSESSION;
    } else if (base == "timeouts"s) {
        gatherData = &FeedRefinerTopN::gatherTimeouts;
        cachedChapter = SuperCodex::TIMEOUTS;
    } else if (base == "tcprsts"s) {
        gatherData = &FeedRefinerTopN::gatherTcpRsts;
        cachedChapter = SuperCodex::TCPRSTS;
    } else if (base == "tcpdupacks"s) {
        gatherData = &FeedRefinerTopN::gatherTcpDupAcks;
        cachedChapter = SuperCodex::TCPDUPACKS;
    } else if (base == "tcpzerowindows"s) {
        gatherData = &FeedRefinerTopN::gatherTcpZeroWindows;
        cachedChapter = static_cast<SuperCodex::ChapterType>(SuperCodex::TCPMISCANOMALIES + MA_TCPZEROWINDOW);
    } else if (base == "tcpretransmissions"s) {
        gatherData = &FeedRefinerTopN::gatherTcpRetransmissions;
        cachedChapter = SuperCodex::TCPRETRANSMISSIONS;
    } else if (base == "tcpportsreused"s) {
        gatherData = &FeedRefinerTopN::gatherTcpPortsReused;
        cachedChapter = static_cast<SuperCodex::ChapterType>(SuperCodex::TCPMISCANOMALIES + MA_TCPPORTSREUSED);
    } else if (base == "tcpoutoforders"s) {
        gatherData = &FeedRefinerTopN::gatherTcpOutOfOrders;
        cachedChapter = static_cast<SuperCodex::ChapterType>(SuperCodex::TCPMISCANOMALIES + MA_TCPOUTOFORDER);
    } else
        return; // do nothing for any unknown bases

    // check whether SuperCache is applicable
    if (conditions.mplsLabels.empty() && conditions.vlanQTags.empty()) { // preprequsite: no MPLS labels and VLAN tag filter
        if (conditions.allowedIps.isEmpty && conditions.payloadProtocol == 0 && conditions.l7Protocol == SuperCodex::Session::NOL7DETECTED && conditions.ports.empty())
            pmpiCacheMode = FULL;
        else
            pmpiCacheMode = FILTERED;
    }
    if (pmpiCacheMode == NONE)
        logger.log("SuperCache unapplicable");
    else {
        superCachePath = CodexIndex::feedRoot + conditions.dataFeed + SuperCache::dbs[1];
        logger.log("SuperCache applicable");
    }
}

void FeedRefinerTopN::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    // merge session information
    for (const auto &codex : codices)
        for (const auto &pair : codex->sessions)
            updateTimestampAndMergeIndividualSession(*pair.second);

    // gather raw data in parallel and merge (counts built per source / destination / IP-to-service)
    if (gatherData == nullptr)
        return;
    std::vector<Pack> resultParts = SuperCodex::parallel_convert<SuperCodex::Loader *, Pack>(codices, [&](const SuperCodex::Loader *codex) -> Pack { return std::invoke(gatherData, this, codex); }, affinityPartitioner);

    // merge
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Pack> resultRawsFuture) {
            // merge to total
            std::vector<std::thread> synchronizer;
            synchronizer.push_back(std::thread([&]() {
                // merge data
                for (const auto &intermediary : resultRawsFuture)
                    for (const auto &pair : intermediary.perSource)
                        total->perSource[pair.first] += pair.second;

                // remove long tails
                if (total->perSource.size() > greedFactor * 2) {
                    auto ranking = buildRanking(total->perSource);
                    ranking.resize(greedFactor);
                    total->perSource.replace(std::move(ranking));
                }
            }));
            synchronizer.push_back(std::thread([&]() {
                // merge data
                for (const auto &intermediary : resultRawsFuture)
                    for (const auto &pair : intermediary.perDestination)
                        total->perDestination[pair.first] += pair.second;

                // remove long tails
                if (total->perDestination.size() > greedFactor * 2) {
                    auto ranking = buildRanking(total->perDestination);
                    ranking.resize(greedFactor);
                    total->perDestination.replace(std::move(ranking));
                }
            }));
            synchronizer.push_back(std::thread([&]() {
                // merge data
                for (const auto &intermediary : resultRawsFuture)
                    for (const auto &pair : intermediary.perIpToService)
                        total->perIpToService[pair.first] += pair.second;

                // remove long tails
                if (total->perIpToService.size() > greedFactor * 2) {
                    auto ranking = buildRankingIpToService(total->perIpToService);
                    ranking.resize(greedFactor);
                    total->perIpToService.replace(std::move(ranking));
                }
            }));
            for (auto &thread : synchronizer)
                thread.join();
        },
        std::move(resultParts));
}

std::vector<std::pair<FeedRefinerTopN::KeySingle, FeedRefinerTopN::Description>> FeedRefinerTopN::buildRanking(const ankerl::unordered_dense::map<KeySingle, Description, KeySingleHash, KeySingleEqual> &map)
{
    std::vector<std::pair<KeySingle, Description>> result = map.values();
    std::sort(result.begin(), result.end(), [](const std::pair<KeySingle, Description> &a, const std::pair<KeySingle, Description> &b) { return a.second.value > b.second.value; });
    return result;
}

std::vector<std::pair<FeedRefinerTopN::KeyIpToService, FeedRefinerTopN::Description>> FeedRefinerTopN::buildRankingIpToService(const ankerl::unordered_dense::map<KeyIpToService, FeedRefinerTopN::Description, KeyIpToServiceHash, KeyIpToServiceEqual> &map)
{
    std::vector<std::pair<FeedRefinerTopN::KeyIpToService, Description>> result = map.values();
    std::sort(result.begin(), result.end(), [](const std::pair<KeyIpToService, Description> &a, const std::pair<KeyIpToService, Description> &b) { return a.second.value > b.second.value; });

    return result;
}

void FeedRefinerTopN::finalize()
{
    // fill SuperCache data for "value" and (optionally) "value2"
    std::vector<Pack> cached;
    auto &perSource = total->perSource;
    auto &perDestination = total->perDestination;
    auto &perIpToService = total->perIpToService;
    if (pmpiCacheMode != NONE && conditions.cacheFrom) {
        if (base == "bytes"s || base == "packets"s) {
            cached = mergeSuperCache<Pack>(cachedChapter, [&](const std::string_view &perSourceRaw, const std::string_view &perDestinationRaw, const std::string_view &perIpToServiceRaw, Pack &pack) { mergeCacheSingle(perSourceRaw, perDestinationRaw, perIpToServiceRaw, pack); });
            for (const auto &pack : cached) {
                for (const auto &pair : pack.perSource)
                    perSource[pair.first].value += pair.second.value;
                for (const auto &pair : pack.perDestination)
                    perDestination[pair.first].value += pair.second.value;
                for (const auto &pair : pack.perIpToService)
                    perIpToService[pair.first].value += pair.second.value;
            }
        } else {
            cached = mergeSuperCache<Pack>(cachedChapter, [&](const std::string_view &perSourceRaw, const std::string_view &perDestinationRaw, const std::string_view &perIpToServiceRaw, Pack &pack) { mergeCachePair(perSourceRaw, perDestinationRaw, perIpToServiceRaw, pack); });
            for (const auto &pack : cached) {
                for (const auto &pair : pack.perSource) {
                    auto &target = perSource[pair.first];
                    target.value += pair.second.value;
                    target.value2 += pair.second.value2;
                }
                for (const auto &pair : pack.perDestination) {
                    auto &target = perDestination[pair.first];
                    target.value += pair.second.value;
                    target.value2 += pair.second.value2;
                }
                for (const auto &pair : pack.perIpToService) {
                    auto &target = perIpToService[pair.first];
                    target.value += pair.second.value;
                    target.value2 += pair.second.value2;
                }
            }
        }
    }

    // fill "value2" per base if base is "bytes" or "packets"
    if (base == "bytes"s || base == "packets"s) { // "value2" is volume of total transaction (unit: bytes or packets)
        // calculate sum
        uint64_t sumPerSource = 0, sumPerDestination = 0, sumPerIpToService = 0;
        for (const auto &pair : total->perSource)
            sumPerSource += pair.second.value;
        for (const auto &pair : total->perDestination)
            sumPerDestination += pair.second.value;
        for (const auto &pair : total->perIpToService)
            sumPerIpToService += pair.second.value;

        // put sum to all the records
        for (auto &pair : total->perSource)
            pair.second.value2 = sumPerSource;
        for (auto &pair : total->perDestination)
            pair.second.value2 = sumPerDestination;
        for (auto &pair : total->perIpToService)
            pair.second.value2 = sumPerIpToService;
    } else if (base == "timeouts"s || base == "tcpportsreused"s) { // "value2" is number of sessions for each record
        for (const auto &pair : *sessions) {
            const auto keyIpToService = keyIpToServiceFromSession(pair.second);
            ++total->perIpToService[keyIpToService].value2;
            ++total->perSource[sourceFromIpToService(keyIpToService)].value2;
            ++total->perDestination[destinationFromIpToService(keyIpToService)].value2;
        }

        // timed out sessions can't exist in the "sessions" so they must be counted separately
        if (base == "timeouts"s) {
            for (auto &pair : total->perSource)
                pair.second.value2 += pair.second.value;
            for (auto &pair : total->perDestination)
                pair.second.value2 += pair.second.value;
            for (auto &pair : total->perIpToService)
                pair.second.value2 += pair.second.value;
        }
    } else {
        // dirty hack: if value is bigger than value2, add value to value2. It occurs only in TCP retransmission
        for (auto &pair : total->perSource) {
            auto &values = pair.second;
            if (values.value > values.value2)
                values.value2 += values.value;
        }
        for (auto &pair : total->perDestination) {
            auto &values = pair.second;
            if (values.value > values.value2)
                values.value2 += values.value;
        }
        for (auto &pair : total->perIpToService) {
            auto &values = pair.second;
            if (values.value > values.value2)
                values.value2 += values.value;
        }
    }

    // exception handling
    if (total->perSource.empty()) { // there's no data
        std::ofstream dummyS(messyRoomPrefix + "/result_s"s), dummyD(messyRoomPrefix + "/result_d"s), dummyI(messyRoomPrefix + "/result_i"s);
        logger.log("No data. Falling back.");
        return;
    }

    // build and save ranking
    std::vector<std::thread> synchronizer;
    synchronizer.push_back(std::thread([&] { // per source
        saveRanking(buildRanking(total->perSource), messyRoomPrefix + "/result_s"s);
    }));
    synchronizer.push_back(std::thread([&] { // per destination
        saveRanking(buildRanking(total->perDestination), messyRoomPrefix + "/result_d"s);
    }));
    synchronizer.push_back(std::thread([&] { // per IP to Service
        saveRanking(buildRankingIpToService(total->perIpToService), messyRoomPrefix + "/result_i"s);
    }));
    for (auto &future : synchronizer)
        future.join();

    // prepare for log
    sizePerSource = total->perSource.size();
    sizePerDestination = total->perDestination.size();
    sizePerIpToService = total->perIpToService.size();

    // finalize
    delete total;
    logger.log("Results ready to serve: "s + std::to_string(sizePerSource) + " / "s + std::to_string(sizePerDestination) + " / "s + std::to_string(sizePerIpToService));
}

FeedRefinerTopN::KeyIpToService FeedRefinerTopN::keyIpToServiceFromSession(const SuperCodex::Session &session)
{
    KeyIpToService result{};
    result.ipLength = SuperCodex::ipLength(session.etherType);
    memcpy(result.ip1, session.ips, result.ipLength);
    memcpy(result.ip2, session.ips + result.ipLength, result.ipLength);
    result.port2 = session.destinationPort;
    result.direction = 1;
    result.payloadProtocol = session.payloadProtocol;
    result.detectedL7 = session.detectedL7;

    return result;
}

FeedRefinerTopN::KeySingle FeedRefinerTopN::sourceFromIpToService(const FeedRefinerTopN::KeyIpToService &key)
{
    KeySingle result{};
    result.port = 0;
    result.ipLength = key.ipLength;
    memcpy(result.ip, key.ip1, result.ipLength);
    return result;
}
FeedRefinerTopN::KeySingle FeedRefinerTopN::destinationFromIpToService(const FeedRefinerTopN::KeyIpToService &key)
{
    KeySingle result{};
    result.port = key.port2;
    result.ipLength = key.ipLength;
    memcpy(result.ip, key.ip2, result.ipLength);
    return result;
}

template<typename T> void FeedRefinerTopN::saveRanking(const std::vector<T> &ranking, const std::string &fileName)
{
    std::ofstream file(fileName, std::ios::out | std::ios::binary | std::ios::trunc);
    file.write((const char *) ranking.data(), sizeof(T) * ranking.size());
    file.close();
}

template<typename T> void FeedRefinerTopN::processResultFile(const std::string &fileName, std::function<bool(const T &content)> process)
{
    // objects to read from file
    T content;
    constexpr size_t contentSize = sizeof(T);
    std::ifstream file(fileName, std::ios::binary);
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);

    // read first record
    file.read((char *) &content, contentSize);
    while (file.gcount()) {
        // process with read record
        if (!process(content))
            break;

        // read next content
        file.read((char *) &content, contentSize);
    }
    file.close();
}

void FeedRefinerTopN::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    if (bindValue == -1) { // gather data per L7 protocol
        // initialize some variables
        ankerl::unordered_dense::map<int, uint64_t> organizer;
        processResultFile<std::pair<KeyIpToService, Description>>(messyRoomPrefix + "/result_i"s, [&](const std::pair<KeyIpToService, Description> &content) -> bool {
            const auto &key = content.first;
            const auto &values = content.second;
            const auto &detectedL7 = key.detectedL7;
            if (key.detectedL7 != SuperCodex::Session::NOL7DETECTED)
                organizer[key.detectedL7] += values.value;
            else {
                if (key.payloadProtocol == 6 || // TCP
                    key.payloadProtocol == 17 || // UDP
                    key.payloadProtocol == 1 || // ICMP
                    key.payloadProtocol == 58 // ICMPv6
                )
                    organizer[key.payloadProtocol * -1] += values.value;
                else // non-IP protocol
                    organizer[INT32_MIN] += values.value;
            }

            return true;
        });

        // sort result
        auto hits = organizer.values();
        std::sort(hits.begin(), hits.end(), [](const std::pair<int, uint64_t> &a, const std::pair<int, uint64_t> &b) -> bool { return a.second > b.second; });

        // build result
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);
        for (const auto &pair : hits) {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_add_val(rootArray, object);
            // determine protocol name
            if (pair.first < 0) // "other L4 protocols or non-IP"
                switch (pair.first) {
                case -1:
                    yyjson_mut_obj_add_strn(document, object, "protocol", "ICMP", 4);
                    break;
                case -6:
                    yyjson_mut_obj_add_strn(document, object, "protocol", "TCP", 3);
                    break;
                case -17:
                    yyjson_mut_obj_add_strn(document, object, "protocol", "UDP", 3);
                    break;
                case -58:
                    yyjson_mut_obj_add_strn(document, object, "protocol", "ICMPv6", 6);
                    break;
                case INT32_MIN:
                    yyjson_mut_obj_add_strn(document, object, "protocol", "non-IP", 6);
                    break;
                default:
                    yyjson_mut_obj_add_strn(document, object, "protocol", "Unknown", 7);
                    break;
                }
            else {
                std::string l7ProtocolString = SuperCodex::l7ProtocolToString(static_cast<SuperCodex::Session::L7Protocol>(pair.first));
                yyjson_mut_obj_add_strncpy(document, object, "protocol", l7ProtocolString.data(), l7ProtocolString.size());
            }

            // set value
            yyjson_mut_obj_add_uint(document, object, "value", pair.second);
        }

        // return result
        if (connection)
            Civet7::respond200(connection, document);
        else
            lastInterativeResult = document;
    } else { // work normally
        auto document = resultsInteractive(from, to, bindValue, parameters);
        if (connection)
            Civet7::respond200(connection, document);
        else
            lastInterativeResult = document;
    }
}

yyjson_mut_doc *FeedRefinerTopN::resultsInteractive(uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // prepare for variables
    int rankCursor;
    SubSystems::FqdnGetter getter;

    // prepare for JSON writer
    std::string temp;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);
    yyjson_mut_obj_add_strn(document, rootObject, "base", base.data(), base.size());

    // rank per source
    rankCursor = 1;
    yyjson_mut_val *perSourceArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "persource", perSourceArray);
    processResultFile<std::pair<KeySingle, Description>>(messyRoomPrefix + "/result_s"s, [&](const std::pair<KeySingle, Description> &content) -> bool {
        const auto &key = content.first;
        const auto &values = content.second;

        if (key.ipLength == 4 || key.ipLength == 16) {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(perSourceArray, object);

            // write
            yyjson_mut_val *ipObject = yyjson_mut_obj(document);
            yyjson_mut_obj_add_val(document, object, "ip", ipObject);
            describeEdge(getter, document, ipObject, std::string((const char *) key.ip, key.ipLength));
            yyjson_mut_obj_add_int(document, object, "value", values.value);
            yyjson_mut_obj_add_int(document, object, "value2", values.value2);

            // check edge
            if (bindValue && rankCursor < bindValue) {
                ++rankCursor;
                return true;
            } else
                return false;
        } else {
            logger.oops("Skip key with invalid IP length: "s + std::to_string(key.ipLength));
            return true; // continue reading next rank
        }
    });

    // rank per destination
    rankCursor = 1;
    yyjson_mut_val *perDestinationArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "perdestination", perDestinationArray);
    processResultFile<std::pair<KeySingle, Description>>(messyRoomPrefix + "/result_d"s, [&](const std::pair<KeySingle, Description> &content) -> bool {
        const auto &key = content.first;
        const auto &values = content.second;

        if (key.ipLength == 4 || key.ipLength == 16) {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(perDestinationArray, object);

            // write
            yyjson_mut_val *ipObject = yyjson_mut_obj(document);
            yyjson_mut_obj_add_val(document, object, "ip", ipObject);
            describeEdge(getter, document, ipObject, std::string((const char *) key.ip, key.ipLength), key.port);
            yyjson_mut_obj_add_int(document, object, "value", values.value);
            yyjson_mut_obj_add_int(document, object, "value2", values.value2);

            // check edge
            if (bindValue && rankCursor < bindValue) {
                ++rankCursor;
                return true;
            } else
                return false;
        } else {
            logger.oops("Skip key with invalid IP length: "s + std::to_string(key.ipLength));
            return true; // continue reading next rank
        }
    });

    // rank per IP to service
    rankCursor = 1;
    yyjson_mut_val *perIpToServiceArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "periptoservice", perIpToServiceArray);
    processResultFile<std::pair<KeyIpToService, Description>>(messyRoomPrefix + "/result_i"s, [&](const std::pair<KeyIpToService, Description> &content) -> bool {
        const auto &key = content.first;
        const auto &values = content.second;

        if (key.ipLength == 4 || key.ipLength == 16) {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(perIpToServiceArray, object);

            // check sanity if IP length
            // write
            if (key.direction == 1) { // direction: client to server
                yyjson_mut_val *ipObject = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "ip", ipObject);
                describeEdge(getter, document, ipObject, std::string(key.ip1, key.ipLength));
                yyjson_mut_val *ip2Object = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "ip2", ip2Object);
                describeEdge(getter, document, ip2Object, std::string(key.ip2, key.ipLength), key.port2);
            } else {
                yyjson_mut_val *ipObject = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "ip", ipObject);
                describeEdge(getter, document, ipObject, std::string(key.ip2, key.ipLength), key.port2);
                yyjson_mut_val *ip2Object = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "ip2", ip2Object);
                describeEdge(getter, document, ip2Object, std::string(key.ip1, key.ipLength));
            }

            switch (key.payloadProtocol) {
            case 6:
                yyjson_mut_obj_add_strn(document, object, "payloadprotocol", "tcp", 3);
                break;
            case 17:
                yyjson_mut_obj_add_strn(document, object, "payloadprotocol", "udp", 3);
                break;
            default:
                yyjson_mut_obj_add_strn(document, object, "payloadprotocol", "other", 5);
                break;
            }
            temp = SuperCodex::l7ProtocolToString(key.detectedL7);
            yyjson_mut_obj_add_strncpy(document, object, "l7protocol", temp.data(), temp.size());
            yyjson_mut_obj_add_int(document, object, "value", values.value);
            yyjson_mut_obj_add_int(document, object, "value2", values.value2);

            // check tail
            if (bindValue && rankCursor < bindValue) {
                ++rankCursor;
                return true;
            } else
                return false;
        } else {
            logger.oops("Skip key with invalid IP length: "s + std::to_string(key.ipLength));
            return true; // continue reading next rank
        }
    });

    // return result
    return document;
}

void FeedRefinerTopN::dumpResults(mg_connection *connection)
{
    // prepare for store
    SubSystems::FqdnGetter getter;
    std::string chunk;
    chunk.reserve(110000000); // 110 MB
    chunk.append("Duration: "s).append(epochToIsoDate(secondStart) + " ~ "s + epochToIsoDate(secondEnd) + '\n').append("base: "s + base + "\n\n"s);
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // rank per source
    chunk.append("Per Source>\nIP\tTag\tServices\tValue\tValue2\n"s);
    processResultFile<std::pair<KeySingle, Description>>(messyRoomPrefix + "/result_s"s, [&](const std::pair<KeySingle, Description> &content) -> bool {
        describeEdge(getter, chunk, std::string((const char *) content.first.ip, content.first.ipLength));
        chunk.pop_back(); // remove redundant '\t' which separates field for port
        chunk.append(std::to_string(content.second.value) + '\t').append(std::to_string(content.second.value2)).push_back('\n');

        // flush chunk if its size is over 100MB
        if (chunk.size() > 100000000) {
            switch (mg_send_chunk(connection, chunk.data(), chunk.size())) {
            case 0:
                logger.log("Client closed socket. Cancelling operation."s);
                return false;
            case -1:
                logger.log("Server encountered an error. Cancelling operation."s);
                return false;
            default:
                chunk.clear();
            }
        }

        return true;
    });

    // rank per destination
    chunk.append("========================================\n\nPer Destination>\nIP\tTags\tServices\tPort\tValue\tValue2\n"s);
    processResultFile<std::pair<KeySingle, Description>>(messyRoomPrefix + "/result_d"s, [&](const std::pair<KeySingle, Description> &content) -> bool {
        const auto &key = content.first;
        const auto &values = content.second;

        // write
        describeEdge(getter, chunk, std::string((const char *) key.ip, key.ipLength), key.port);
        chunk.append(std::to_string(values.value) + '\t').append(std::to_string(values.value2)).push_back('\n');

        // flush chunk if its size is over 100MB
        if (chunk.size() > 100000000) {
            switch (mg_send_chunk(connection, chunk.data(), chunk.size())) {
            case 0:
                logger.log("Client closed socket. Cancelling operation."s);
                return false;
            case -1:
                logger.log("Server encountered an error. Cancelling operation."s);
                return false;
            default:
                chunk.clear();
            }
        }

        return true;
    });

    // rank per IP to service
    chunk.append("========================================\n\nPer IP to Service>\nSourceIP\tSourceTag\tSourceServices\tSourcePort\tDestinationIP\tDestinationTag\tDestinationServices\tDestinationPort\tPayloadProtocol\tL7Protocol\tValue\tValue2\n"s);
    processResultFile<std::pair<KeyIpToService, Description>>(messyRoomPrefix + "/result_i"s, [&](const std::pair<KeyIpToService, Description> &content) -> bool {
        const auto &key = content.first;
        const auto &values = content.second;

        // write
        if (key.direction == 1) { // client to server
            describeEdge(getter, chunk, std::string(key.ip1, key.ipLength));
            describeEdge(getter, chunk, std::string(key.ip2, key.ipLength), key.port2);
        } else { // server to client
            describeEdge(getter, chunk, std::string(key.ip2, key.ipLength), key.port2);
            describeEdge(getter, chunk, std::string(key.ip1, key.ipLength));
        }
        chunk.append(std::to_string(key.payloadProtocol) + '\t').append(SuperCodex::l7ProtocolToString(key.detectedL7) + '\t').append(std::to_string(values.value) + '\t').append(std::to_string(values.value2)).push_back('\n');

        // flush chunk if its size is over 100MB
        if (chunk.size() > 100000000) {
            switch (mg_send_chunk(connection, chunk.data(), chunk.size())) {
            case 0:
                logger.log("Client closed socket. Cancelling operation."s);
                return false;
            case -1:
                logger.log("Server encountered an error. Cancelling operation."s);
                return false;
            default:
                chunk.clear();
            }
        }

        return true;
    });

    // send final chunks
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

FeedRefinerTopN::Pack FeedRefinerTopN::gatherBytes(const SuperCodex::Loader *codex)
{
    Pack pack;

    for (auto *bps = codex->firstBpsPerSession(); bps; bps = codex->nextBpsPerSession(bps)) {
        const auto session = sessions->at(bps->sessionId);
        auto key = keyIpToServiceFromSession(session);
        // IP-to-service
        if (session.sourceIsSmall) {
            pack.perIpToService[key].value += bps->fromSmallToBig;
            key.direction = 0;
            pack.perIpToService[key].value += bps->fromBigToSmall;
        } else {
            pack.perIpToService[key].value += bps->fromBigToSmall;
            key.direction = 0;
            pack.perIpToService[key].value += bps->fromSmallToBig;
        }

        // single
        auto sum = bps->fromSmallToBig + bps->fromBigToSmall;
        pack.perSource[sourceFromIpToService(key)].value += sum;
        pack.perDestination[sourceFromIpToService(key)].value += sum;
    }

    return pack;
}

FeedRefinerTopN::Pack FeedRefinerTopN::gatherPackets(const SuperCodex::Loader *codex)
{
    Pack pack;

    for (auto *pps = codex->firstPpsPerSession(); pps; pps = codex->nextPpsPerSession(pps)) {
        const auto session = sessions->at(pps->sessionId);
        auto key = keyIpToServiceFromSession(session);
        // IP-to-service
        if (session.sourceIsSmall) {
            pack.perIpToService[key].value += pps->fromSmallToBig;
            key.direction = 0;
            pack.perIpToService[key].value += pps->fromBigToSmall;
        } else {
            pack.perIpToService[key].value += pps->fromBigToSmall;
            key.direction = 0;
            pack.perIpToService[key].value += pps->fromSmallToBig;
        }

        // single
        auto sum = pps->fromSmallToBig + pps->fromBigToSmall;
        pack.perSource[sourceFromIpToService(key)].value += sum;
        pack.perDestination[sourceFromIpToService(key)].value += sum;
    }

    return pack;
}

FeedRefinerTopN::Pack FeedRefinerTopN::gatherTimeouts(const SuperCodex::Loader *codex)
{
    Pack pack;

    // note: each timeout has its own session data
    for (auto timeout = codex->firstTimeout(); timeout; timeout = codex->nextTimeout(timeout)) {
        auto key = keyIpToServiceFromSession(timeout->session);
        if (codex->sessionAccepted(&timeout->session)) {
            ++pack.perIpToService[key].value;
            ++pack.perSource[sourceFromIpToService(key)].value;
            ++pack.perDestination[destinationFromIpToService(key)].value;
        }
    }

    return pack;
}

FeedRefinerTopN::Pack FeedRefinerTopN::gatherTcpRsts(const SuperCodex::Loader *codex)
{
    Pack pack;

    for (auto marker = codex->firstTcpRst(); marker; marker = codex->nextTcpRst(marker)) {
        auto session = sessions->at(marker->sessionId);
        auto key = keyIpToServiceFromSession(session);
        if (session.sourceIsSmall != marker->fromSmallToBig)
            key.direction = 0;
        ++pack.perIpToService[key].value;
        ++pack.perSource[sourceFromIpToService(key)].value;
        ++pack.perDestination[destinationFromIpToService(key)].value;
    }
    fillPpsIpToService(codex, pack.perIpToService);
    fillPpsSource(codex, pack.perSource, true);
    fillPpsSource(codex, pack.perDestination, false);

    return pack;
}

FeedRefinerTopN::Pack FeedRefinerTopN::gatherTcpDupAcks(const SuperCodex::Loader *codex)
{
    Pack pack;

    for (auto marker = codex->firstTcpDupAck(); marker; marker = codex->nextTcpDupAck(marker)) {
        auto session = sessions->at(marker->sessionId);
        auto key = keyIpToServiceFromSession(session);
        if (session.sourceIsSmall != marker->fromSmallToBig)
            key.direction = 0;
        ++pack.perIpToService[key].value;
        ++pack.perSource[sourceFromIpToService(key)].value;
        ++pack.perDestination[destinationFromIpToService(key)].value;
    }
    fillPpsIpToService(codex, pack.perIpToService);
    fillPpsSource(codex, pack.perSource, true);
    fillPpsSource(codex, pack.perDestination, false);

    return pack;
}

FeedRefinerTopN::Pack FeedRefinerTopN::gatherTcpZeroWindows(const SuperCodex::Loader *codex)
{
    Pack pack;

    for (auto marker = codex->firstTcpMiscAnomaly(); marker; marker = codex->nextTcpMiscAnomaly(marker))
        if (marker->tail == MA_TCPZEROWINDOW) {
            auto session = sessions->at(marker->sessionId);
            auto key = keyIpToServiceFromSession(session);
            if (session.sourceIsSmall != marker->fromSmallToBig)
                key.direction = 0;
            ++pack.perIpToService[key].value;
            ++pack.perSource[sourceFromIpToService(key)].value;
            ++pack.perDestination[destinationFromIpToService(key)].value;
        }
    fillPpsIpToService(codex, pack.perIpToService);
    fillPpsSource(codex, pack.perSource, true);
    fillPpsSource(codex, pack.perDestination, false);

    return pack;
}

FeedRefinerTopN::Pack FeedRefinerTopN::gatherTcpRetransmissions(const SuperCodex::Loader *codex)
{
    Pack pack;

    for (auto marker = codex->firstTcpRetransmission(); marker; marker = codex->nextTcpRetransmission(marker)) {
        auto session = sessions->at(marker->sessionId);
        auto key = keyIpToServiceFromSession(session);
        if (session.sourceIsSmall != marker->fromSmallToBig)
            key.direction = 0;
        ++pack.perIpToService[key].value;
        ++pack.perSource[sourceFromIpToService(key)].value;
        ++pack.perDestination[destinationFromIpToService(key)].value;
    }
    fillPpsIpToService(codex, pack.perIpToService);
    fillPpsSource(codex, pack.perSource, true);
    fillPpsSource(codex, pack.perDestination, false);

    return pack;
}

FeedRefinerTopN::Pack FeedRefinerTopN::gatherTcpOutOfOrders(const SuperCodex::Loader *codex)
{
    Pack pack;

    for (auto marker = codex->firstTcpMiscAnomaly(); marker; marker = codex->nextTcpMiscAnomaly(marker))
        if (marker->tail == MA_TCPOUTOFORDER) {
            auto session = sessions->at(marker->sessionId);
            auto key = keyIpToServiceFromSession(session);
            if (session.sourceIsSmall != marker->fromSmallToBig)
                key.direction = 0;
            ++pack.perIpToService[key].value;
            ++pack.perSource[sourceFromIpToService(key)].value;
            ++pack.perDestination[destinationFromIpToService(key)].value;
        }
    fillPpsIpToService(codex, pack.perIpToService);
    fillPpsSource(codex, pack.perSource, true);
    fillPpsSource(codex, pack.perDestination, false);

    return pack;
}

FeedRefinerTopN::Pack FeedRefinerTopN::gatherTcpPortsReused(const SuperCodex::Loader *codex)
{
    Pack pack;

    for (auto marker = codex->firstTcpMiscAnomaly(); marker; marker = codex->nextTcpMiscAnomaly(marker))
        if (marker->tail == MA_TCPPORTSREUSED) {
            auto session = sessions->at(marker->sessionId);
            auto key = keyIpToServiceFromSession(session);
            if (session.sourceIsSmall != marker->fromSmallToBig)
                key.direction = 0;
            ++pack.perIpToService[key].value;
            ++pack.perSource[sourceFromIpToService(key)].value;
            ++pack.perDestination[destinationFromIpToService(key)].value;
        }
    fillPpsIpToService(codex, pack.perIpToService);
    fillPpsSource(codex, pack.perSource, true);
    fillPpsSource(codex, pack.perDestination, false);

    return pack;
}

void FeedRefinerTopN::fillPpsSource(const SuperCodex::Loader *codex, ankerl::unordered_dense::map<KeySingle, Description, KeySingleHash, KeySingleEqual> &map, const bool isSource)
{
    for (auto pps = codex->firstPpsPerSession(); pps; pps = codex->nextPpsPerSession(pps)) {
        // build Key
        const auto &session = sessions->at(pps->sessionId);
        KeySingle key{};
        key.ipLength = SuperCodex::ipLength(session.etherType);
        if (isSource)
            memcpy(key.ip, session.ips, key.ipLength);
        else
            memcpy(key.ip, session.ips + key.ipLength, key.ipLength);

        // fill PPS
        if (map.contains(key))
            map[key].value2 += pps->fromSmallToBig + pps->fromBigToSmall;
    }
}

void FeedRefinerTopN::fillPpsIpToService(const SuperCodex::Loader *codex, ankerl::unordered_dense::map<KeyIpToService, Description, KeyIpToServiceHash, KeyIpToServiceEqual> &map)
{
    for (auto pps = codex->firstPpsPerSession(); pps; pps = codex->nextPpsPerSession(pps)) {
        auto session = sessions->at(pps->sessionId);
        auto key = keyIpToServiceFromSession(session);

        // check record for client to server
        if (map.contains(key)) {
            if (session.sourceIsSmall)
                map[key].value2 += pps->fromSmallToBig;
            else
                map[key].value2 += pps->fromBigToSmall;
        }

        // check record for server to client
        key.direction = 0;
        if (map.contains(key)) {
            if (session.sourceIsSmall)
                map[key].value2 += pps->fromBigToSmall;
            else
                map[key].value2 += pps->fromSmallToBig;
        }
    }
}

template<typename T> std::vector<T> FeedRefinerTopN::mergeSuperCache(const int chapterType, std::function<void(const std::string_view &, const std::string_view &, const std::string_view &, T &)> toMerge)
{
    // build duration vector
    struct Segment
    {
        uint32_t from, to;
    };
    std::vector<Segment> timestamps;
    const uint32_t interval = 3600;
    for (uint32_t i = conditions.cacheFrom; i < conditions.cacheTo; i += interval)
        timestamps.push_back(Segment{i, i + interval - 1});
    timestamps.back().to = conditions.cacheTo;

    // query in parallel
    return SuperCodex::parallel_convert<Segment, T>(timestamps, [&](const Segment &segment) -> T {
        T result;

        // query database
        FeatherLite feather(CodexIndex::feedRoot + conditions.dataFeed + "/supercache.pmpi"s, SQLITE_OPEN_READONLY);
        feather.prepare("SELECT originalsize,filepath FROM rows WHERE timestamp>=? AND timestamp<=? AND chapter=?;"s);
        feather.bindInt(1, segment.from);
        feather.bindInt(2, segment.to);
        feather.bindInt(3, chapterType);

        while (feather.next() == SQLITE_ROW) {
            auto pmpiTriplet = SuperCache::getPmpiTriplet(std::string(feather.getText(1)), feather.getInt(0));
            if (pmpiTriplet.decompressedRaw == nullptr)
                continue;
            toMerge(pmpiTriplet.perSourceRaw, pmpiTriplet.perDestinationRaw, pmpiTriplet.perIpToServiceRaw, result);
            delete[] pmpiTriplet.decompressedRaw;
        }

        // finalize
        feather.reset();
        feather.finalize();
        return result;
    });
}

void FeedRefinerTopN::mergeCacheSingle(const std::string_view &perSourceRaw, const std::string_view &perDestinationRaw, const std::string_view &perIpToServiceRaw, Pack &pack)
{
    // prepare for variables and shortcuts
    const std::pair<FeedRefinerTopN::KeySingle, uint64_t> *item;
    int appliedCounter;
    auto &perSource = pack.perSource;
    auto &perDestination = pack.perDestination;
    auto &perIpToService = pack.perIpToService;
    auto ipToServiceFilter = KeyIpToServiceFilter(conditions);

    // per source
    appliedCounter = 0;
    switch (pmpiCacheMode) {
    case FULL:
        for (const char *cursor = perSourceRaw.data(), *cursorEnd = cursor + perSourceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle) {
            item = (const std::pair<FeedRefinerTopN::KeySingle, uint64_t> *) cursor;
            perSource[item->first].value += item->second;
            ++appliedCounter;

            // check breakpoint
            if (appliedCounter > greedFactor)
                break;
        }
        break;
    case FILTERED:
        if (ipToServiceFilter.isIpFilterOnly && conditions.includeExternalTransfer)
            for (const char *cursor = perSourceRaw.data(), *cursorEnd = cursor + perSourceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle) {
                item = (const std::pair<FeedRefinerTopN::KeySingle, uint64_t> *) cursor;
                if (conditions.allowedIps.contains(std::string((const char *) item->first.ip, item->first.ipLength))) {
                    perSource[item->first].value += item->second;
                    ++appliedCounter;
                }

                // check breakpoint
                if (appliedCounter > greedFactor)
                    break;
            }
        break;
    }
    if (perSource.size() > greedFactor * 2) {
        auto ranking = buildRanking(perSource);
        ranking.resize(greedFactor);
        perSource.replace(std::move(ranking));
    }

    // per destination
    appliedCounter = 0;
    switch (pmpiCacheMode) {
    case FULL:
        for (const char *cursor = perDestinationRaw.data(), *cursorEnd = cursor + perDestinationRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle) {
            item = (const std::pair<FeedRefinerTopN::KeySingle, uint64_t> *) cursor;
            perDestination[item->first].value += item->second;
            ++appliedCounter;

            // check breakpoint
            if (appliedCounter > greedFactor)
                break;
        }
        break;
    case FILTERED:
        if (ipToServiceFilter.isIpFilterOnly && conditions.includeExternalTransfer)
            for (const char *cursor = perDestinationRaw.data(), *cursorEnd = cursor + perDestinationRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle) {
                item = (const std::pair<FeedRefinerTopN::KeySingle, uint64_t> *) cursor;
                if (conditions.allowedIps.contains(std::string((const char *) item->first.ip, item->first.ipLength))) {
                    perDestination[item->first].value += item->second;
                    ++appliedCounter;
                }

                // check breakpoint
                if (appliedCounter > greedFactor)
                    break;
            }
        break;
    }
    if (perDestination.size() > greedFactor * 2) {
        auto ranking = buildRanking(perDestination);
        ranking.resize(greedFactor);
        perDestination.replace(std::move(ranking));
    }

    // per IP-to-service
    const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> *itemIpToService;
    switch (pmpiCacheMode) {
    case FULL:
        for (const char *cursor = perIpToServiceRaw.data(), *cursorEnd = cursor + perIpToServiceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService) {
            itemIpToService = (const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> *) cursor;
            perIpToService[itemIpToService->first].value += itemIpToService->second;
            ++appliedCounter;

            // check breakpoint
            if (appliedCounter > greedFactor)
                break;
        }
        break;
    case FILTERED:
        if (ipToServiceFilter.isIpFilterOnly && conditions.includeExternalTransfer) { // we can concern only per IP-to-service
            // merge items to IP-to-service pack
            for (const char *cursor = perIpToServiceRaw.data(), *cursorEnd = cursor + perIpToServiceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService) {
                itemIpToService = (const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> *) cursor;
                const auto &key = itemIpToService->first;
                if (conditions.allowedIps.contains(std::string(key.ip2, key.ipLength)) && conditions.allowedIps.contains(std::string(key.ip1, key.ipLength))) { // quicker route
                    perIpToService[key].value += itemIpToService->second;
                    ++appliedCounter;
                }

                // check breakpoint
                if (appliedCounter > greedFactor)
                    break;
            }
        } else { // we need to loop until the end after appliedCounter this greedFactor, as there can be more records that should be merged to the per source or per destination counter in normal situation
            for (const char *cursor = perIpToServiceRaw.data(), *cursorEnd = cursor + perIpToServiceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService) {
                itemIpToService = (const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> *) cursor;
                const auto &key = itemIpToService->first;
                if (ipToServiceFilter.accept(key)) {
                    if (appliedCounter <= greedFactor) {
                        perIpToService[key].value += itemIpToService->second;
                        ++appliedCounter;
                    }
                    if (perSource.size() <= greedFactor)
                        perSource[sourceFromIpToService(key)].value += itemIpToService->second;
                    if (perDestination.size() <= greedFactor)
                        perDestination[destinationFromIpToService(key)].value += itemIpToService->second;
                }
            }
        }
        break;
    }
    if (perIpToService.size() > greedFactor * 2) {
        auto ranking = buildRankingIpToService(perIpToService);
        ranking.resize(greedFactor);
        perIpToService.replace(std::move(ranking));
    }
}
void FeedRefinerTopN::mergeCachePair(const std::string_view &perSourceRaw, const std::string_view &perDestinationRaw, const std::string_view &perIpToServiceRaw, Pack &pack)
{
    // prepare for variables and shortcuts
    const std::pair<FeedRefinerTopN::KeySingle, std::pair<uint64_t, uint64_t>> *item;
    int appliedCounter;
    auto &perSource = pack.perSource;
    auto &perDestination = pack.perDestination;
    auto &perIpToService = pack.perIpToService;
    auto ipToServiceFilter = KeyIpToServiceFilter(conditions);

    // per source
    appliedCounter = 0;
    switch (pmpiCacheMode) {
    case FULL:
        for (const char *cursor = perSourceRaw.data(), *cursorEnd = cursor + perSourceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle2) {
            item = (const std::pair<FeedRefinerTopN::KeySingle, std::pair<uint64_t, uint64_t>> *) cursor;
            perSource[item->first].value += item->second.first;
            perSource[item->first].value2 += item->second.second;
            ++appliedCounter;

            // check breakpoint
            if (appliedCounter > greedFactor)
                break;
        }
        break;
    case FILTERED:
        if (ipToServiceFilter.isIpFilterOnly && conditions.includeExternalTransfer)
            for (const char *cursor = perSourceRaw.data(), *cursorEnd = cursor + perSourceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle) {
                item = (const std::pair<FeedRefinerTopN::KeySingle, std::pair<uint64_t, uint64_t>> *) cursor;
                if (conditions.allowedIps.contains(std::string((const char *) item->first.ip, item->first.ipLength))) {
                    perSource[item->first].value += item->second.first;
                    perSource[item->first].value2 += item->second.second;
                    ++appliedCounter;
                }

                // check breakpoint
                if (appliedCounter > greedFactor)
                    break;
            }
        break;
    default: // INTERNALTRAFFICSONLY will be handled in IP-to-service section
        break;
    }
    if (perSource.size() > greedFactor * 2) {
        auto ranking = buildRanking(perSource);
        ranking.resize(greedFactor);
        perSource.replace(std::move(ranking));
    }
    // per destination
    appliedCounter = 0;
    switch (pmpiCacheMode) {
    case FULL:
        for (const char *cursor = perDestinationRaw.data(), *cursorEnd = cursor + perDestinationRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle2) {
            item = (const std::pair<FeedRefinerTopN::KeySingle, std::pair<uint64_t, uint64_t>> *) cursor;
            perDestination[item->first].value += item->second.first;
            perDestination[item->first].value2 += item->second.second;
            ++appliedCounter;

            // check breakpoint
            if (appliedCounter > greedFactor)
                break;
        }
        break;
    case FILTERED:
        if (ipToServiceFilter.isIpFilterOnly && conditions.includeExternalTransfer)
            for (const char *cursor = perDestinationRaw.data(), *cursorEnd = cursor + perDestinationRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle) {
                item = (const std::pair<FeedRefinerTopN::KeySingle, std::pair<uint64_t, uint64_t>> *) cursor;
                if (conditions.allowedIps.contains(std::string((const char *) item->first.ip, item->first.ipLength))) {
                    perDestination[item->first].value += item->second.first;
                    perDestination[item->first].value2 += item->second.second;
                    ++appliedCounter;
                }

                // check breakpoint
                if (appliedCounter > greedFactor)
                    break;
            }
        break;
    default: // INTERNALTRAFFICSONLY will be handled in IP-to-service section
        break;
    }
    if (perDestination.size() > greedFactor * 2) {
        auto ranking = buildRanking(perDestination);
        ranking.resize(greedFactor);
        perDestination.replace(std::move(ranking));
    }
    // per IP-to-service
    const std::pair<FeedRefinerTopN::KeyIpToService, std::pair<uint64_t, uint64_t>> *itemIpToService;
    switch (pmpiCacheMode) {
    case FULL:
        for (const char *cursor = perIpToServiceRaw.data(), *cursorEnd = cursor + perIpToServiceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService2) {
            itemIpToService = (const std::pair<FeedRefinerTopN::KeyIpToService, std::pair<uint64_t, uint64_t>> *) cursor;
            perIpToService[itemIpToService->first].value += itemIpToService->second.first;
            perIpToService[itemIpToService->first].value2 += itemIpToService->second.second;
            ++appliedCounter;

            // check breakpoint
            if (appliedCounter > greedFactor)
                break;
        }
        break;
    case FILTERED:
        if (ipToServiceFilter.isIpFilterOnly && conditions.includeExternalTransfer) { // we can concern only per IP-to-service
            // merge items to IP-to-service pack
            for (const char *cursor = perIpToServiceRaw.data(), *cursorEnd = cursor + perIpToServiceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService2) {
                itemIpToService = (const std::pair<FeedRefinerTopN::KeyIpToService, std::pair<uint64_t, uint64_t>> *) cursor;
                const auto &key = itemIpToService->first;
                if (conditions.allowedIps.contains(std::string((const char *) key.ip2, key.ipLength)) || conditions.allowedIps.contains(std::string((const char *) key.ip1, key.ipLength))) { // when IP filters are used, most of the time it is server IPs that are applied
                    perIpToService[itemIpToService->first].value += itemIpToService->second.first;
                    perIpToService[itemIpToService->first].value2 += itemIpToService->second.second;
                    ++appliedCounter;
                }

                // check breakpoint
                if (appliedCounter > greedFactor)
                    break;
            }
        } else { // we need to loop until the end after appliedCounter this greedFactor, as there can be more records that should be merged to the per source or per destination counter in normal situation
            for (const char *cursor = perIpToServiceRaw.data(), *cursorEnd = cursor + perIpToServiceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService) {
                itemIpToService = (const std::pair<FeedRefinerTopN::KeyIpToService, std::pair<uint64_t, uint64_t>> *) cursor;
                const auto &key = itemIpToService->first;
                if (ipToServiceFilter.accept(key)) {
                    if (appliedCounter <= greedFactor) {
                        perIpToService[key].value += itemIpToService->second.first;
                        perIpToService[key].value2 += itemIpToService->second.second;
                        ++appliedCounter;
                    }
                    if (perSource.size() <= greedFactor) {
                        perSource[sourceFromIpToService(key)].value += itemIpToService->second.first;
                        perSource[sourceFromIpToService(key)].value2 += itemIpToService->second.second;
                    }
                    if (perDestination.size() <= greedFactor) {
                        perDestination[destinationFromIpToService(key)].value += itemIpToService->second.first;
                        perDestination[destinationFromIpToService(key)].value2 += itemIpToService->second.second;
                    }
                }
            }
        }
        break;
    }
    if (perIpToService.size() > greedFactor * 2) {
        auto ranking = buildRankingIpToService(perIpToService);
        ranking.resize(greedFactor);
        perIpToService.replace(std::move(ranking));
    }
}

FeedRefinerTopNHttpErrors::FeedRefinerTopNHttpErrors(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerTopN(messyRoomName, conditions)
{
    logger.setLogHeader("TopNHttpErrors"s);

    // determine whether to use SuperCache
    cachedChapter = static_cast<SuperCodex::ChapterType>(SuperCodex::REMARKS + SuperCodex::Session::HTTP);
    // check whether SuperCache is applicable
    if (conditions.mplsLabels.empty() && conditions.vlanQTags.empty()) { // preprequsite: no MPLS labels and VLAN tag filter
        if (conditions.allowedIps.isEmpty && conditions.payloadProtocol == 0 && conditions.ports.empty()) // conditions.l7protocol is automatically set to HTTP in DataFeed::postRefinery()
            pmpiCacheMode = FULL;
        else
            pmpiCacheMode = FILTERED;
    }
    if (pmpiCacheMode == NONE)
        logger.log("SuperCache unapplicable");
    else {
        superCachePath = CodexIndex::feedRoot + conditions.dataFeed + SuperCache::dbs[1];
        logger.log("SuperCache applicable");
    }

    // initialize some hashmaps
    orphanedRequests = new ankerl::unordered_dense::map<uint64_t, std::pair<std::string, std::string>>();
    merged = new ankerl::unordered_dense::map<std::string, ankerl::unordered_dense::map<std::string, uint64_t>>();
}

void FeedRefinerTopNHttpErrors::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    // gather data from codices
    std::vector<IntermediatePack> resultParts = SuperCodex::parallel_convert<SuperCodex::Loader *, IntermediatePack>(codices, [&](const SuperCodex::Loader *codex) -> IntermediatePack {
        // since they're all HTTP sessions, the direction of client and server shall be always correct
        const auto &sessions = codex->sessions;
        IntermediatePack pack;

        // reserve some room
        pack.fullErrors.reserve(sessions.size());
        pack.orphanedRequests.reserve(100);
        pack.orphanedResopnses.reserve(100);

        // gather HTTP request-response pairs with HTTP 4xx or 5xx
        for (auto remarksRaw = codex->firstRemarks(); remarksRaw.content; remarksRaw = codex->nextRemarks(remarksRaw)) {
            // prepare for some variables
            const auto &sessionId = remarksRaw.sessionId;
            const auto session = sessions.at(sessionId);
            const std::string sourceIp = SuperCodex::sourceIp(*session), humanReadableDestinationIp = SuperCodex::humanReadableIp(SuperCodex::destinationIp(*session));
            const uint16_t destinationPort = session->destinationPort;
            std::string_view content(remarksRaw.content, remarksRaw.size);

            // determine whether this session ends with an orphaned request
            size_t lastRequest = content.rfind("HttpRequest="s), lastResponse = content.rfind("HttpResponse="s);
            if (lastRequest != std::string_view::npos && lastRequest > lastResponse) { // this session ends with HTTP request
                const std::string_view raw = content.substr(lastRequest);
                pack.orphanedRequests.push_back(std::make_pair(sessionId, std::make_pair(buildDescription(raw, humanReadableDestinationIp, destinationPort), sourceIp)));
            }

            // we search from end of remarks in reverse direction
            while (lastResponse != std::string_view::npos) {
                // check whether the stats code is 4XX or 5XX
                const size_t statusCodeOffset = lastResponse + 33;
                const char &statusCodeFiirst = content.at(statusCodeOffset);
                if (statusCodeFiirst == '4' || statusCodeFiirst == '5') {
                    const size_t pairRequestOffset = content.rfind("HttpRequest=", lastResponse);
                    if (pairRequestOffset == std::string_view::npos) { // this is orphaned response with HTTP 4XX or 5XX in the beginning. We can safely register orphan and break this loop
                        pack.orphanedResopnses.push_back(std::make_pair(sessionId, std::string(content.substr(statusCodeOffset, 3))));
                        break;
                    } else {
                        auto newRecord = buildDescription(content.substr(pairRequestOffset, content.find("HttpEnd=Request"s, pairRequestOffset) - pairRequestOffset), humanReadableDestinationIp, destinationPort);
                        memcpy(&newRecord[0], &content[statusCodeOffset], 3);
                        pack.fullErrors.push_back(std::make_pair(std::move(newRecord), sourceIp));
                    }
                }

                // search for next occurrence
                if (lastResponse > 0)
                    lastResponse = content.rfind("HttpResponse="s, lastResponse - 13);
                else // this is orphaned response in the beginning, but it's not HTTP error. We can safely ignore it
                    break;
            }
        }

        return pack;
    });

    // merge pack
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<IntermediatePack> resultRawsFuture) {
            for (const auto &intermediate : resultRawsFuture) {
                // fill orphaned responses to existing orphaned requests
                for (const auto &responsePair : intermediate.orphanedResopnses)
                    if (orphanedRequests->contains(responsePair.first)) {
                        auto toConverge = orphanedRequests->extract(responsePair.first).value().second; // ankerl::unoordered_dense::map::extract() returns pair of (key, value) like iterator
                        memcpy(&toConverge.first[0], &responsePair.second[0], 3);
                        ++(*merged)[toConverge.first][toConverge.second];
                    }

                // register new orphaned requests
                for (const auto &requestPair : intermediate.orphanedRequests)
                    (*orphanedRequests).insert(requestPair);

                // count errors
                for (const auto &errorPair : intermediate.fullErrors)
                    ++(*merged)[errorPair.first][errorPair.second];
            }
        },
        resultParts);
}

std::string FeedRefinerTopNHttpErrors::buildDescription(const std::string_view &raw, const std::string &serverIp, const uint16_t serverPort)
{
    std::string result("000"s); // room for status code

    // determine hostname: extract Host header, or if it doesn't exist, use server IP as hostname
    std::string host = remarksValueHttpHeader(raw, "Host"s);
    if (host.empty())
        host = serverIp;
    result.append(host);

    // determine whether to add port number
    // build full URL: hostname + (port number if it's not 80) + path
    if (serverPort != 80)
        result.append(':' + std::to_string(serverPort));

    // extract path from HttpRequest
    const std::string_view firstLine = raw.substr(0, raw.find('\n'));
    result.append(firstLine.substr(firstLine.rfind(' ') + 1));

    // add server IP
    result.append(" ("s + serverIp + ')');

    return result;
}

void FeedRefinerTopNHttpErrors::finalize()
{
    // fill SuperCache data: accidentally structure of the raw data is same for general Top N, so we can safely reuse mergeSuperCache()
    mergeSuperCache(cachedChapter, [&](const std::string_view &orphanedRequestsSerialized, const std::string_view &orphanedResponsesSerialized, const std::string_view &fullErrors) {
        SuperCache::HttpErrorHeader header;

        // merge orphaned responses
        for (const char *i = orphanedResponsesSerialized.data(), *iEnd = i + orphanedResponsesSerialized.size(); i < iEnd; i += SuperCache::httpErrorHeaderSize) {
            header = *(SuperCache::HttpErrorHeader *) i;
            if (orphanedRequests->contains(header.value)) {
                auto description = orphanedRequests->extract(header.value).value().second;
                memcpy(&description.first[0], &header.descriptionLength, 3); // HTTP status code resides in first 3 bytes of descriptionLength
                ++(*merged)[description.first][description.second];
            }
        }

        // introduce new orphaned requests
        switch (pmpiCacheMode) {
        case FULL:
            for (const char *i = orphanedRequestsSerialized.data(), *iEnd = i + orphanedRequestsSerialized.size(); i < iEnd;) {
                // read header
                header = *(SuperCache::HttpErrorHeader *) i;
                i += SuperCache::httpErrorHeaderSize;

                //get description body with prefix
                std::string_view descriptionWithIpPair(i, header.descriptionLength);
                i += header.descriptionLength; // here cursor indicates next record already

                // parse prefix
                uint8_t ipLength = descriptionWithIpPair[0];
                if (ipLength == 4 || ipLength == 16) {
                    // register description
                    (*orphanedRequests)[header.value] = std::make_pair(std::string(descriptionWithIpPair.substr(1 + ipLength * 2)), std::string(descriptionWithIpPair.substr(1, ipLength)));
                } else
                    logger.oops("Invalid IP Length: "s + std::to_string(ipLength));
            }
            break;

        case FILTERED:
            for (const char *i = orphanedRequestsSerialized.data(), *iEnd = i + orphanedRequestsSerialized.size(); i < iEnd;) {
                // read header
                header = *(SuperCache::HttpErrorHeader *) i;
                i += SuperCache::httpErrorHeaderSize;
                if (i > iEnd) { // boundary check
                    logger.oops("Orphaned request pointer out of bound(type 1)"s);
                    break;
                }

                //get description body with prefix
                std::string_view descriptionWithIpPair(i, header.descriptionLength);
                i += header.descriptionLength; // here cursor indicates next record already
                if (i > iEnd) { // boundary check
                    logger.oops("Orphaned request pointer out of bound(type 2). Description length is "s + std::to_string(header.descriptionLength));
                    break;
                }

                // apply IP filter condition and register conditions as needed
                uint8_t ipLength = descriptionWithIpPair[0];
                if (ipLength == 4 || ipLength == 16) {
                    const std::string sourceIp(descriptionWithIpPair.substr(1, ipLength)), destinationIp(descriptionWithIpPair.substr(1 + ipLength, ipLength));
                    uint16_t port2 = 80;
                    const std::string url(descriptionWithIpPair.substr(9));
                    const auto colonIndex = url.find(':');
                    if (colonIndex != std::string::npos) {
                        const auto firstSlash = url.find('/', colonIndex + 1);
                        try {
                            port2 = std::stoi(url.substr(colonIndex + 1, firstSlash - 1 - colonIndex));
                        } catch (...) {
                            logger.oops("Failed to recognize port number in URL");
                        }
                    }
                    // check port number
                    if (!conditions.ports.empty())
                        if (!conditions.ports.contains(port2))
                            continue;

                    // check IP addresses
                    if (conditions.includeExternalTransfer) {
                        if (conditions.allowedIps.contains(destinationIp) || conditions.allowedIps.contains(sourceIp))
                            (*orphanedRequests)[header.value] = std::make_pair(std::string(descriptionWithIpPair.substr(1 + ipLength * 2)), sourceIp);
                    } else {
                        if (conditions.allowedIps.contains(destinationIp) && conditions.allowedIps.contains(sourceIp))
                            (*orphanedRequests)[header.value] = std::make_pair(std::string(descriptionWithIpPair.substr(1 + ipLength * 2)), sourceIp);
                    }
                }
            }
            break;
        }

        // merge full errors
        switch (pmpiCacheMode) {
        case FULL:
            for (const char *i = fullErrors.data(), *iEnd = i + fullErrors.size(); i < iEnd;) {
                // read header
                header = *(SuperCache::HttpErrorHeader *) i;
                i += SuperCache::httpErrorHeaderSize;

                //get description body with prefix
                std::string_view descriptionWithIpPair(i, header.descriptionLength);
                i += header.descriptionLength; // here cursor indicates next record already

                // parse prefix
                size_t ipLength = descriptionWithIpPair[0];

                // register description
                (*merged)[std::string(descriptionWithIpPair.substr(1 + ipLength * 2))][std::string(descriptionWithIpPair.substr(1, ipLength))] += header.value;
            }
            break;
        case FILTERED:
            for (const char *i = fullErrors.data(), *iEnd = i + fullErrors.size(); i < iEnd;) {
                // read header
                header = *(SuperCache::HttpErrorHeader *) i;
                i += SuperCache::httpErrorHeaderSize;

                //get description body with prefix
                std::string_view descriptionWithIpPair(i, header.descriptionLength);
                i += header.descriptionLength; // here cursor indicates next record already

                // apply IP filter condition and register conditions as needed
                size_t ipLength = descriptionWithIpPair[0];
                const std::string sourceIp(descriptionWithIpPair.substr(1, ipLength)), destinationIp(descriptionWithIpPair.substr(1 + ipLength, ipLength));
                uint16_t port2 = 80;
                const std::string url(descriptionWithIpPair.substr(9));
                const auto colonIndex = url.find(':');
                if (colonIndex != std::string::npos) {
                    const auto firstSlash = url.find('/', colonIndex + 1);
                    try {
                        port2 = std::stoi(url.substr(colonIndex + 1, firstSlash - 1 - colonIndex));
                    } catch (...) {
                        logger.oops("Failed to recognize port number in URL");
                    }
                }
                // check port number
                if (!conditions.ports.empty())
                    if (!conditions.ports.contains(port2))
                        continue;

                // check IP addresses
                if (conditions.includeExternalTransfer) {
                    if (conditions.allowedIps.contains(destinationIp) || conditions.allowedIps.contains(sourceIp))
                        (*merged)[std::string(descriptionWithIpPair.substr(1 + ipLength * 2))][sourceIp] += header.value;
                } else {
                    if (conditions.allowedIps.contains(destinationIp) && conditions.allowedIps.contains(sourceIp))
                        (*merged)[std::string(descriptionWithIpPair.substr(1 + ipLength * 2))][sourceIp] += header.value;
                }
            }
            break;
        }
    });

    // free memory for orphaned requests, which is not used anymore
    delete orphanedRequests;

    // build summary of merged data
    ankerl::unordered_dense::map<std::string, SummaryHeader> summary;
    for (const auto &pair : *merged) {
        auto &target = summary[pair.first];
        // calculate total hits
        uint64_t sum = 0;
        for (const auto &pair2 : pair.second)
            sum += pair2.second;
        target.totalHits = sum;

        // build numbers for the description itself
        target.descriptionHash = fnv64a(pair.first.data(), pair.first.size());
        target.descriptionSize = pair.first.size();
    }

    // sort merged data per total hits per description
    auto sorted = merged->values();
    delete merged; // not necessary anymore
    std::sort(sorted.begin(), sorted.end(), [&](const std::pair<std::string, ankerl::unordered_dense::map<std::string, uint64_t>> &a, const std::pair<std::string, ankerl::unordered_dense::map<std::string, uint64_t>> &b) -> bool { return summary[a.first].totalHits > summary[b.first].totalHits; });

    // prepare to write down stuff
    std::ofstream diskWriter;
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    diskWriter.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);

    // write down summary
    diskWriter.open(messyRoomPrefix + "/summary"s, std::ios::binary | std::ios::trunc);
    for (const auto &pair : summary) {
        // write summary header
        diskWriter.write((const char *) &pair.second, summaryHeaderSize);
        // write down description itself
        diskWriter.write(pair.first.data(), pair.second.descriptionSize);
    }
    diskWriter.close();

    // write down per source details
    for (const auto &pair : sorted) {
        // sort details and prepare for save
        const auto &targetSummary = summary[pair.first];
        auto sortedDetail = pair.second.values();
        std::sort(sortedDetail.begin(), sortedDetail.end(), [](const std::pair<std::string, uint64_t> &a, const std::pair<std::string, uint64_t> &b) -> bool { return a.second > b.second; });
        const uint32_t ipLength = sortedDetail.front().first.size();

        // flush
        diskWriter.open(messyRoomPrefix + '/' + std::to_string(targetSummary.descriptionHash), std::ios::binary | std::ios::trunc);
        // save IP length
        diskWriter.write((const char *) &ipLength, 4);
        // flush everything
        for (const auto &pair2 : sortedDetail) {
            diskWriter.write(pair2.first.data(), ipLength); // source IP
            diskWriter.write((const char *) &pair2.second, 8); // number of hits
        }
        diskWriter.close();
    }

    // log
    logger.log("Result ready to serve: "s + std::to_string(summary.size()));
}

void FeedRefinerTopNHttpErrors::mergeSuperCache(const int chapterType, std::function<void(const std::string_view &, const std::string_view &, const std::string_view &)> toMerge)
{
    // query database
    FeatherLite feather(CodexIndex::feedRoot + conditions.dataFeed + "/supercache.pmpi"s, SQLITE_OPEN_READONLY);
    feather.prepare("SELECT originalsize,filepath FROM rows WHERE timestamp>=? AND timestamp<=? AND chapter=? ORDER BY timestamp;"s);
    feather.bindInt(1, conditions.cacheFrom);
    feather.bindInt(2, conditions.cacheTo);
    feather.bindInt(3, chapterType);

    while (feather.next() == SQLITE_ROW) {
        auto pmpiTriplet = SuperCache::getPmpiTriplet(std::string(feather.getText(1)), feather.getInt(0));
        if (pmpiTriplet.decompressedRaw == nullptr)
            continue;
        toMerge(pmpiTriplet.perSourceRaw, pmpiTriplet.perDestinationRaw, pmpiTriplet.perIpToServiceRaw);
        delete[] pmpiTriplet.decompressedRaw;
    }

    // finalize
    feather.reset();
    feather.finalize();
}

void FeedRefinerTopNHttpErrors::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::string url;
    std::ifstream file(messyRoomPrefix + "/summary"s, std::ios::binary);

    // generate result
    std::string temp;
    SummaryHeader header;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    if (bindValue >= 0) {
        yyjson_mut_val *rootObject = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootObject);

        int rankCursor = 0;
        yyjson_mut_obj_add_strn(document, rootObject, "base", "httperrors", 10);
        yyjson_mut_val *rankArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "rank", rankArray);
        // read first header
        file.read((char *) &header, summaryHeaderSize);
        while (file.gcount()) {
            // read description
            char *keyBuffer = new char[header.descriptionSize];
            file.read(keyBuffer, header.descriptionSize);
            url = std::string(keyBuffer, header.descriptionSize);
            delete[] keyBuffer; // it has done its use

            // write
            if (!url.empty()) {
                int statusCode = std::stoi(url.substr(0, 3));
                if (from == 0 || (statusCode >= from && statusCode <= to)) {
                    yyjson_mut_val *object = yyjson_mut_obj(document);
                    yyjson_mut_arr_append(rankArray, object);
                    temp = url.substr(3);
                    yyjson_mut_obj_add_strncpy(document, object, "path", temp.data(), temp.size());
                    yyjson_mut_obj_add_int(document, object, "statuscode", statusCode);
                    yyjson_mut_obj_add_int(document, object, "value", header.totalHits);

                    // check ranking limit
                    if (bindValue && (++rankCursor) >= bindValue)
                        break;
                }
            }

            // read next header
            file.read((char *) &header, summaryHeaderSize);
        }
    } else { // bindValue<0
        ankerl::unordered_dense::segmented_map<int, long long> accumulated;

        // build per status code counter
        file.read((char *) &header, summaryHeaderSize);
        while (file.gcount()) {
            char *keyBuffer = new char[header.descriptionSize];
            file.read(keyBuffer, header.descriptionSize);
            url = std::string(keyBuffer, header.descriptionSize);
            delete[] keyBuffer; // it has done its use

            // accumulate per status code
            int statusCode = std::stoi(url.substr(0, 3));
            if (from == 0 || (statusCode >= from && statusCode <= to))
                accumulated[statusCode] += header.totalHits;

            // read next header
            file.read((char *) &header, summaryHeaderSize);
        }

        // sort
        std::vector<std::pair<int, long long>> accumulatedSorted;
        accumulatedSorted.reserve(accumulated.size());
        for (const auto &pair : accumulated)
            accumulatedSorted.push_back(std::make_pair(pair.first, pair.second));
        std::sort(accumulatedSorted.begin(), accumulatedSorted.end(), [](const std::pair<int, long long> &a, const std::pair<int, long long> &b) -> bool { return a.second > b.second; });

        // build JSON
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);
        for (const auto &pair : accumulatedSorted) {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(rootArray, object);
            yyjson_mut_obj_add_int(document, object, "statuscode", pair.first);
            yyjson_mut_obj_add_int(document, object, "value", pair.second);
        }
    }

    if (connection)
        Civet7::respond200(connection, document);
    else
        lastInterativeResult = document;
}

void FeedRefinerTopNHttpErrors::dumpResults(mg_connection *connection)
{
    std::string chunk;
    chunk.reserve(110000000); // 110 MB
    chunk.append("Duration: "s).append(epochToIsoDate(secondStart)).append(" ~ "s).append(epochToIsoDate(secondEnd)).append("\n"s).append("base\thttperrors\n\nURL\tStatus Code\tSource IP\tHits\n"s);
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // read records
    std::ifstream file(messyRoomPrefix + "/phase2"s, std::ios::binary);
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);
    std::string url;
    // read first header
    SummaryHeader header;
    file.read((char *) &header, summaryHeaderSize);
    while (file.gcount()) {
        char *keyBuffer = new char[header.descriptionSize];
        file.read(keyBuffer, header.descriptionSize);
        url = std::string(keyBuffer, header.descriptionSize); // there are situations URL size is zero
        delete[] keyBuffer; // it has done its use

        // prepare for line prefix
        std::string prefix;
        prefix.append(url.substr(3)).append("\t"s).append(url.substr(0, 3)).push_back('\t');

        // write source IPs
        std::ifstream sourceIps(messyRoomPrefix + '/' + std::to_string(header.descriptionHash), std::ios::binary);
        // discover IP length
        uint32_t ipLength;
        sourceIps.read((char *) &ipLength, 4);
        // read source IPs and their hits
        char *ip;
        uint64_t hits;
        while (sourceIps.gcount()) {
            // read a record
            ip = new char[ipLength];
            sourceIps.read(ip, ipLength);
            sourceIps.read((char *) &hits, 8);
            chunk.append(prefix).append(SuperCodex::humanReadableIp(std::string(ip, ipLength)) + '\t').append(std::to_string(hits)).push_back('\n');
            delete[] ip;
        }

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

        // read next summary header
        file.read((char *) &header, summaryHeaderSize);
    }

    // send final chunks
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

FeedRefinerTopNLatencies::FeedRefinerTopNLatencies(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerTopN(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerTopN/latencies"s);
    cachedChapter = static_cast<SuperCodex::ChapterType>(SuperCodex::RTTS);

    // check whether SuperCache is applicable
    if (conditions.mplsLabels.empty() && conditions.vlanQTags.empty()) { // preprequsite: no MPLS labels and VLAN tag filter
        if (conditions.allowedIps.isEmpty && conditions.payloadProtocol == 0 && conditions.l7Protocol == SuperCodex::Session::NOL7DETECTED && conditions.ports.empty())
            pmpiCacheMode = FULL;
        else
            pmpiCacheMode = FILTERED;
    }
    if (pmpiCacheMode == NONE)
        logger.log("SuperCache unapplicable");
    else {
        superCachePath = CodexIndex::feedRoot + conditions.dataFeed + SuperCache::dbs[1];
        logger.log("SuperCache applicable");
    }
}

void FeedRefinerTopNLatencies::fillSessions(const SuperCodex::Loader *codex, Pack &pack)
{
    pack.sessions.reserve(pack.values.size() / 2);
    for (auto i = pack.values.begin(); i != pack.values.end();) {
        const auto session = codex->sessions.at(i->first);
        if (SuperCodex::ipLength(session->etherType)) {
            pack.sessions.push_back(*session);
            ++i;
        } else
            i = pack.values.erase(i);
    }
}

void FeedRefinerTopNLatencies::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    // build raw data
    std::vector<Pack> resultParts = SuperCodex::parallel_convert<SuperCodex::Loader *, Pack>(
        codices,
        [&](SuperCodex::Loader *codex) -> Pack {
            Pack pack;

            // group each latency
            for (auto rtt = codex->firstRtt(); rtt; rtt = codex->nextRtt(rtt))
                if (rtt->tail <= rttIgnoreFrom) { // more than given time(default: 10 seconds) is treated as just being idle.
                    // simple sanity check
                    if (rtt->tail < 0) {
                        logger.log("Skipping negative RTT tail at "s + std::to_string(rtt->second) + ' ' + std::to_string(rtt->tail));
                        continue;
                    }

                    auto &target = pack.values[rtt->sessionId];
                    target.sessionId = rtt->sessionId;
                    if (rtt->fromSmallToBig) {
                        target.numerator0 += rtt->tail;
                        ++target.denominator0;
                    } else {
                        target.numerator1 += rtt->tail;
                        ++target.denominator1;
                    }
                }
            for (auto bytes = codex->firstBpsPerSession(); bytes; bytes = codex->nextBpsPerSession(bytes))
                pack.values[bytes->sessionId].bytes += bytes->fromBigToSmall + bytes->fromSmallToBig;
            fillSessions(codex, pack);

            return pack;
        },
        affinityPartitioner);

    // merge pack
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Pack> resultRawsFuture) {
            // background: merge sessions from current and new raw data and prepare sum
            std::thread sessionOrganizerFuture([&]() {
                for (const auto &resultRaw : resultRawsFuture)
                    updateTimestampAndMergeSessions(resultRaw.sessions);
            });

            // save values
            std::ofstream valuesFile(messyRoomPrefix + "/values"s, std::ios::out | std::ios::binary | std::ios::app);
            std::unique_ptr<char[]> valuesFileBuffer(new char[536870912]); // 512MB
            valuesFile.rdbuf()->pubsetbuf(valuesFileBuffer.get(), 536870912);
            for (const auto &resultRaw : resultRawsFuture)
                for (const auto &pair : resultRaw.values)
                    valuesFile.write((const char *) &pair.second, valuesRttSize);
            valuesFile.close();

            // wait for session organizer to finish
            sessionOrganizerFuture.join();
        },
        resultParts);
}

void FeedRefinerTopNLatencies::finalize()
{
    // prepare for containters to build statistics
    ankerl::unordered_dense::map<KeySingle, ValuesRtt, KeySingleHash, KeySingleEqual> perSource, perDestination;
    ankerl::unordered_dense::map<KeyIpToService, ValuesIpToService, KeyIpToServiceHash, KeyIpToServiceEqual> perIpToService;
    std::mutex perSourceMutex, perDestinationMutex, perIpToServiceMutex;
    struct MergePack
    {
        ankerl::unordered_dense::map<KeySingle, ValuesRtt, KeySingleHash, KeySingleEqual> perSource, perDestination;
        ankerl::unordered_dense::map<KeyIpToService, ValuesIpToService, KeyIpToServiceHash, KeyIpToServiceEqual> perIpToService;
    };

    // fill SuperCache data
    if (conditions.cacheFrom) {
        std::vector<MergePack> toMerge = mergeSuperCache<MergePack>(cachedChapter, [&](const std::string_view &perSourceRaw, const std::string_view &perDestinationRaw, const std::string_view &perIpToServiceRaw, MergePack &pack) {
            // prepare to apply values
            auto &perSourceLocal = pack.perSource;
            auto &perDestinationLocal = pack.perDestination;
            auto &perIpToServiceLocal = pack.perIpToService;
            const std::pair<KeySingle, ValuesRtt> *item;
            int appliedCounter = 0;

            // reserve some room
            perSourceLocal.reserve(greedFactor * 2);
            perDestinationLocal.reserve(greedFactor * 2);
            perIpToServiceLocal.reserve(greedFactor * 2);
            auto ipToServiceFilter = KeyIpToServiceFilter(conditions);

            // per source
            appliedCounter = 0;
            switch (pmpiCacheMode) {
            case FULL:
                for (const char *cursor = perSourceRaw.data(), *cursorEnd = cursor + perSourceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingleRtt) {
                    item = (const std::pair<KeySingle, ValuesRtt> *) cursor;
                    perSourceLocal[item->first] += item->second;
                    ++appliedCounter;

                    // check breakpoint
                    if (appliedCounter > greedFactor)
                        break;
                }
                break;
            case FILTERED:
                if (ipToServiceFilter.isIpFilterOnly && conditions.includeExternalTransfer)
                    for (const char *cursor = perSourceRaw.data(), *cursorEnd = cursor + perSourceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle) {
                        item = (const std::pair<KeySingle, ValuesRtt> *) cursor;
                        if (conditions.allowedIps.contains(std::string((const char *) item->first.ip, item->first.ipLength))) {
                            perSourceLocal[item->first] += item->second;
                            ++appliedCounter;
                        }

                        // check breakpoint
                        if (appliedCounter > greedFactor)
                            break;
                    }
                break;
            }
            if (perSourceLocal.size() > greedFactor * 2) {
                auto ranking = buildRanking(perSourceLocal);
                ranking.resize(greedFactor);
                perSourceLocal.replace(std::move(ranking));
            }

            // per destination
            appliedCounter = 0;
            switch (pmpiCacheMode) {
            case FULL:
                for (const char *cursor = perDestinationRaw.data(), *cursorEnd = cursor + perDestinationRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingleRtt) {
                    item = (const std::pair<KeySingle, ValuesRtt> *) cursor;
                    perDestinationLocal[item->first] += item->second;
                    ++appliedCounter;

                    // check breakpoint
                    if (appliedCounter > greedFactor)
                        break;
                }
                break;
            case FILTERED:
                if (ipToServiceFilter.isIpFilterOnly && conditions.includeExternalTransfer)
                    for (const char *cursor = perDestinationRaw.data(), *cursorEnd = cursor + perDestinationRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle) {
                        item = (const std::pair<KeySingle, ValuesRtt> *) cursor;
                        if (conditions.allowedIps.contains(std::string((const char *) item->first.ip, item->first.ipLength))) {
                            perDestinationLocal[item->first] += item->second;
                            ++appliedCounter;
                        }

                        // check breakpoint
                        if (appliedCounter > greedFactor)
                            break;
                    }
                break;
            }
            if (perDestinationLocal.size() > greedFactor * 2) {
                auto ranking = buildRanking(perDestinationLocal);
                ranking.resize(greedFactor);
                perDestinationLocal.replace(std::move(ranking));
            }

            // per IP-to-service
            const std::pair<KeyIpToService, ValuesRtt> *itemIpToService;
            switch (pmpiCacheMode) {
            case FULL:
                for (const char *cursor = perIpToServiceRaw.data(), *cursorEnd = cursor + perIpToServiceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToServiceRtt) {
                    itemIpToService = (const std::pair<KeyIpToService, ValuesRtt> *) cursor;
                    perIpToServiceLocal[itemIpToService->first].values += itemIpToService->second;
                    ++appliedCounter;

                    // check breakpoint
                    if (appliedCounter > greedFactor)
                        break;
                }
                break;
            case FILTERED:
                if (ipToServiceFilter.isIpFilterOnly && conditions.includeExternalTransfer) { // we can concern only per IP-to-service
                    // merge items to IP-to-service pack
                    for (const char *cursor = perIpToServiceRaw.data(), *cursorEnd = cursor + perIpToServiceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService) {
                        itemIpToService = (const std::pair<KeyIpToService, ValuesRtt> *) cursor;
                        const auto &key = itemIpToService->first;
                        if (conditions.allowedIps.contains(std::string(key.ip2, key.ipLength)) && conditions.allowedIps.contains(std::string(key.ip1, key.ipLength))) { // quicker route
                            perIpToServiceLocal[key].values += itemIpToService->second;
                            ++appliedCounter;
                        }

                        // check breakpoint
                        if (appliedCounter > greedFactor)
                            break;
                    }
                } else { // we need to loop until the end after appliedCounter this greedFactor, as there can be more records that should be merged to the per source or per destination counter in normal situation
                    for (const char *cursor = perIpToServiceRaw.data(), *cursorEnd = cursor + perIpToServiceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService) {
                        itemIpToService = (const std::pair<KeyIpToService, ValuesRtt> *) cursor;
                        const auto &key = itemIpToService->first;
                        if (ipToServiceFilter.accept(key)) {
                            if (appliedCounter <= greedFactor) {
                                perIpToServiceLocal[key].values += itemIpToService->second;
                                ++appliedCounter;
                            }
                            if (perSource.size() <= greedFactor)
                                perSourceLocal[sourceFromIpToService(key)] += itemIpToService->second;
                            if (perDestination.size() <= greedFactor)
                                perDestinationLocal[destinationFromIpToService(key)] += itemIpToService->second;
                        }
                    }
                }
                break;
            case NONE:
                logger.oops("Unexpected cache mode - NONE"s);
                break;
            }
            if (perIpToServiceLocal.size() > greedFactor * 2) {
                auto ranking = buildRankingIpToService(perIpToServiceLocal);
                ranking.resize(greedFactor);
                perIpToServiceLocal.replace(std::move(ranking));
            }
        });

        // merge cached data to main logic
        for (const auto &pack : toMerge) {
            for (const auto &pair : pack.perSource)
                perSource[pair.first] += pair.second;
            for (const auto &pair : pack.perDestination)
                perDestination[pair.first] += pair.second;
            for (const auto &pair : pack.perIpToService) {
                auto &target = perIpToService[pair.first];
                target.values += pair.second.values;
                if (target.detectedL7 == SuperCodex::Session::NOL7DETECTED && pair.second.detectedL7 != SuperCodex::Session::NOL7DETECTED)
                    target.detectedL7 = SuperCodex::Session::NOL7DETECTED;
            }
        }
    }

    // determine concurrency size for tbb::parallel_for
    size_t fileSize = std::filesystem::file_size(messyRoomPrefix + "/values"s), cursor = 0, bufferSize = valuesRttSize * 1000000; // read 1mil records per thread
    std::vector<size_t> chunks;
    while (cursor < fileSize) {
        chunks.push_back(cursor);
        cursor += bufferSize;
    }

    // initialize file buffer
    std::ifstream valuesFile(messyRoomPrefix + "/values"s, std::ios::binary | std::ios::in);
    std::mutex valuesFileMutex;

    // start the concurrency
    tbb::parallel_for(tbb::blocked_range<size_t>(0, chunks.size()), [&](tbb::blocked_range<size_t> r) {
        std::unique_ptr<char[]> buffer(new char[bufferSize]); // reused
        for (size_t i = r.begin(); i < r.end(); ++i) {
            // read from file
            valuesFileMutex.lock();
            size_t chunkOffset = chunks.at(i);
            valuesFile.seekg(chunkOffset, std::ios::beg);
            valuesFile.read(buffer.get(), bufferSize);
            valuesFileMutex.unlock();

            // prepare for some counters
            const ValuesRtt *values = (const ValuesRtt *) buffer.get(), *valuesEnd = values + (valuesFile.gcount() / valuesRttSize);

            // per sourcce
            ankerl::unordered_dense::map<KeySingle, ValuesRtt, KeySingleHash, KeySingleEqual> perSource1;
            for (auto i = values; i < valuesEnd; ++i)
                if (sessions->count(i->sessionId)) {
                    // prepare for key
                    auto &session = sessions->at(i->sessionId);
                    KeySingle key{};
                    key.ipLength = SuperCodex::ipLength(session.etherType);
                    memcpy(key.ip, session.ips, key.ipLength);

                    // merge values
                    auto &target = perSource1[key];
                    target += *i;
                }

            // merge and make it greedy
            perSourceMutex.lock();
            for (const auto &pair : perSource1)
                perSource[pair.first] += pair.second;
            if (perSource.size() > greedFactor * 2) {
                // make a "in-the-middle" result
                auto ranking = buildRanking(perSource);
                ranking.resize(greedFactor);
                perSource.replace(std::move(ranking));
            }
            perSourceMutex.unlock();

            // per destination
            ankerl::unordered_dense::map<KeySingle, ValuesRtt, KeySingleHash, KeySingleEqual> perDestination1;
            for (auto i = values; i < valuesEnd; ++i)
                if (sessions->count(i->sessionId)) {
                    // prepare for key
                    auto &session = sessions->at(i->sessionId);
                    KeySingle key{};
                    key.ipLength = SuperCodex::ipLength(session.etherType);
                    memcpy(key.ip, session.ips + key.ipLength, key.ipLength);
                    key.port = session.destinationPort;

                    // merge values
                    auto &target = perDestination1[key];
                    target += *i;
                }

            // merge and make it greedy
            perDestinationMutex.lock();
            for (const auto &pair : perDestination1)
                perDestination[pair.first] += pair.second;
            if (perDestination.size() > greedFactor * 2) {
                // make a "in-the-middle" result
                auto ranking = buildRanking(perDestination);
                ranking.resize(greedFactor);
                perDestination.replace(std::move(ranking));
            }
            perDestinationMutex.unlock();

            // per IP to service
            ankerl::unordered_dense::segmented_map<KeyIpToService, ValuesIpToService, KeyIpToServiceHash, KeyIpToServiceEqual> perIpToService1;
            for (auto i = values; i < valuesEnd; ++i)
                if (sessions->count(i->sessionId)) {
                    // merge values
                    const SuperCodex::Session &session = sessions->at(i->sessionId);
                    auto &target = perIpToService1[keyIpToServiceFromSession(session)];
                    target.values += *i;
                    if (session.detectedL7 != SuperCodex::Session::NOL7DETECTED)
                        target.detectedL7 = session.detectedL7;
                }

            // make it greedy
            perIpToServiceMutex.lock();
            for (const auto &pair : perIpToService1) {
                if (!perIpToService.contains(pair.first))
                    perIpToService[pair.first].detectedL7 = pair.second.detectedL7;
                perIpToService[pair.first].values += pair.second.values;
            }
            if (perIpToService.size() > greedFactor) {
                // make a "in-the-middle" result
                auto ranking = buildRankingIpToService(perIpToService);
                ranking.resize(greedFactor);
                perIpToService.replace(std::move(ranking));
            }
            perIpToServiceMutex.unlock();
        }
    });

    // exception handling: there's no data
    if (!std::filesystem::exists(messyRoomPrefix + "/values"s)) {
        std::ofstream dummyS(messyRoomPrefix + "/result_s"s), dummyD(messyRoomPrefix + "/result_d"s), dummyI(messyRoomPrefix + "/result_i"s);
        logger.log("No data. Falling back.");
        return;
    }

    // build ranking and save results
    std::vector<std::thread> synchronizer;
    synchronizer.push_back(std::thread([&] { // per source
        auto ranking = buildRanking(perSource);
        std::vector<std::pair<KeySingle, Description>> rankingConverted;
        rankingConverted.reserve(ranking.size());
        for (const auto &item : ranking)
            rankingConverted.push_back(std::make_pair(item.first, Description{item.second.represent(), item.second.bytes}));
        saveRanking(rankingConverted, messyRoomPrefix + "/result_s"s);
    }));
    synchronizer.push_back(std::thread([&] { // per destination
        auto ranking = buildRanking(perDestination);
        std::vector<std::pair<KeySingle, Description>> rankingConverted;
        rankingConverted.reserve(ranking.size());
        for (const auto &item : ranking)
            rankingConverted.push_back(std::make_pair(item.first, Description{item.second.represent(), item.second.bytes}));
        saveRanking(rankingConverted, messyRoomPrefix + "/result_d"s);
    }));
    synchronizer.push_back(std::thread([&] { // per IP to Service
        // build ranking
        std::vector<std::pair<KeyIpToService, Description>> ranking;
        ranking.reserve(perIpToService.size());
        for (const auto &pair : perIpToService) {
            const auto &target = pair.second;
            auto key = pair.first;
            key.detectedL7 = target.detectedL7;
            if (key.direction == 1) { // source is lexically small
                if (target.values.numerator0)
                    ranking.push_back(std::make_pair(key, Description{static_cast<uint64_t>(target.values.denominator0 ? target.values.numerator0 / target.values.denominator0 : 0), target.values.bytes})); // source to destination
                key.direction = 0;
                if (target.values.numerator1)
                    ranking.push_back(std::make_pair(key, Description{static_cast<uint64_t>(target.values.denominator1 ? target.values.numerator1 / target.values.denominator1 : 0), target.values.bytes})); // destination to source
            } else {
                if (target.values.numerator0)
                    ranking.push_back(std::make_pair(key, Description{static_cast<uint64_t>(target.values.denominator0 ? target.values.numerator0 / target.values.denominator0 : 0), target.values.bytes})); // destination to source
                key.direction = 1;
                if (target.values.numerator1)
                    ranking.push_back(std::make_pair(key, Description{static_cast<uint64_t>(target.values.denominator1 ? target.values.numerator1 / target.values.denominator1 : 0), target.values.bytes})); // source to destination
            }
        }
        std::sort(ranking.begin(), ranking.end(), [](const std::pair<KeyIpToService, Description> &a, const std::pair<KeyIpToService, Description> &b) { return a.second.value > b.second.value; });

        // save ranking
        saveRanking(ranking, messyRoomPrefix + "/result_i"s);
    }));
    for (auto &thread : synchronizer)
        thread.join();

    // log
    sizePerSource = perSource.size();
    sizePerDestination = perDestination.size();
    sizePerIpToService = perIpToService.size();
    valuesFile.close();
    std::filesystem::remove(messyRoomPrefix + "/values"s);
    logger.log("Results ready to serve: "s + std::to_string(sizePerSource) + " / "s + std::to_string(sizePerDestination) + " / "s + std::to_string(sizePerIpToService));
}

std::vector<std::pair<FeedRefinerTopNLatencies::KeySingle, FeedRefinerTopNLatencies::ValuesRtt>> FeedRefinerTopNLatencies::buildRanking(const ankerl::unordered_dense::map<KeySingle, ValuesRtt, KeySingleHash, KeySingleEqual> &map)
{
    auto result = map.values();

    std::sort(result.begin(), result.end(), [](const std::pair<KeySingle, ValuesRtt> &a, const std::pair<KeySingle, ValuesRtt> &b) -> bool { return a.second.represent() > b.second.represent(); });

    return result;
}

std::vector<std::pair<FeedRefinerTopNLatencies::KeyIpToService, FeedRefinerTopNLatencies::ValuesIpToService>> FeedRefinerTopNLatencies::buildRankingIpToService(const ankerl::unordered_dense::map<KeyIpToService, ValuesIpToService, KeyIpToServiceHash, KeyIpToServiceEqual> &map)
{
    auto result = map.values();

    std::sort(result.begin(), result.end(), [](const std::pair<KeyIpToService, ValuesIpToService> &a, const std::pair<KeyIpToService, ValuesIpToService> &b) -> bool { return a.second.values.represent() > b.second.values.represent(); });

    return result;
}

KeyIpToServiceFilter::KeyIpToServiceFilter(const SuperCodex::Conditions &conditions)
    : conditions(conditions)
{
    isIpFilterOnly = (!conditions.allowedIps.isEmpty && conditions.ports.empty() && conditions.payloadProtocol == 0 && conditions.l7Protocol == SuperCodex::Session::NOL7DETECTED);
}

bool KeyIpToServiceFilter::accept(const FeedRefinerTopN::KeyIpToService &header) const
{
    // payload protocol
    if (conditions.payloadProtocol && header.payloadProtocol != conditions.payloadProtocol)
        return false;

    // L7 protocol
    if (conditions.l7Protocol != SuperCodex::Session::NOL7DETECTED && conditions.l7Protocol != header.detectedL7)
        return false;

    // IP address
    const auto &allowedIps = conditions.allowedIps;
    if (!allowedIps.isEmpty) {
        // check sanity of IP length
        if (header.ipLength != 4 && header.ipLength != 16)
            return false;

        if (conditions.includeExternalTransfer) {
            if (!allowedIps.contains(std::string(header.ip2, header.ipLength)) && !allowedIps.contains(std::string(header.ip1, header.ipLength)))
                return false;
        } else {
            if (!allowedIps.contains(std::string(header.ip2, header.ipLength)) || !allowedIps.contains(std::string(header.ip1, header.ipLength)))
                return false;
        }
    }

    // port
    const auto &ports = conditions.ports;
    if (!ports.empty() && !ports.contains(header.port2))
        return false;

    return true;
}
