#include "feedrefinermain.h"
#include <filesystem>
#include <fstream>
#include <future>
#include <regex>
#include <sstream>
#include <time.h>

#include <tbb/parallel_for.h>
#include <tbb/parallel_for_each.h>

#include "civet7.hpp"
#include "codexindex.h"
#include "supercache.h"
#include "../featherlite.h"
#include "feedrefinertopn.h"

using namespace std::string_literals;

FeedRefinerDataStreams::FeedRefinerDataStreams(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerDataStreams"s);

    // set regular exressions
    if (conditions.parameters.contains("regex"s)) {
        regex = conditions.parameters.at("regex"s);
        // trimming regex
        while (regex.back() == ' ' || regex.back() == '\r' || regex.back() == '\n')
            regex.pop_back();
        while (regex.front() == ' ')
            regex.erase(0, 1);
        logger.log("Regex set: " + regex);
        trackPayload = !regex.empty(); // sometimes there's regex but it may be empty. In that case regex isn't required
    }
}

void FeedRefinerDataStreams::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    // read payload and merge data
    std::vector<Pack> resultPacks = SuperCodex::parallel_convert<SuperCodex::Loader *, Pack>(codices, [&](const SuperCodex::Loader *codex) -> Pack {
        Pack pack;

        // enumerate sessions inside target timeframe
        for (auto pair : codex->sessions) {
            const auto &session = pair.second;
            if (session->etherType == 0x0800 && session->payloadProtocol == 0x06 || session->payloadProtocol == 0x11) { // temporary: IPv4 only
                mergeSession(session);
                if (session->status & SuperCodex::Session::STREAMCLOSED)
                    pack.closedTcpSessions.push_back(session->id);
            }
        }

        // gather byte statistics
        for (const SuperCodex::Loader::BpsPpsItem *bps = codex->firstBpsPerSession(); bps; bps = codex->nextBpsPerSession(bps))
            if (sessions2.count(bps->sessionId)) {
                tbb::concurrent_hash_map<uint64_t, std::pair<int64_t, int64_t>>::accessor a;
                usage.insert(a, bps->sessionId);
                a->second.first += bps->fromSmallToBig;
                a->second.second += bps->fromBigToSmall;
            }

        // gather RTT
        for (const SuperCodex::PacketMarker *rtt = codex->firstRtt(); rtt; rtt = codex->nextRtt(rtt))
            if (sessions2.count(rtt->sessionId) && rtt->tail < 10000000000) {
                tbb::concurrent_hash_map<uint64_t, ValuesRtt>::accessor a; // accumulated RTT. session ID + < from small to big + from big to small >
                rtts.insert(a, rtt->sessionId);
                if (rtt->fromSmallToBig) {
                    a->second.numerator0 += rtt->tail;
                    ++a->second.denominator0;
                } else {
                    a->second.numerator1 += rtt->tail;
                    ++a->second.denominator1;
                }
            }

        // gather timeouts
        for (auto timeout = codex->firstTimeout(); timeout; timeout = codex->nextTimeout(timeout))
            if (sessions2.count(timeout->session.etherType == 0x0800))
                timeouts.insert(timeout->session.id);

        // read payload(PCAP or appendix) to RAM
        if (trackPayload) {
            std::string payloadPath(codex->fileName), payload;
            payloadPath.erase(payloadPath.size() - 11, 11);
            if (std::filesystem::exists(payloadPath + ".pcap"s)) { // .PCAP
                payload = static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(payloadPath + ".pcap"s, std::ifstream::binary).rdbuf()).str();
                payload.erase(0, 24); // remove PCAP global header, which is practically unnecessary
            } else if (std::filesystem::exists(payloadPath + ".appendix"s)) { // .appendix
                payload = static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(payloadPath + ".appendix"s, std::ifstream::binary).rdbuf()).str();
            } else { // nothing found
                logger.log("Payload file(PCAP or appendix) not found for "s + payloadPath);
                return pack; // return blank result if corresponding PCAP file is not found
            }
            unsigned int payloadSize = payload.size();

            // walk through payload
            for (const SuperCodex::Packet *packet = codex->firstPacket(); packet; packet = codex->nextPacket(packet))
                if (sessions2.count(packet->sessionId)) {
                    const auto sessionId = packet->sessionId;
                    const auto payloadProtocol = codex->sessions.at(sessionId)->payloadProtocol;
                    if (packet->savedLength > 64 && (payloadProtocol == 0x06 || payloadProtocol == 0x11)) { // has payload + it's TCP or UDP
                        // append payload data
                        unsigned int payloadEnd = packet->fileOffset + packet->savedLength, payloadStart = payloadEnd - packet->payloadDataSize;
                        if (payloadStart > payloadSize) {
                            logger.log("Invalid payload start. " + payloadPath + " | Payload offset: "s + std::to_string(payloadStart) + " / Payload size: "s + std::to_string(payloadSize));
                            continue;
                        }
                        if (payloadEnd > payloadStart)
                            pack.payloads[sessionId].append(payload.data() + payloadStart, payloadEnd - payloadStart);
                    }
                }
        }

        return pack;
    });

    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Pack> resultRawsFuture) {
            if (!trackPayload)
                return;
            // write down payloads
            std::vector<std::pair<uint64_t, const std::string *>> payloadsToWrite;
            int size = 0;
            for (const auto &resultRaw : resultRawsFuture)
                size += resultRaw.payloads.size();
            payloadsToWrite.reserve(size);
            for (const auto &resultRaw : resultRawsFuture)
                for (const auto &pair : resultRaw.payloads)
                    payloadsToWrite.push_back(std::make_pair(pair.first, &pair.second));
            tbb::parallel_for_each(payloadsToWrite, [&](const std::pair<uint64_t, const std::string *> pair) {
                std::string fileName = messyRoomPrefix + '/' + std::to_string(pair.first) + ".bin"s;
                if (!pair.second->empty() && (!std::filesystem::exists(fileName) || std::filesystem::file_size(fileName) < maxPayloadSizeForRegex)) {
                    std::ofstream payloadWriter(fileName, std::ios::binary | std::ios::app);
                    payloadWriter.write(pair.second->data(), pair.second->size());
                    payloadWriter.close();
                }
            });

            // remove sessions and payloads among closed sessions
            if (regex != ".*") // exception handling: we'll include everything. this is related with a bug where std::regex_search crashes with too long lines(29086 characters or more) on Linux libc++
                tbb::parallel_for_each(resultRawsFuture, [&](const Pack &pack) {
                    tbb::parallel_for_each(pack.closedTcpSessions, [&](const uint64_t sessionId) {
                        std::regex regexFilter(regex);
                        std::smatch match;
                        std::string payload(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(messyRoomPrefix + '/' + std::to_string(sessionId) + ".bin"s, std::ifstream::binary).rdbuf()).str());
                        if (!std::regex_search(payload, match, regexFilter)) {
                            try {
                                sessions2.erase(sessionId);
                                usage.erase(sessionId);
                                rtts.erase(sessionId);
                                std::filesystem::remove(messyRoomPrefix + '/' + std::to_string(sessionId) + ".bin"s);
                            } catch (std::exception &e) {
                                logger.log("Exception occurred. Details: "s + e.what());
                            } catch (...) {
                                logger.log("Exception occurred. Details unknown."s);
                            }
                        }
                    });
                });
        },
        resultPacks);
}

void FeedRefinerDataStreams::finalize()
{
    // regex-filter all the remaining sessions
    if (trackPayload) {
        // filter and delete UDP and non-closed TCP sessions
        std::vector<uint64_t> sessionIdsToFilter;
        sessionIdsToFilter.reserve(sessions2.size() / 2);
        for (const auto &pair : sessions2)
            if (pair.second.payloadProtocol == 0x11 || (pair.second.payloadProtocol == 0x06 && (pair.second.status & SuperCodex::Session::STREAMCLOSED) == 0))
                sessionIdsToFilter.push_back(pair.first);
        if (regex != ".*") // exception handling: we'll include everything. this is related with a bug where std::regex_search crashes with too long lines(29086 characters or more) on Linux libc++
            tbb::parallel_for_each(sessionIdsToFilter, [&](const uint64_t sessionId) {
                std::regex regexFilter(regex);
                std::smatch match;
                std::string payload(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(messyRoomPrefix + '/' + std::to_string(sessionId) + ".bin"s, std::ifstream::binary).rdbuf()).str());
                if (!std::regex_search(payload, match, regexFilter)) {
                    sessions2.erase(sessionId);
                    usage.erase(sessionId);
                    rtts.erase(sessionId);
                    std::filesystem::remove(messyRoomPrefix + '/' + std::to_string(sessionId) + ".bin"s);
                }
            });
    }

    // sort records per timestamp of session start
    itemsCount = sessions2.size();
    std::vector<ResultRecord> recordsToSave;
    recordsToSave.reserve(itemsCount);
    for (const auto &pair : sessions2) {
        tbb::concurrent_hash_map<uint64_t, std::pair<int64_t, int64_t>>::const_accessor a;
        if (usage.find(a, pair.first)) {
            const auto &usageTarget = a->second;

            // determine RTT / timeout
            int64_t rtt = -1; // default = timeout
            if (!timeouts.contains(pair.first)) {
                tbb::concurrent_hash_map<uint64_t, ValuesRtt>::const_accessor b;
                if (rtts.find(b, pair.first))
                    rtt = b->second.represent();
            }

            // build record
            if (pair.second.sourceIsSmall)
                recordsToSave.push_back(ResultRecord{pair.second, usageTarget.first, usageTarget.second, rtt});
            else
                recordsToSave.push_back(ResultRecord{pair.second, usageTarget.second, usageTarget.first, rtt});
        } else
            logger.log("Recovery from assertion failure: no BPS record. Session ID: "s + std::to_string(pair.first));
    }
    std::sort(recordsToSave.begin(), recordsToSave.end(), [](const ResultRecord &a, const ResultRecord &b) { return SuperCodex::isPast(a.session.first.second, a.session.first.nanosecond, b.session.first.second, b.session.first.nanosecond); });

    // save result
    std::ofstream file(messyRoomPrefix + "/sessions"s, std::ios::binary | std::ios::out);
    file.write((const char *) recordsToSave.data(), recordsToSave.size() * resultRecordLength);

    // log
    logger.log("Results ready to serve: "s + std::to_string(itemsCount));
}

void FeedRefinerDataStreams::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    if (parameters.contains("payload"s)) {
        std::string sessionId = parameters.at("payload");
        logger.log("Send stream: "s + sessionId);
        Civet7::respond200(connection, nullptr, 0, "application/octet-stream");

        std::ifstream fileStream(messyRoomPrefix + '/' + sessionId + ".bin"s, std::ifstream::binary);
        char buffer[1048576];
        fileStream.read(buffer, 1048576);
        size_t bufferRead = fileStream.gcount();
        while (bufferRead) {
            switch (mg_send_chunk(connection, buffer, bufferRead)) {
            case 0:
                logger.log("Client closed socket. Cancelling operation."s);
                return;
            case -1:
                logger.log("Server encountered an error. Cancelling operation."s);
                mg_send_chunk(connection, "Server encountered an error. Cancelling operation.", 0);
                return;
            }

            fileStream.read(buffer, 1048576);
            bufferRead = fileStream.gcount();
        }

        // send final chunk
        mg_send_chunk(connection, "", 0);
    } else if (parameters.contains("type") && parameters.at("type") == "summary")
        resultsSummary(connection);
    else {
        // build JSON
        std::string temp;
        std::ifstream file(messyRoomPrefix + "/sessions"s, std::ios::binary);
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootObject = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootObject);

        // add view hint
        yyjson_mut_val *viewhintObject = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, rootObject, "viewhint", viewhintObject);
        yyjson_mut_obj_add_int(document, viewhintObject, "records", itemsCount);

        // prepare to add main data
        yyjson_mut_val *dataArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "data", dataArray);

        // read first record
        ResultRecord record;
        file.read((char *) &record, resultRecordLength);
        int32_t counter = 0;
        SubSystems::FqdnGetter getter;
        while (file.gcount()) {
            const auto &session = record.session;
            // check boundary
            ++counter;
            if (counter < from) {
                file.read((char *) &record, resultRecordLength);
                continue;
            }
            if (counter >= to)
                break;

            // build object
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(dataArray, object);

            yyjson_mut_val *startArray = yyjson_mut_arr(document);
            yyjson_mut_obj_add_val(document, object, "start", startArray);
            yyjson_mut_arr_add_int(document, startArray, session.first.second);
            yyjson_mut_arr_add_int(document, startArray, session.first.nanosecond);

            yyjson_mut_val *endArray = yyjson_mut_arr(document);
            yyjson_mut_obj_add_val(document, object, "end", endArray);
            yyjson_mut_arr_add_int(document, endArray, session.last.second);
            yyjson_mut_arr_add_int(document, endArray, session.last.nanosecond);

            yyjson_mut_val *clientObject = yyjson_mut_obj(document);
            yyjson_mut_obj_add_val(document, object, "client", clientObject);
            describeEdge(getter, document, clientObject, SuperCodex::sourceIp(session), session.sourcePort);

            yyjson_mut_val *serverObject = yyjson_mut_obj(document);
            yyjson_mut_obj_add_val(document, object, "server", serverObject);
            describeEdge(getter, document, serverObject, SuperCodex::destinationIp(session), session.destinationPort);

            switch (session.payloadProtocol) {
            case 0x06: // TCP
                yyjson_mut_obj_add_strn(document, object, "payloadprotocol", "tcp", 3);
                break;
            case 0x11: // UDP
                yyjson_mut_obj_add_strn(document, object, "payloadprotocol", "udp", 3);
                break;
            default:
                yyjson_mut_obj_add_strn(document, object, "payloadprotocol", "other", 5);
                break;
            }
            temp = SuperCodex::l7ProtocolToString(session.detectedL7);
            yyjson_mut_obj_add_strncpy(document, object, "detectedl7", temp.data(), temp.size());
            temp = std::to_string(session.id);
            yyjson_mut_obj_add_strncpy(document, object, "sessionid", temp.data(), temp.size());
            yyjson_mut_obj_add_int(document, object, "ip1toip2", record.fromClientToServer);
            yyjson_mut_obj_add_int(document, object, "ip2toip1", record.fromServerToClient);
            yyjson_mut_obj_add_int(document, object, "rtt", record.rtt);
            if (trackPayload) {
                std::ifstream payloadFile(messyRoomPrefix + '/' + std::to_string(session.id) + ".bin"s, std::ios::binary);
                char *readBuffer = new char[100];
                payloadFile.read(readBuffer, 100);
                temp = SuperCodex::stringToHex(std::string(readBuffer, payloadFile.gcount()));
                yyjson_mut_obj_add_strncpy(document, object, "payloadhead", temp.data(), temp.size());
                delete[] readBuffer;
            }

            // read next record
            file.read((char *) &record, resultRecordLength);
        }
        file.close();
        Civet7::respond200(connection, document);
    }
}

void FeedRefinerDataStreams::resultsSummary(mg_connection *connection)
{
    // prepare for values
    struct Summary
    {
        int64_t min = INT64_MAX, max = INT64_MIN, sum = 0, count = 0;
    } summaryBytes, summaryRtts;
    int64_t timeouts = 0;

    // read records
    ResultRecord record;
    std::ifstream file(messyRoomPrefix + "/sessions"s, std::ios::binary);
    file.read((char *) &record, resultRecordLength);
    while (file.gcount()) {
        // set summary for bytes
        const auto trafficSum = record.fromClientToServer + record.fromServerToClient;
        summaryBytes.sum += trafficSum;
        ++summaryBytes.count;
        if (trafficSum > summaryBytes.max)
            summaryBytes.max = trafficSum;
        if (trafficSum < summaryBytes.min)
            summaryBytes.min = trafficSum;

        // set summary for RTTs and timeouts
        if (record.rtt == -1)
            ++timeouts;
        else {
            summaryRtts.sum += record.rtt;
            ++summaryRtts.count;
            if (record.rtt > summaryRtts.max)
                summaryRtts.max = record.rtt;
            if (record.rtt < summaryRtts.min)
                summaryRtts.min = record.rtt;
        }

        // read next record
        file.read((char *) &record, resultRecordLength);
    }
    file.close();

    // build JSON
    std::string temp;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);
    // bytes
    yyjson_mut_val *recordBytes = yyjson_mut_obj(document);
    yyjson_mut_obj_add_val(document, rootObject, "bytes", recordBytes);
    yyjson_mut_obj_add_sint(document, recordBytes, "min", summaryBytes.min);
    yyjson_mut_obj_add_sint(document, recordBytes, "max", summaryBytes.max);
    yyjson_mut_obj_add_sint(document, recordBytes, "avg", summaryBytes.count ? summaryBytes.sum / summaryBytes.count : 0);
    // RTTs
    yyjson_mut_val *recordRtts = yyjson_mut_obj(document);
    yyjson_mut_obj_add_val(document, rootObject, "rtts", recordRtts);
    yyjson_mut_obj_add_sint(document, recordRtts, "min", summaryRtts.min);
    yyjson_mut_obj_add_sint(document, recordRtts, "max", summaryRtts.max);
    yyjson_mut_obj_add_sint(document, recordRtts, "avg", summaryRtts.count ? summaryRtts.sum / summaryRtts.count : -1);
    // timeouts
    yyjson_mut_obj_add_sint(document, rootObject, "timeouts", timeouts);

    Civet7::respond200(connection, document);
}

void FeedRefinerDataStreams::dumpResults(mg_connection *connection)
{
    std::string chunk("Start\tEnd\tSourceIP\tSourceAlias\tSourceTag\tSourceDomains\tSourcePort\tDestinationIP\tDestinationAlias\tDestinationTag\tDestinationDomains\tDestinationPort\tPayloadProtocol\tL7Protocol\tSrcToDst\tDstToSrc\tRTT\n"s), temp;
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // read first record
    SubSystems::FqdnGetter getter;
    std::ifstream file(messyRoomPrefix + "/sessions"s, std::ios::binary);
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);
    ResultRecord record;
    file.read((char *) &record, resultRecordLength);
    while (file.gcount()) {
        const auto &session = record.session;
        chunk.append(epochToIsoDate(session.first.second) + '+' + std::to_string(static_cast<double>(session.first.nanosecond) / 1000000000)).push_back('\t');
        chunk.append(epochToIsoDate(session.last.second) + '+' + std::to_string(static_cast<double>(session.last.nanosecond) / 1000000000)).push_back('\t');
        describeEdge(getter, chunk, SuperCodex::sourceIp(session), session.sourcePort);
        describeEdge(getter, chunk, SuperCodex::destinationIp(session), session.destinationPort);
        // payload protocol
        switch (session.payloadProtocol) {
        case 0x06: // TCP
            chunk.append("tcp\t"s);
            break;
        case 0x11: // UDP
            chunk.append("udp\t"s);
            break;
        default:
            chunk.append("other\t"s);
            break;
        }
        chunk.append(SuperCodex::l7ProtocolToString(session.detectedL7)).push_back('\t');
        chunk.append(std::to_string(record.fromClientToServer) + '\t').append(std::to_string(record.fromServerToClient)).append(std::to_string(record.rtt)).push_back('\n');

        // flush chunk if its size is over 100MB
        if (chunk.size() > 100000000) {
            switch (mg_send_chunk(connection, chunk.data(), chunk.size())) {
            case 0:
                logger.log("Client closed socket. Cancelling operation."s);
                return;
            case -1:
                logger.log("Server encountered an error. Cancelling operation."s);
                mg_send_chunk(connection, "Server encountered an error. Cancelling operation.", 0);
                return;
            default:
                chunk.clear();
            }
        }

        // read next record
        file.read((char *) &record, resultRecordLength);
    }

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

FeedRefinerServices::FeedRefinerServices(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerServices"s);
}

void FeedRefinerServices::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    tbb::parallel_for(
        tbb::blocked_range<int>(0, codices.size()),
        [&](tbb::blocked_range<int> r) {
            for (int i = r.begin(); i < r.end(); ++i) {
                for (const auto pair : codices[i]->sessions)
                    if (SuperCodex::castType(*pair.second))
                        mergeSession(pair.second);
            }
        },
        affinityPartitioner);
}

void FeedRefinerServices::finalize()
{
    std::function<size_t(const int8_t, const std::string, const uint8_t, const std::string)> buildResult = [&](const int8_t ipLength, const std::string prefix, const uint8_t protocolNumber, const std::string suffix) -> size_t {
        // build result
        ankerl::unordered_dense::map<RecordService, ankerl::unordered_dense::map<std::string, int64_t>, RecordServiceHash, RecordServiceEqual> organized; // service + <client IP + client hits>
        RecordService key;
        for (const auto &pair : sessions2) {
            const auto &session = pair.second;
            if (session.payloadProtocol == protocolNumber) {
                const auto ipLengthInSession = SuperCodex::ipLength(session.etherType);
                if (ipLength == ipLengthInSession) {
                    // build key information
                    key.ipLength = ipLength;
                    memcpy(key.ip, session.ips + ipLength, key.ipLength);
                    key.port = session.destinationPort;
                    key.detectedL7 = session.detectedL7;

                    // count number of sessions per client
                    ++organized[key][std::string((const char *) session.ips, ipLength)];
                }
            }
        }

        // count number of clients and sort keys
        std::vector<RecordService> keys;
        keys.reserve(organized.size());
        for (const auto &pair : organized) {
            keys.push_back(pair.first);
            keys.back().numberOfClients = pair.second.size();
        }
        std::sort(keys.begin(), keys.end(), [](const RecordService &a, const RecordService &b) -> bool { return memcmp(&a, &b, recordServiceSize) < 0; });

        // build hits offset
        int64_t offset = 0;
        for (auto &key : keys) {
            key.hitsOffset = offset;
            offset += key.numberOfClients;
        }

        // save keys
        std::ofstream file;
        file.open(messyRoomPrefix + prefix + "keys"s + suffix, std::ios::binary | std::ios::out);
        file.write((const char *) keys.data(), keys.size() * recordServiceSize);
        file.close();

        // save client hits
        file.open(messyRoomPrefix + prefix + "hits"s + suffix, std::ios::binary | std::ios::out);
        RecordClient clientBuffer;
        std::vector<RecordClient> clientsSorted;
        for (const auto &key : keys) {
            const auto &clients = organized.at(key);
            // prepare for client records
            clientsSorted.clear();
            clientsSorted.reserve(clients.size());
            for (const auto &pair : clients) {
                clientBuffer.ipLength = pair.first.size();
                memcpy(clientBuffer.ip, pair.first.data(), clientBuffer.ipLength);
                clientBuffer.hitCount = pair.second;
                clientsSorted.push_back(clientBuffer);
            }
            // sort client records per IP
            std::sort(clientsSorted.begin(), clientsSorted.end(), [](const RecordClient &a, const RecordClient &b) -> bool { return a.ipLength < b.ipLength || (a.ipLength == b.ipLength && memcmp(&a, &b, a.ipLength) < 0); });

            // save client records
            file.write((const char *) clientsSorted.data(), clientsSorted.size() * recordClientSize);
        }
        file.close();

        return organized.size();
    };
    std::vector<std::future<size_t>> synchronizer;
    synchronizer.push_back(std::async(buildResult, 4, "/v4", 0x06, "tcp"s));
    synchronizer.push_back(std::async(buildResult, 4, "/v4", 0x11, "udp"s));
    synchronizer.push_back(std::async(buildResult, 16, "/v6", 0x06, "tcp"s));
    synchronizer.push_back(std::async(buildResult, 16, "/v6", 0x11, "udp"s));
    for (auto &future : synchronizer)
        future.wait();

    // log
    for (size_t i = 0; i < 4; ++i)
        servicesCount[i] = synchronizer.at(i).get();
    logger.log("Results ready to serve: "s + std::to_string(servicesCount[0]) + " / "s + std::to_string(servicesCount[1]) + " / "s + std::to_string(servicesCount[2]) + " / "s + std::to_string(servicesCount[3]));
}

void FeedRefinerServices::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // prepare for JSON builder objects and variables
    SubSystems::FqdnGetter getter;
    std::string temp;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);

    // add view hint
    yyjson_mut_val *viewhintObject = yyjson_mut_obj(document);
    yyjson_mut_obj_add_val(document, rootObject, "viewhint", viewhintObject);
    yyjson_mut_obj_add_int(document, viewhintObject, "tcp", servicesCount[0]);
    yyjson_mut_obj_add_int(document, viewhintObject, "udp", servicesCount[1]);
    yyjson_mut_obj_add_int(document, viewhintObject, "tcp6", servicesCount[2]);
    yyjson_mut_obj_add_int(document, viewhintObject, "udp6", servicesCount[3]);

    // build actual list
    yyjson_mut_val *targetArray;
    std::function<void(const std::string &, const std::string &)> writeJson = [&](const std::string &keysFile, const std::string &hitsFile) {
        // prepare for file handles and stand ready cursors
        std::ifstream keys(keysFile, std::ios::binary), hits(hitsFile, std::ios::binary);
        keys.seekg(from * recordServiceSize, std::ios::beg);
        RecordService key;
        RecordClient hit;

        // read first record
        keys.read((char *) &key, recordServiceSize);
        if (to == UINT32_MAX)
            --to; // overflow guard (to-from+1=0)
        for (uint32_t i = 0, iEnd = to - from; i < iEnd && keys.gcount(); ++i) {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(targetArray, object);

            // describe server
            yyjson_mut_val *serverObject = yyjson_mut_obj(document);
            yyjson_mut_obj_add_val(document, object, "server", serverObject);
            describeEdge(getter, document, serverObject, std::string(key.ip, key.ipLength), key.port);
            temp = SuperCodex::l7ProtocolToString(key.detectedL7);
            yyjson_mut_obj_add_strncpy(document, object, "l7protocol", temp.data(), temp.size());

            // clients which accessed the service
            yyjson_mut_val *clientHitsArray = yyjson_mut_arr(document);
            yyjson_mut_obj_add_val(document, object, "clienthits", clientHitsArray);
            long long totalHits = 0;
            hits.seekg(key.hitsOffset * recordClientSize, std::ios::beg);
            hits.read((char *) &hit, recordClientSize); // read first record
            for (int j = 0, jEnd = key.numberOfClients; j < jEnd && hits.gcount(); ++j) {
                yyjson_mut_val *object2 = yyjson_mut_obj(document);
                yyjson_mut_arr_append(clientHitsArray, object2);
                describeEdge(getter, document, object2, std::string(hit.ip, hit.ipLength));
                yyjson_mut_obj_add_int(document, object2, "hits", hit.hitCount);
                totalHits += hit.hitCount;

                // read next record
                hits.read((char *) &hit, recordClientSize); // read first record
            }
            yyjson_mut_obj_add_int(document, object, "totalhits", totalHits);

            // read next server record
            keys.read((char *) &key, recordServiceSize);
        }
    };

    // build JSON
    targetArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "tcp", targetArray);
    writeJson(messyRoomPrefix + "/v4keystcp"s, messyRoomPrefix + "/v4hitstcp"s);
    targetArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "tcp6", targetArray);
    writeJson(messyRoomPrefix + "/v6keystcp"s, messyRoomPrefix + "/v6hitstcp"s);
    targetArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "udp", targetArray);
    writeJson(messyRoomPrefix + "/v4keysudp"s, messyRoomPrefix + "/v4hitsudp"s);
    targetArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "udp6", targetArray);
    writeJson(messyRoomPrefix + "/v6keysudp"s, messyRoomPrefix + "/v6hitsudp"s);

    Civet7::respond200(connection, document);
}

void FeedRefinerServices::dumpResults(mg_connection *connection)
{
    SubSystems::FqdnGetter getter;
    std::string chunk("TCP Services(IPv4)\nServerIP\tServerAlias\tServerTag\tServerDomains\tServerPort\tL7Protocol\tClientIP\tClientAlias\tClientTag\tClientDomains\tClientHits\n"s), linePrefix;
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    std::function<void(const std::string &, const std::string &)> buildResult = [&](const std::string &keysFile, const std::string &hitsFile) {
        std::ifstream keys(keysFile, std::ios::binary), hits(hitsFile, std::ios::binary);
        std::unique_ptr<char[]> readBufferKeys(new char[268435456]), readBufferHits(new char[268435456]); // 256MB
        keys.rdbuf()->pubsetbuf(readBufferKeys.get(), 268435456);
        hits.rdbuf()->pubsetbuf(readBufferHits.get(), 268435456);
        RecordService key;
        RecordClient hit;
        // read first record
        keys.read((char *) &key, recordServiceSize);
        while (keys.gcount()) {
            linePrefix.clear();
            // service information
            describeEdge(getter, linePrefix, std::string(key.ip, key.ipLength), key.port);
            linePrefix.append(SuperCodex::l7ProtocolToString(key.detectedL7)).push_back('\t');

            // client hits
            hits.seekg(key.hitsOffset * recordClientSize, std::ios::beg);
            hits.read((char *) &hit, recordClientSize); // read first record
            for (int i = 0, iEnd = key.numberOfClients; i < iEnd && hits.gcount(); ++i) {
                chunk.append(linePrefix);
                describeEdge(getter, chunk, std::string(hit.ip, hit.ipLength));
                chunk.pop_back();
                chunk.pop_back(); // remove unnecessary two '\t's(but is needed elsewhere)
                chunk.append(std::to_string(hit.hitCount)).push_back('\n');

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

                hits.read((char *) &hit, recordClientSize); // read next record
            }

            // read next record
            keys.read((char *) &key, recordServiceSize);
        }
    };

    buildResult(messyRoomPrefix + "/v4keystcp"s, messyRoomPrefix + "/v4hitstcp"s);
    chunk.append("\nTCP Services(IPv6)\nServerIP\tServerAlias\tServerTag\tServerDomains\tServerPort\tL7Protocol\tClientIP\tClientAlias\tClientTag\tClientDomains\tClientHits\n"s);
    buildResult(messyRoomPrefix + "/v6keystcp"s, messyRoomPrefix + "/v6hitstcp"s);

    chunk.append("\nUDP Services(IPv4)\nServerIP\tServerTag\tServerDomains\tServerPort\tL7Protocol\tClientIP\tClientTag\tClientDomains\tClientHits\n"s);
    buildResult(messyRoomPrefix + "/v4keysudp"s, messyRoomPrefix + "/v4hitsudp"s);
    chunk.append("\nUDP Services(IPv6)\nServerIP\tServerTag\tServerDomains\tServerPort\tL7Protocol\tClientIP\tClientTag\tClientDomains\tClientHits\n"s);
    buildResult(messyRoomPrefix + "/v6keysudp"s, messyRoomPrefix + "/v6hitsudp"s);

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

FeedRefinerMacsPerIp::FeedRefinerMacsPerIp(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerMacsPerIp"s);

    // initialize hash map
    pairs = new ankerl::unordered_dense::map<std::string, ankerl::unordered_dense::set<std::string>>();
}

void FeedRefinerMacsPerIp::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    struct Intermediate
    {
        uint32_t secondStart = UINT32_MAX, secondEnd = 0; // timestamps
        ankerl::unordered_dense::map<std::string, ankerl::unordered_dense::set<std::string>> data; // IP + MAC address(deduplicated)
    };

    logger.log("Processing: "s + std::to_string(codices.size()));
    std::vector<Intermediate> resultParts = SuperCodex::parallel_convert<SuperCodex::Loader *, Intermediate>(codices, [&](const SuperCodex::Loader *codex) -> Intermediate {
        Intermediate intermediate;

        for (const SuperCodex::Packet *packet = codex->firstPacket(); packet; packet = codex->nextPacket(packet))
            if (SuperCodex::ipLength(codex->sessions.at(packet->sessionId)->etherType)) { // IP protocol only: SuperCodex::ipLength() will return number other than 0 if it's an IP protocol
                // save timestamp for start and end of the scope
                if (packet->second < intermediate.secondStart)
                    intermediate.secondStart = packet->second;
                if (packet->second > intermediate.secondEnd)
                    intermediate.secondEnd = packet->second;

                // save MAC address
                const auto &session = codex->sessions.at(packet->sessionId);
                if (conditions.allowedIps.isEmpty) { // IP filter not set: show all
                    if (session->sourceIsSmall == packet->fromSmallToBig) {
                        intermediate.data[SuperCodex::sourceIp(*session)].insert(std::string((const char *) packet->sourceMac, 6));
                        // intermediate.data[SuperCodex::destinationIp(*session)].insert(std::string((const char *)packet->destinationMac, 6));
                    } else {
                        // intermediate.data[SuperCodex::sourceIp(*session)].insert(std::string((const char *)packet->destinationMac, 6));
                        intermediate.data[SuperCodex::destinationIp(*session)].insert(std::string((const char *) packet->sourceMac, 6));
                    }
                } else { // IP filter is set: save MACs for only selected IPs
                    std::string sourceIp(SuperCodex::sourceIp(*session));
                    if (conditions.allowedIps.contains(sourceIp) && session->sourceIsSmall == packet->fromSmallToBig)
                        intermediate.data[sourceIp].insert(std::string((const char *) packet->sourceMac, 6));

                    std::string destinationIp(SuperCodex::destinationIp(*session));
                    if (conditions.allowedIps.contains(destinationIp) && session->sourceIsSmall != packet->fromSmallToBig)
                        intermediate.data[destinationIp].insert(std::string((const char *) packet->sourceMac, 6));
                }
            }

        return intermediate;
    });

    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](std::vector<Intermediate> resultRawsFuture) {
            for (const auto &resultRaw : resultRawsFuture) {
                // update timestamp
                if (secondStart > resultRaw.secondStart)
                    secondStart = resultRaw.secondStart;
                if (secondEnd < resultRaw.secondEnd)
                    secondEnd = resultRaw.secondEnd;

                // merge data
                for (const auto &pair : resultRaw.data)
                    if (pairs->count(pair.first)) {
                        auto &target = (*pairs)[pair.first];
                        for (const auto &mac : pair.second)
                            target.insert(mac);
                    } else
                        pairs->insert(pair);
            }
        },
        resultParts);
}

void FeedRefinerMacsPerIp::finalize()
{
    // prepare for saving
    ipsFound = pairs->size();
    std::ofstream file;

    // build IP list
    std::vector<RecordIp> ips;
    ips.reserve(pairs->size());
    RecordIp recordIp;
    for (const auto &pair : *pairs) {
        recordIp.ipLength = pair.first.size();
        memcpy(recordIp.ip, pair.first.data(), recordIp.ipLength);
        recordIp.numberOfMacs = pair.second.size();
        ips.push_back(recordIp);
    }

    // sort and save IP list
    std::sort(ips.begin(), ips.end(), [](const RecordIp &a, const RecordIp &b) -> bool { return a.ipLength < b.ipLength || (a.ipLength == b.ipLength && memcmp(a.ip, b.ip, a.ipLength) < 0); });
    file.open(messyRoomPrefix + "/ipsv4"s, std::ios::binary);
    file.write((const char *) ips.data(), ips.size() * recordIpSize);
    file.close();

    // save MAC addresses
    std::vector<std::string> macs;
    for (const auto &ip : ips) {
        std::string ipString(ip.ip, ip.ipLength);
        file.open(messyRoomPrefix + '/' + SuperCodex::stringToHex(ipString), std::ios::binary);
        // determine targe MAC addresses to put
        const auto &targetMacs = pairs->at(ipString);

        // sort by MAC address
        macs.clear();
        macs.reserve(targetMacs.size());
        for (const auto &mac : targetMacs)
            macs.push_back(mac);
        std::sort(macs.begin(), macs.end());

        // write to file
        std::string writeBuffer;
        writeBuffer.reserve(macs.size() * 6);
        for (const auto &mac : macs)
            writeBuffer.append(mac);
        file.write(writeBuffer.data(), writeBuffer.size());
        file.close();
    }

    // log
    delete pairs;
    logger.log("Results ready to serve: "s + std::to_string(ipsFound));
}

void FeedRefinerMacsPerIp::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // initialize YYJSON
    SubSystems::FqdnGetter getter;
    std::string temp;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);

    // add view hint
    yyjson_mut_val *viewhintObject = yyjson_mut_obj(document);
    yyjson_mut_obj_add_val(document, rootObject, "viewhint", viewhintObject);
    yyjson_mut_obj_add_int(document, viewhintObject, "records", ipsFound);

    // prepare to add main data
    yyjson_mut_val *dataArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "data", dataArray);

    // prepare for variables and objects
    std::ifstream ips(messyRoomPrefix + "/ipsv4"s, std::ios::binary), macs;
    ips.seekg(from * recordIpSize, std::ios::beg);
    char mac[6];
    RecordIp record;
    ips.read((char *) &record, recordIpSize); // read first record
    for (int i = 0, iEnd = to - from; i < iEnd && ips.gcount(); ++i) {
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(dataArray, object);

        yyjson_mut_val *ipObject = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, object, "ip", ipObject);
        describeEdge(getter, document, ipObject, std::string(record.ip, record.ipLength));

        yyjson_mut_val *macsArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, object, "macs", macsArray);
        macs.open(messyRoomPrefix + '/' + SuperCodex::stringToHex(std::string(record.ip, record.ipLength)), std::ios::binary);
        macs.read(mac, 6); // read first record
        for (int j = 0, jEnd = record.numberOfMacs; j < jEnd && macs.gcount(); ++j) {
            temp = SuperCodex::stringToHex(std::string(mac, 6));
            yyjson_mut_arr_add_strncpy(document, macsArray, temp.data(), temp.size());
            macs.read(mac, 6); // read next record
        }
        macs.close();

        // read next record
        ips.read((char *) &record, recordIpSize);
    }
    ips.close();

    Civet7::respond200(connection, document);
}

void FeedRefinerMacsPerIp::dumpResults(mg_connection *connection)
{
    SubSystems::FqdnGetter getter;
    std::string chunk("IP\tAlias\tTag\tDomains\tMAC\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    std::ifstream ips(messyRoomPrefix + "/ipsv4"s, std::ios::binary), macs;
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    ips.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);
    char mac[6];
    RecordIp record;
    // read first record
    ips.read((char *) &record, recordIpSize);
    while (ips.gcount()) {
        macs.open(messyRoomPrefix + '/' + SuperCodex::stringToHex(std::string(record.ip, record.ipLength)), std::ios::binary);
        macs.read(mac, 6); // read first record
        for (int i = 0, iEnd = record.numberOfMacs; i < iEnd && macs.gcount(); ++i) {
            describeEdge(getter, chunk, std::string(record.ip, record.ipLength));
            chunk.append(SuperCodex::stringToHex(std::string(mac, 6))).push_back('\n');
            macs.read(mac, 6); // read next record
        }
        macs.close();

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
        ips.read((char *) &record, recordIpSize);
    }

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

FeedRefinerOverview::FeedRefinerOverview(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerOverview"s);

    // initialize session store
    sessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();
    udpSessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();

    // set gatherBy
    gatherBy = conditions.parameters.at("gatherby"s);

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
        cachedChapter = SuperCodex::ChapterType::BPSPERSESSION; // actually, dummy(we need both BPSPERSESSION and PPSPERSESSION)
        logger.log("SuperCache applicable");
    }
}

void FeedRefinerOverview::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    // gather session information
    std::vector<Pack> resultParts = SuperCodex::parallel_convert<SuperCodex::Loader *, Pack>(
        codices,
        [&](const SuperCodex::Loader *codex) -> Pack {
            Pack result;

            // gather session information
            for (const auto &pair : codex->sessions) {
                const SuperCodex::Session *session = pair.second;
                // update timestamps
                if (result.secondStart > session->first.second)
                    result.secondStart = session->first.second;
                if (result.secondEnd < session->last.second)
                    result.secondEnd = session->last.second;

                // distribute session per payload protocol
                switch (session->payloadProtocol) {
                case 0x06:
                    result.tcpSessions.push_back(*session);
                    result.tcpSessionsIndex.insert(pair.first);
                    break; // TCP
                case 0x11:
                    result.udpSessions.push_back(*session);
                    result.udpSessionsIndex.insert(pair.first);
                    break; // UDP
                default:
                    break; // do nothing :P
                }
            }

            // count bytes and packets
            for (auto bps = codex->firstBpsPerSession(); bps; bps = codex->nextBpsPerSession(bps))
                if (result.tcpSessionsIndex.contains(bps->sessionId))
                    result.tcpValues[bps->sessionId].first += bps->fromSmallToBig + bps->fromBigToSmall;
                else if (result.udpSessionsIndex.contains(bps->sessionId))
                    result.udpValues[bps->sessionId].first += bps->fromSmallToBig + bps->fromBigToSmall;
            for (auto pps = codex->firstPpsPerSession(); pps; pps = codex->nextPpsPerSession(pps))
                if (result.tcpSessionsIndex.contains(pps->sessionId))
                    result.tcpValues[pps->sessionId].second += pps->fromSmallToBig + pps->fromBigToSmall;
                else if (result.udpSessionsIndex.contains(pps->sessionId))
                    result.udpValues[pps->sessionId].second += pps->fromSmallToBig + pps->fromBigToSmall;

            return result;
        },
        affinityPartitioner);

    // merge extracted data to result data
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Pack> resultRawsFuture) {
            // background: merge session information and values for TCP
            std::thread mergeTcpValuesThread([&]() {
                // merge values
                for (const auto &resultRaw : resultRawsFuture)
                    for (const auto &pair : resultRaw.tcpValues)
                        if (tcpValues.contains(pair.first)) {
                            auto &target = tcpValues[pair.first];
                            target.first += pair.second.first;
                            target.second += pair.second.second;
                        } else
                            tcpValues.insert(pair);
            });
            std::thread mergeTcpSessionsThread([&]() {
                // update timestamp and session information
                for (const auto &resultRaw : resultRawsFuture)
                    updateTimestampAndMergeSessions(resultRaw.tcpSessions);
            });

            // merge data for UDP
            for (const auto &resultRaw : resultRawsFuture) {
                // update session information
                for (const auto &session : resultRaw.udpSessions)
                    if (udpSessions->count(session.id))
                        (*udpSessions)[session.id].last = session.last;
                    else
                        (*udpSessions)[session.id] = session;

                // merge values
                for (const auto &resultRaw : resultRawsFuture)
                    for (const auto &pair : resultRaw.udpValues)
                        if (udpValues.contains(pair.first)) {
                            auto &target = udpValues[pair.first];
                            target.first += pair.second.first;
                            target.second += pair.second.second;
                        } else
                            udpValues.insert(pair);
            }

            // wait for TCP session merging to begin timestamp update with UDP sessions
            mergeTcpSessionsThread.join();

            // update timestamp with UDP values as needed
            for (const auto &resultRaw : resultRawsFuture)
                for (const auto &session : resultRaw.udpSessions) {
                    if (secondStart > session.first.second)
                        secondStart = session.first.second;
                    if (secondEnd < session.last.second)
                        secondEnd = session.last.second;
                }

            // wait for remaining background jobs to be completed
            mergeTcpValuesThread.join();
        },
        resultParts);
}

void FeedRefinerOverview::finalize()
{
    // determine IP combination
    std::function<std::string(const SuperCodex::Session &)> extractIp;
    if (gatherBy == "source"s)
        extractIp = [&](const SuperCodex::Session &session) -> std::string { return SuperCodex::sourceIp(session); };
    else if (gatherBy == "destination"s)
        extractIp = [&](const SuperCodex::Session &session) -> std::string { return SuperCodex::destinationIp(session); };
    else if (gatherBy == "iptoservice"s)
        extractIp = [&](const SuperCodex::Session &session) -> std::string { return SuperCodex::sourceIp(session) + SuperCodex::destinationIp(session); };

    // get total bytes and packets
    for (const auto &pair : tcpValues) {
        totalBytes += pair.second.first;
        totalPackets += pair.second.second;
    }
    for (const auto &pair : udpValues) {
        totalBytes += pair.second.first;
        totalPackets += pair.second.second;
    }

    // build result
    std::future<int64_t> buildResultTcpFuture = std::async([&]() -> int64_t { return buildResult(sessions, &tcpValues, extractIp, messyRoomPrefix + "/v4tcpports"s, messyRoomPrefix + "/v4tcpdescriptions"s); });
    std::future<int64_t> buildResultUdpFuture = std::async([&]() -> int64_t { return buildResult(udpSessions, &udpValues, extractIp, messyRoomPrefix + "/v4udpports"s, messyRoomPrefix + "/v4udpdescriptions"s); });
    buildResultTcpFuture.wait();
    buildResultUdpFuture.wait();

    // free memory and save result
    tcpRecords = buildResultTcpFuture.get();
    udpRecords = buildResultUdpFuture.get();
    delete udpSessions;
    logger.log("Results ready to serve: "s + std::to_string(tcpRecords) + " / "s + std::to_string(udpRecords) + " records."s);
}

int64_t FeedRefinerOverview::buildResult(const ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session> *sessionsToGo, const ankerl::unordered_dense::segmented_map<uint64_t, std::pair<int64_t, int64_t>> *valuesToGo, std::function<std::string(const SuperCodex::Session &)> extractIp, const std::string &portsFileName, const std::string &descriptionsFileName)
{
    // prepare to build result
    ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> result; // port number + < IP addresses + <bytes+packets> >

    // determine SuperCache read condition: IP length and payload protocol(TCP or UDP)
    int8_t ipLength = 0, payloadProtocol = 0;
    switch (portsFileName[portsFileName.size() - 9]) { // IP version in terms of IP length
    case '4':
        ipLength = 4;
        break;
    case '6':
        ipLength = 16;
        break;
    }
    const std::string_view payloadProtocolRaw(&portsFileName[portsFileName.size() - 8], 3); // payload protocol
    if (payloadProtocolRaw == "tcp"s)
        payloadProtocol = 6;
    else if (payloadProtocolRaw == "udp"s)
        payloadProtocol = 17;
    std::function<std::string(const FeedRefinerTopN::KeyIpToService &)> getIp; // IP(s) to obtain
    if (gatherBy == "source"s)
        getIp = [&](const FeedRefinerTopN::KeyIpToService &head) -> std::string { return std::string(head.ip1, head.ipLength); };
    else if (gatherBy == "destination"s)
        getIp = [&](const FeedRefinerTopN::KeyIpToService &head) -> std::string { return std::string(head.ip2, head.ipLength); };
    else if (gatherBy == "iptoservice"s)
        getIp = [&](const FeedRefinerTopN::KeyIpToService &head) -> std::string { return std::string(head.ip1, head.ipLength) + std::string(head.ip2, head.ipLength); };

    // merge result from SuperCache first. SuperCodex data is merged later to optimize data insertion
    switch (pmpiCacheMode) {
    case FULL:
        result = readSuperCachePmpi(
            [&](const std::string_view &raw, ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> &intermediate) {
                for (const char *cursor = raw.data(), *cursorEnd = cursor + raw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService) {
                    const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> *item = (const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> *) cursor;
                    const auto &head = item->first;
                    if (head.ipLength == ipLength && head.payloadProtocol == payloadProtocol)
                        intermediate[head.port2][getIp(head)].first += item->second;
                }
            },
            [&](const std::string_view &raw, ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> &intermediate) {
                for (const char *cursor = raw.data(), *cursorEnd = cursor + raw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService) {
                    const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> *item = (const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> *) cursor;
                    const auto &head = item->first;
                    if (head.ipLength == ipLength && head.payloadProtocol == payloadProtocol)
                        intermediate[head.port2][getIp(head)].second += item->second;
                }
            });
        break;
    case FILTERED:
        result = readSuperCachePmpi(
            [&](const std::string_view &raw, ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> &intermediate) {
                const auto keyFilter = KeyIpToServiceFilter(conditions);
                for (const char *cursor = raw.data(), *cursorEnd = cursor + raw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService) {
                    const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> *item = (const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> *) cursor;
                    const auto &head = item->first;
                    if (head.ipLength == ipLength && head.payloadProtocol == payloadProtocol && keyFilter.accept(head))
                        intermediate[head.port2][getIp(head)].first += item->second;
                }
            },
            [&](const std::string_view &raw, ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> &intermediate) {
                const auto keyFilter = KeyIpToServiceFilter(conditions);
                for (const char *cursor = raw.data(), *cursorEnd = cursor + raw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService) {
                    const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> *item = (const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> *) cursor;
                    const auto &head = item->first;
                    if (head.ipLength == ipLength && head.payloadProtocol == payloadProtocol && keyFilter.accept(head))
                        intermediate[head.port2][getIp(head)].second += item->second;
                }
            });
        break;
    case NONE:
        // do nothing
        break;
    }

    // merge result from SuperCodex
    for (const auto &pair : *sessionsToGo) {
        const auto &session = pair.second;
        if (!valuesToGo->contains(pair.first)) {
            logger.oops("Session ID not found from values(may have been covered in SuperCache phase): "s + std::to_string(pair.first));
            continue;
        }
        const auto &values = valuesToGo->at(pair.first);
        result[session.destinationPort][extractIp(session)].first += values.first;
        result[session.destinationPort][extractIp(session)].second += values.second;
    }

    // prepare for port information
    std::vector<RecordPort> ports;
    ports.reserve(result.size());
    for (const auto &pair : result)
        ports.push_back(RecordPort{pair.first, static_cast<int64_t>(0), static_cast<int64_t>(pair.second.size())});
    std::sort(ports.begin(), ports.end(), [](const RecordPort &a, const RecordPort &b) -> bool { return a.port < b.port; });
    int64_t offset = 0;
    for (auto &port : ports) {
        port.ipOffset += offset;
        offset += port.numberOfIps;
    }

    std::ofstream file;

    // save port information
    file.open(portsFileName, std::ios::binary);
    file.write((const char *) ports.data(), ports.size() * recordPortSize);
    file.close();

    // reserve buffer to save descriptions
    std::vector<RecordDescription> descriptions;
    RecordDescription recordDescriptionBuffer;
    file.open(descriptionsFileName, std::ios::binary);
    for (const RecordPort &port : ports) {
        descriptions.clear();
        descriptions.reserve(result.at(port.port).size());
        for (const auto &targetDescription : result.at(port.port)) {
            recordDescriptionBuffer.ipLength = targetDescription.first.size();
            memcpy(recordDescriptionBuffer.ip, targetDescription.first.data(), recordDescriptionBuffer.ipLength);
            recordDescriptionBuffer.bytes = targetDescription.second.first;
            recordDescriptionBuffer.packets = targetDescription.second.second;
            descriptions.push_back(recordDescriptionBuffer);
        }
        // sort save descriptions per IP
        std::sort(descriptions.begin(), descriptions.end(), [](const RecordDescription &a, const RecordDescription &b) -> bool { return a.ipLength < b.ipLength || (a.ipLength == b.ipLength && memcmp(a.ip, b.ip, a.ipLength) < 0); });
        file.write((const char *) descriptions.data(), descriptions.size() * recordDescriptionSize);
    }
    file.close();

    // return number of service ports found
    return result.size();
}

ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> FeedRefinerOverview::readSuperCachePmpi(std::function<void(const std::string_view &, ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> &)> insertByteCount, std::function<void(const std::string_view &, ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> &)> insertPacketCount)
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

    // prepare for database connection
    auto intermediates = SuperCodex::parallel_convert<Segment, ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>>>(timestamps, [&](const Segment &segment) -> ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> {
        ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> intermediate;

        // function to process records
        std::function<void(const int, std::function<void(const std::string_view &, ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> &)>)> extract = [&](const int chapterType, std::function<void(const std::string_view &, ankerl::unordered_dense::map<uint16_t, ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>>> &)> todo) {
            FeatherLite feather(CodexIndex::feedRoot + conditions.dataFeed + "/supercache.pmpi"s, SQLITE_OPEN_READONLY);
            feather.prepare("SELECT originalsize,filepath FROM rows WHERE timestamp>=? AND timestamp<=? AND chapter=?;"s);
            feather.bindInt(1, segment.from);
            feather.bindInt(2, segment.to);
            feather.bindInt(3, chapterType);

            while (feather.next() == SQLITE_ROW) {
                auto pmpiTriplet = SuperCache::getPmpiTriplet(std::string(feather.getText(1)), feather.getInt(0));
                if (pmpiTriplet.decompressedRaw == nullptr)
                    continue;
                todo(pmpiTriplet.perIpToServiceRaw, intermediate);
                delete[] pmpiTriplet.decompressedRaw;
            }

            // finalize
            feather.reset();
            feather.finalize();
        };

        // do it
        extract(SuperCodex::ChapterType::BPSPERSESSION, insertByteCount);
        extract(SuperCodex::ChapterType::PPSPERSESSION, insertPacketCount);

        return intermediate;
    });

    // merge intermediates
    auto result = intermediates.back();
    intermediates.pop_back();
    for (const auto &item : intermediates)
        for (const auto &portPair : item)
            for (const auto &ipPair : portPair.second) {
                auto &target = result[portPair.first][ipPair.first];
                target.first = ipPair.second.first;
                target.second = ipPair.second.second;
            }
    return result;
}

void FeedRefinerOverview::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // check whether this is the request for special purpose
    if (parameters.contains("type"s)) {
        const std::string &type = parameters.at("type"s);
        if (type == "summary"s) {
            resultsInteractiveSummary(connection);
            return;
        } else if (type == "viewhint"s) {
            yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
            yyjson_mut_val *rootObject = yyjson_mut_obj(document);
            yyjson_mut_doc_set_root(document, rootObject);
            yyjson_mut_obj_add_int(document, rootObject, "tcp", tcpRecords);
            yyjson_mut_obj_add_int(document, rootObject, "udp", udpRecords);
            Civet7::respond200(connection, document);
            return;
        }
    }

    // prepare for stuff
    SubSystems::FqdnGetter getter;
    std::string temp;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);

    // add view hint
    yyjson_mut_val *viewhintObject = yyjson_mut_obj(document);
    yyjson_mut_obj_add_val(document, rootObject, "viewhint", viewhintObject);
    yyjson_mut_obj_add_int(document, viewhintObject, "tcp", tcpRecords);
    yyjson_mut_obj_add_int(document, viewhintObject, "udp", udpRecords);

    std::function<void(yyjson_mut_val *, const std::string &)> writeIp;
    if (gatherBy == "iptoservice")
        writeIp = [&](yyjson_mut_val *object, const std::string &ipRaw) {
            yyjson_mut_val *ipObject = yyjson_mut_obj(document);
            yyjson_mut_obj_add_val(document, object, "ip", ipObject);
            describeEdge(getter, document, ipObject, ipRaw.substr(0, ipRaw.size() / 2));
            yyjson_mut_val *ip2Object = yyjson_mut_obj(document);
            yyjson_mut_obj_add_val(document, object, "ip2", ip2Object);
            describeEdge(getter, document, ip2Object, ipRaw.substr(ipRaw.size() / 2));
        };
    else
        writeIp = [&](yyjson_mut_val *object, const std::string &ipRaw) {
            yyjson_mut_val *ipObject = yyjson_mut_obj(document);
            yyjson_mut_obj_add_val(document, object, "ip", ipObject);
            describeEdge(getter, document, ipObject, ipRaw);
        };

    // start writing
    RecordPort portBuffer;
    RecordDescription descriptionBuffer;
    std::ifstream file, descriptionsFile;

    // overall descriptions
    yyjson_mut_obj_add_strncpy(document, rootObject, "gatherby", gatherBy.data(), gatherBy.size());
    int denominator = secondEnd - secondStart + 1;
    yyjson_mut_obj_add_int(document, rootObject, "averagebps", totalBytes / denominator);
    yyjson_mut_obj_add_int(document, rootObject, "averagepps", totalPackets / denominator);
    yyjson_mut_obj_add_int(document, rootObject, "totalbytes", totalBytes);
    yyjson_mut_obj_add_int(document, rootObject, "totalpackets", totalPackets);

    // statistics per TCP port
    yyjson_mut_val *tcpArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "tcp", tcpArray);
    // read first record
    descriptionsFile.open(messyRoomPrefix + "/v4tcpdescriptions"s, std::ios::binary);
    file.open(messyRoomPrefix + "/v4tcpports"s, std::ios::binary);
    file.seekg(from * recordPortSize, std::ios::beg);
    file.read((char *) &portBuffer, recordPortSize); // read first record
    for (int i = 0, iEnd = to - from; i < iEnd && file.gcount(); ++i) {
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(tcpArray, object);

        yyjson_mut_obj_add_int(document, object, "port", portBuffer.port);
        yyjson_mut_val *perIpArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, object, "perip", perIpArray);
        descriptionsFile.seekg(portBuffer.ipOffset * recordDescriptionSize, std::ios::beg);
        descriptionsFile.read((char *) &descriptionBuffer, recordDescriptionSize); // read first record
        for (int j = 0, jEnd = portBuffer.numberOfIps; j < jEnd; ++j) {
            yyjson_mut_val *object2 = yyjson_mut_obj(document);
            yyjson_mut_arr_add_val(perIpArray, object2);
            writeIp(object2, std::string(descriptionBuffer.ip, descriptionBuffer.ipLength));
            yyjson_mut_obj_add_int(document, object2, "packets", descriptionBuffer.packets);
            yyjson_mut_obj_add_int(document, object2, "bytes", descriptionBuffer.bytes);

            // read next record
            descriptionsFile.read((char *) &descriptionBuffer, recordDescriptionSize);
        }

        // read next record
        file.read((char *) &portBuffer, recordPortSize);
    }
    file.close();
    descriptionsFile.close();

    // statistics per UDP port
    yyjson_mut_val *udpArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "udp", udpArray);
    // read first record
    descriptionsFile.open(messyRoomPrefix + "/v4udpdescriptions"s, std::ios::binary);
    file.open(messyRoomPrefix + "/v4udpports"s, std::ios::binary);
    file.seekg(from * recordPortSize, std::ios::beg);
    file.read((char *) &portBuffer, recordPortSize);
    for (int i = 0, iEnd = to - from; i < iEnd && file.gcount(); ++i) {
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(udpArray, object);

        yyjson_mut_obj_add_int(document, object, "port", portBuffer.port);
        yyjson_mut_val *perIpArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, object, "perip", perIpArray);
        descriptionsFile.seekg(portBuffer.ipOffset * recordDescriptionSize, std::ios::beg);
        descriptionsFile.read((char *) &descriptionBuffer, recordDescriptionSize); // read first record
        for (int j = 0, jEnd = portBuffer.numberOfIps; j < jEnd; ++j) {
            yyjson_mut_val *object2 = yyjson_mut_obj(document);
            yyjson_mut_arr_add_val(perIpArray, object2);
            writeIp(object2, std::string(descriptionBuffer.ip, descriptionBuffer.ipLength));
            yyjson_mut_obj_add_int(document, object2, "packets", descriptionBuffer.packets);
            yyjson_mut_obj_add_int(document, object2, "bytes", descriptionBuffer.bytes);

            // read next record
            descriptionsFile.read((char *) &descriptionBuffer, recordDescriptionSize);
        }

        // read next record
        file.read((char *) &portBuffer, recordPortSize);
    }
    file.close();
    descriptionsFile.close();

    if (connection)
        Civet7::respond200(connection, document);
    else
        lastInterativeResult = document;
}

void FeedRefinerOverview::resultsInteractiveSummary(mg_connection *connection)
{
    // prepare for summary
    struct ResultStore
    {
        int64_t bytes, packets;
        ankerl::unordered_dense::set<std::string> ips;
    };
    ankerl::unordered_dense::map<uint16_t, ResultStore> summaryTcp, summaryUdp;

    // prepare for reader
    std::function<void(const std::string &, const std::string &, ankerl::unordered_dense::map<uint16_t, ResultStore> &)> readFile = [&](const std::string &ports, const std::string &descriptions, ankerl::unordered_dense::map<uint16_t, ResultStore> &summary) {
        // initialize variables to read file
        std::ifstream file, descriptionsFile;
        RecordPort portBuffer;
        RecordDescription descriptionBuffer;

        // open file and read first recore
        descriptionsFile.open(descriptions, std::ios::binary);
        file.open(ports, std::ios::binary);
        file.seekg(0, std::ios::beg);
        file.read((char *) &portBuffer, recordPortSize); // read first record
        while (file.gcount()) {
            auto &target = summary[portBuffer.port];
            // read descriptions
            descriptionsFile.seekg(portBuffer.ipOffset * recordDescriptionSize, std::ios::beg);
            descriptionsFile.read((char *) &descriptionBuffer, recordDescriptionSize); // read first record
            for (int j = 0, jEnd = portBuffer.numberOfIps; j < jEnd; ++j) {
                target.bytes += descriptionBuffer.bytes;
                target.packets += descriptionBuffer.packets;
                target.ips.insert(std::string(descriptionBuffer.ip, descriptionBuffer.ipLength));

                // read next record
                descriptionsFile.read((char *) &descriptionBuffer, recordDescriptionSize);
            }

            // read next record
            file.read((char *) &portBuffer, recordPortSize);
        }

        file.close();
        descriptionsFile.close();
    };

    // read file to build summary
    readFile(messyRoomPrefix + "/v4tcpports"s, messyRoomPrefix + "/v4tcpdescriptions"s, summaryTcp);
    readFile(messyRoomPrefix + "/v4udpports"s, messyRoomPrefix + "/v4udpdescriptions"s, summaryUdp);

    // prepart to build JSON
    std::string temp;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);
    std::function<void(const char *, const ankerl::unordered_dense::map<uint16_t, ResultStore> &)> writeSummary = [&](const char *key, const ankerl::unordered_dense::map<uint16_t, ResultStore> &target) {
        yyjson_mut_val *array = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, key, array);
        for (const auto &pair : target) {
            // initialize variables
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(array, object);
            const auto &values = pair.second;

            // write down values
            yyjson_mut_obj_add_int(document, object, "port", pair.first);
            yyjson_mut_obj_add_int(document, object, "bytes", values.bytes);
            yyjson_mut_obj_add_int(document, object, "packets", values.packets);
            yyjson_mut_obj_add_int(document, object, "ips", values.ips.size());
        }
    };

    // build JSON body
    writeSummary("tcp", summaryTcp);
    writeSummary("udp", summaryUdp);

    Civet7::respond200(connection, document);
}

void FeedRefinerOverview::dumpResults(mg_connection *connection)
{
    SubSystems::FqdnGetter getter;

    std::string chunk;
    chunk.reserve(110000000); // 110 MB
    std::function<void(const std::string &)> writeIp;
    if (gatherBy == "iptoservice")
        writeIp = [&](const std::string &ipRaw) {
            describeEdge(getter, chunk, ipRaw.substr(0, ipRaw.size() / 2));
            chunk.pop_back();
            chunk.pop_back();
            describeEdge(getter, chunk, ipRaw.substr(ipRaw.size() / 2));
            chunk.pop_back();
            chunk.pop_back();
        };
    else if (gatherBy == "source")
        writeIp = [&](const std::string &ipRaw) {
            describeEdge(getter, chunk, ipRaw);
            chunk.append("\t"s);
        };
    else
        writeIp = [&](const std::string &ipRaw) { // gatherBy=="destination"
            chunk.append("\t"s);
            describeEdge(getter, chunk, ipRaw);
        };

    // totals and averages
    int denominator = secondEnd - secondStart + 1;
    chunk.append("gatherby\t"s).append(gatherBy).push_back('\n');
    chunk.append("averagebps\t"s).append(std::to_string(totalBytes / denominator)).push_back('\n');
    chunk.append("averagepps\t"s).append(std::to_string(totalPackets / denominator)).push_back('\n');
    chunk.append("totalbytes\t"s).append(std::to_string(totalBytes)).push_back('\n');
    chunk.append("totalpackets\t"s).append(std::to_string(totalPackets)).push_back('\n');

    std::string portNo;
    RecordPort portBuffer;
    RecordDescription descriptionBuffer;
    std::ifstream file, descriptionsFile;
    std::unique_ptr<char[]> readBuffer(new char[268435456]),
        readBufferDescriptions(new char[268435456]); // 256MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 268435456);
    descriptionsFile.rdbuf()->pubsetbuf(readBufferDescriptions.get(), 268435456);

    // per port TCP transactions
    chunk.append("\nTCP Transactions\nPort\tSourceIP\tSourceAlias\tSourceTag\tSourceDomains\tDestinationIP\tDestinationAlias\tDestinationTag\tDestinationDomains\tPackets\tBytes\n"s);
    descriptionsFile.open(messyRoomPrefix + "/v4tcpdescriptions"s, std::ios::binary);
    file.open(messyRoomPrefix + "/v4tcpports"s, std::ios::binary);
    file.read((char *) &portBuffer, recordPortSize); // read first record
    while (file.gcount()) {
        portNo = std::to_string(portBuffer.port) + '\t';
        descriptionsFile.seekg(portBuffer.ipOffset * recordDescriptionSize, std::ios::beg);
        descriptionsFile.read((char *) &descriptionBuffer,
                              recordDescriptionSize); // read first record
        for (int i = 0, iEnd = portBuffer.numberOfIps; i < iEnd; ++i) {
            chunk.append(portNo);
            writeIp(std::string(descriptionBuffer.ip, descriptionBuffer.ipLength));
            chunk.append(std::to_string(descriptionBuffer.packets)).push_back('\t'); // packets
            chunk.append(std::to_string(descriptionBuffer.bytes)).push_back('\n'); // bytes

            // read next record
            descriptionsFile.read((char *) &descriptionBuffer, recordDescriptionSize);
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

        // read next record
        file.read((char *) &portBuffer, recordPortSize);
    }
    file.close();
    descriptionsFile.close();

    // per port UDP transactions
    chunk.append("\nUDP Transactions\nPort\tSourceIP\tSourceAlias\tSourceTag\tSourceDomains\tDestinationIP\tDestinationAlias\tDestinationTag\tDestinationDomains\tPackets\tBytes\n"s);
    descriptionsFile.open(messyRoomPrefix + "/v4udpdescriptions"s, std::ios::binary);
    file.open(messyRoomPrefix + "/v4udpports"s, std::ios::binary);
    file.read((char *) &portBuffer, recordPortSize); // read first record
    while (file.gcount()) {
        portNo = std::to_string(portBuffer.port) + '\t';
        descriptionsFile.seekg(portBuffer.ipOffset * recordDescriptionSize, std::ios::beg);
        descriptionsFile.read((char *) &descriptionBuffer,
                              recordDescriptionSize); // read first record
        for (int i = 0, iEnd = portBuffer.numberOfIps; i < iEnd; ++i) {
            chunk.append(portNo);
            writeIp(std::string(descriptionBuffer.ip, descriptionBuffer.ipLength));
            chunk.append(std::to_string(descriptionBuffer.packets)).push_back('\t'); // packets
            chunk.append(std::to_string(descriptionBuffer.bytes)).push_back('\n'); // bytes

            // read next record
            descriptionsFile.read((char *) &descriptionBuffer, recordDescriptionSize);
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

        // read next record
        file.read((char *) &portBuffer, recordPortSize);
    }
    file.close();
    descriptionsFile.close();

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

FeedRefinerLowHopLimits::FeedRefinerLowHopLimits(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerLowHop"s);

    // initialize session store
    sessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();

    // recognize optional parameter, "n"
    if (conditions.parameters.contains("n"s))
        base = std::stoi(conditions.parameters.at("n"s));
}

void FeedRefinerLowHopLimits::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    logger.log("Processing: "s + std::to_string(codices.size()));
    std::vector<Pack> resultParts = SuperCodex::parallel_convert<SuperCodex::Loader *, Pack>(
        codices,
        [&](const SuperCodex::Loader *codex) -> Pack {
            Pack resultPart;
            for (auto packet = codex->firstPacket(); packet; packet = codex->nextPacket(packet))
                if (packet->hopLimit <= base && codex->sessions.contains(packet->sessionId) && SuperCodex::ipLength(codex->sessions.at(packet->sessionId)->etherType) && SuperCodex::castType(*codex->sessions.at(packet->sessionId)))
                    resultPart.packets.push_back(*packet);
            // register sessions only shown on packets
            for (const auto &packet : resultPart.packets)
                if (resultPart.sessionsIndex.contains(packet.sessionId) == 0) {
                    resultPart.sessions.push_back(*codex->sessions.at(packet.sessionId));
                    resultPart.sessionsIndex.insert(packet.sessionId);
                }

            return resultPart;
        },
        affinityPartitioner);

    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Pack> resultRawsFuture) {
            // background: update session information
            std::thread updateSessionInformationFuture([&]() {
                for (const auto &resultRaw : resultRawsFuture)
                    updateTimestampAndMergeSessions(resultRaw.sessions);
            });

            // save values
            std::ofstream file(messyRoomPrefix + "/packets"s, std::ios::binary);
            for (const auto &resultRaw : resultRawsFuture) {
                // sort per timestamp
                std::vector<SuperCodex::Packet> sorted = resultRaw.packets;
                std::sort(sorted.begin(), sorted.end(), [](const SuperCodex::Packet &a, const SuperCodex::Packet &b) { return SuperCodex::isPast(a.second, a.nanosecond, b.second, b.nanosecond); });
                // write to file
                file.write((const char *) sorted.data(), sorted.size() * SuperCodex::packetSize);
            }

            // wait for session organizer to finish its job
            updateSessionInformationFuture.join();
        },
        resultParts);
}

void FeedRefinerLowHopLimits::finalize()
{
    // prepare for writing results
    std::ofstream file(messyRoomPrefix + "/records"s, std::ios::binary), perSecondStatisticsFile(messyRoomPrefix + "/persecond"s, std::ios::binary);
    std::ifstream packets(messyRoomPrefix + "/packets"s, std::ios::binary);
    Record record;
    SuperCodex::Packet packet;
    TimeValuePair perSecondStatistics;
    ankerl::unordered_dense::map<std::string, int64_t> ranking; // <source IP+destination IP> + occurrences

    // write result except ranking
    packets.read((char *) &packet, SuperCodex::packetSize); // read first record
    perSecondStatistics.second = packet.second; // initialize timestamp for first record
    while (packets.gcount()) {
        // count number of items
        ++numberOfItems;

        // write record
        record.session = sessions->at(packet.sessionId);
        record.packet = packet;
        file.write((const char *) &record, recordSize);

        // write per second statistics if second level timestamp differs
        if (packet.second != perSecondStatistics.second) {
            perSecondStatisticsFile.write((const char *) &perSecondStatistics, timeValuePairSize);

            // fill the gaps between seconds(e.g. first low hop packets appeared at 10:00:00 and next appeared around 10:00:25)
            perSecondStatistics.value = 0;
            for (int i = perSecondStatistics.second + 1, iEnd = packet.second; i < iEnd; ++i) {
                perSecondStatistics.second = i;
                perSecondStatisticsFile.write((const char *) &perSecondStatistics, timeValuePairSize);
            }

            // reset per second statistics buffer
            perSecondStatistics.second = packet.second;
            perSecondStatistics.value = 0;
        }
        ++perSecondStatistics.value;

        // generate ranking data
        if (record.session.sourceIsSmall == record.packet.fromSmallToBig)
            ++ranking[SuperCodex::sourceIp(record.session) + SuperCodex::destinationIp(record.session)];

        // read next record
        packets.read((char *) &packet, SuperCodex::packetSize);
    }
    file.close();
    perSecondStatisticsFile.close();

    // prepare for ranking
    RecordRanking recordRanking;
    std::vector<RecordRanking> rankingSorted;
    rankingSorted.reserve(ranking.size());
    for (const auto &pair : ranking) {
        recordRanking.ipLength = pair.first.size();
        memcpy(recordRanking.ip, pair.first.data(), recordRanking.ipLength);
        recordRanking.hits = pair.second;
        rankingSorted.push_back(recordRanking);
    }
    std::sort(rankingSorted.begin(), rankingSorted.end(), [](const RecordRanking &a, const RecordRanking &b) { return a.hits > b.hits; });

    // write ranking data
    file.open(messyRoomPrefix + "/ranking"s, std::ios::binary);
    file.write((const char *) rankingSorted.data(), rankingSorted.size() * recordRankingSize);
    file.close();

    // log
    packets.close();
    std::filesystem::remove(messyRoomPrefix + "/packets"s);
    logger.log("Results ready to serve: "s + std::to_string(numberOfItems));
}

void FeedRefinerLowHopLimits::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    if (bindValue == 0) {
        SubSystems::FqdnGetter getter;
        // prepare for file handles and stand ready cursors
        std::ifstream file(messyRoomPrefix + "/records"s, std::ios::binary);
        file.seekg(from * recordSize, std::ios::beg);
        Record record;

        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootObject = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootObject);

        // add view hint
        yyjson_mut_val *viewhintObject = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, rootObject, "viewhint", viewhintObject);
        yyjson_mut_obj_add_int(document, viewhintObject, "records", numberOfItems);

        // prepare to add main data
        yyjson_mut_val *dataArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "data", dataArray);
        file.read((char *) &record, recordSize); // read first record
        for (int i = 0, iEnd = to - from; i < iEnd && file.gcount(); ++i) {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(dataArray, object);

            // packet data
            yyjson_mut_obj_add_int(document, object, "second", record.packet.second);
            yyjson_mut_obj_add_int(document, object, "nanosecond", record.packet.nanosecond);
            yyjson_mut_obj_add_int(document, object, "hop", record.packet.hopLimit);

            // session data
            if (record.session.sourceIsSmall == record.packet.fromSmallToBig) {
                yyjson_mut_val *sourceObject = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "source", sourceObject);
                describeEdge(getter, document, sourceObject, SuperCodex::sourceIp(record.session), record.session.sourcePort);
                yyjson_mut_val *destinationObject = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "destination", destinationObject);
                describeEdge(getter, document, destinationObject, SuperCodex::destinationIp(record.session), record.session.destinationPort);
            } else {
                yyjson_mut_val *sourceObject = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "source", sourceObject);
                describeEdge(getter, document, sourceObject, SuperCodex::destinationIp(record.session), record.session.destinationPort);
                yyjson_mut_val *destinationObject = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, object, "destination", destinationObject);
                describeEdge(getter, document, destinationObject, SuperCodex::sourceIp(record.session), record.session.sourcePort);
            }

            // read next record
            file.read((char *) &record, recordSize);
        }
        file.close();
        Civet7::respond200(connection, document);
    } else if (bindValue > 0)
        summarize(connection, messyRoomPrefix + "/persecond", bindValue);
    else { // bindValue<0 -> get some ranking
        SubSystems::FqdnGetter getter;

        // build JSON
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);

        RecordRanking ranking;
        std::ifstream file(messyRoomPrefix + "/ranking"s, std::ios::binary);
        file.read((char *) &ranking, recordRankingSize); // read first rank
        for (int i = 0, iEnd = bindValue * -1; i < iEnd && file.gcount(); ++i) {
            // prepare for stuff
            const std::string ipPair(ranking.ip, ranking.ipLength);
            const size_t ipLength = ipPair.size() / 2;
            std::string sourceIp = ipPair.substr(0, ipLength), destinationIp = ipPair.substr(ipLength);

            // write data
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_add_val(rootArray, object);
            yyjson_mut_val *sourceObject = yyjson_mut_obj(document);
            yyjson_mut_obj_add_val(document, object, "source", sourceObject);
            describeEdge(getter, document, sourceObject, sourceIp);
            yyjson_mut_val *destinationObject = yyjson_mut_obj(document);
            yyjson_mut_obj_add_val(document, object, "destination", destinationObject);
            describeEdge(getter, document, destinationObject, destinationIp);
            yyjson_mut_obj_add_int(document, object, "hits", ranking.hits);

            // read next rank
            file.read((char *) &ranking, recordRankingSize);
        }
        file.close();

        Civet7::respond200(connection, document);
    }
}

void FeedRefinerLowHopLimits::dumpResults(mg_connection *connection)
{
    SubSystems::FqdnGetter getter;
    std::string chunk("Second\tNanosecond\tSourceIP\tSourceAlias\tSourceTag\tSourceDomains\tSourcePort\tDestinationIP\tDestinationAlias\tDestinationTag\tDestinationDomains\tDestinationPort\tHop\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    Record record;
    std::ifstream file(messyRoomPrefix + "/records"s, std::ios::binary);
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);
    file.read((char *) &record, recordSize); // read first record
    while (file.gcount()) {
        // timestamp
        chunk.append(epochToIsoDate(record.packet.second)).append("\t"s).append(std::to_string(record.packet.nanosecond)).push_back('\t');
        if (record.session.sourceIsSmall == record.packet.fromSmallToBig) {
            describeEdge(getter, chunk, SuperCodex::sourceIp(record.session), record.session.sourcePort);
            describeEdge(getter, chunk, SuperCodex::destinationIp(record.session), record.session.destinationPort);
        } else {
            describeEdge(getter, chunk, SuperCodex::destinationIp(record.session), record.session.destinationPort);
            describeEdge(getter, chunk, SuperCodex::sourceIp(record.session), record.session.sourcePort);
        }

        // hop size
        chunk.append(std::to_string(record.packet.hopLimit)).push_back('\n');

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
        file.read((char *) &record, recordSize);
    }

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

FeedRefinerIcmpWalk::FeedRefinerIcmpWalk(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    // determine whether this job is for ICMPv4(0x01) or v6(0x3a)
    if (conditions.payloadProtocol == 0x01) { // ICMPv4(0x01)
        // declare this job is for ICMPv4
        logger.setLogHeader("FeedRefinerIcmpWalk"s);
        isForV4 = true;
        buildIntermediate = buildIntermediateV4;

        // check whether SuperCache is applicable
        if (conditions.mplsLabels.empty() && conditions.vlanQTags.empty()) { // preprequsite: no MPLS labels and VLAN tag filter
            if (conditions.allowedIps.isEmpty && conditions.l7Protocol == SuperCodex::Session::NOL7DETECTED && conditions.ports.empty()) // payloadProtocol is set as 1 on DataFeed::postRefinery()
                pmpiCacheMode = FULL;
            else
                pmpiCacheMode = FILTERED;
        }
        if (pmpiCacheMode == NONE)
            logger.log("SuperCache unapplicable");
        else {
            superCachePath = CodexIndex::feedRoot + conditions.dataFeed + SuperCache::dbs[1];
            cachedChapter = static_cast<SuperCodex::ChapterType>(-1);
            logger.log("SuperCache applicable");
        }
    } else { // ICMPv6(0x3a)
        // declare this job is for ICMPv6
        logger.setLogHeader("FeedRefinerIcmpWalk/V6"s);
        isForV4 = false;
        buildIntermediate = buildIntermediateV6;

        // SuperCache is not supported yet
    }
}

void FeedRefinerIcmpWalk::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // check parameters
    int type = -1, code = -1;
    ankerl::unordered_dense::set<std::string> ips;
    try {
        if (parameters.contains("type"s) && parameters.contains("code"s)) {
            type = std::stoi(parameters.at("type"s));
            code = std::stoi(parameters.at("code"s));
        }
        if (parameters.contains("ips"s)) { // comma separated
            std::istringstream lineReader(parameters.at("ips"s));
            for (std::string ip; std::getline(lineReader, ip, ',');)
                ips.insert(SuperCodex::stringFromHex(ip));
        }
    } catch (...) {
        mg_send_http_error(connection, 400, "Check parameter 'type', 'code', or 'ips'.");
        return;
    }

    // respond
    if (type == -1 && code == -1 && ips.empty()) { // if filter is not set, return index in JSON
        if (connection)
            Civet7::respond200(connection, indexJson.data(), indexJson.size());
        else
            lastInterativeResult = (yyjson_mut_doc *) &indexJson[0];
    } else {
        // prepare for result
        bool ipsEmpty = ips.empty();
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);

        // open file
        std::ifstream file(messyRoomPrefix + '/' + std::to_string(type) + '_' + std::to_string(code), std::ios::binary);

        // read
        Description buffer;
        file.read((char *) &buffer, descriptionSize);
        while (file.gcount()) {
            std::string ip(buffer.sourceIp()), ip2(buffer.destinationIp());
            if (ipsEmpty || (ips.size() == 2 && ips.contains(ip) && ips.contains(ip2)) || (ips.size() != 2 && (ips.contains(ip) || ips.contains(ip2)))) {
                yyjson_mut_val *object = yyjson_mut_obj(document);
                yyjson_mut_arr_add_val(rootArray, object);
                yyjson_mut_obj_add_int(document, object, "timestamp", buffer.timestamp);
                ip = SuperCodex::stringToHex(ip);
                yyjson_mut_obj_add_strncpy(document, object, "ip", ip.data(), ip.size());
                ip2 = SuperCodex::stringToHex(ip2);
                yyjson_mut_obj_add_strncpy(document, object, "ip2", ip2.data(), ip2.size());
                yyjson_mut_obj_add_int(document, object, "type", type);
                yyjson_mut_obj_add_int(document, object, "code", code);
                if (*(const uint16_t *) buffer.ipsOriginal != 0) { // field "original" has some value to be interpreted
                    yyjson_mut_val *details = yyjson_mut_obj(document);
                    yyjson_mut_obj_add_val(document, object, "details", details);
                    yyjson_mut_obj_add_int(document, details, "payloadprotocol", buffer.payloadProtocol);
                    const std::string ip(SuperCodex::stringToHex(buffer.sourceIpOriginal())), ip2(SuperCodex::stringToHex(buffer.destinationIpOriginal()));
                    yyjson_mut_obj_add_strncpy(document, details, "ip", ip.data(), ip.size());
                    yyjson_mut_obj_add_strncpy(document, details, "ip2", ip2.data(), ip2.size());
                    yyjson_mut_obj_add_int(document, details, "port", buffer.port);
                    yyjson_mut_obj_add_int(document, details, "port2", buffer.port2);
                }
            }
            file.read((char *) &buffer, descriptionSize);
        }

        // return result
        if (connection)
            Civet7::respond200(connection, document);
        else
            lastInterativeResult = document;
    }
}

void FeedRefinerIcmpWalk::dumpResults(mg_connection *connection)
{
    // prepare for header
    std::string chunk("Type\tCode\tTimestamp\tSource IP\tDestination IP\n"s), prefix;
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // read files one by one
    for (const auto &entry : std::filesystem::directory_iterator(messyRoomPrefix))
        if (entry.is_regular_file()) {
            // prepare to read
            Description buffer;
            std::ifstream file(entry.path(), std::ios::binary);

            // read first record
            file.read((char *) &buffer, descriptionSize);
            while (file.gcount()) {
                // write lines
                chunk.append(std::to_string(buffer.type) + '\t').append(std::to_string(buffer.code) + '\t').append(epochToIsoDate(buffer.timestamp) + '\t').append(SuperCodex::humanReadableIp(buffer.sourceIp())).append("\t"s).append(SuperCodex::humanReadableIp(buffer.destinationIp())).push_back('\n');

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
                file.read((char *) &buffer, descriptionSize);
            }
        }

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

void FeedRefinerIcmpWalk::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    std::vector<Intermediate> intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, Intermediate>(codices, buildIntermediate, affinityPartitioner);

    // merge
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Intermediate> intermediatesFuture) {
            for (const auto &intermediate : intermediatesFuture)
                if (!intermediate.empty()) {
                    // determine whether to write to file directly or defer until SuperCache merges
                    bool writeToDisk = ((pmpiCacheMode != NONE) && (intermediate.begin()->second.front().timestamp < conditions.cacheFrom));

                    for (const auto &pair : intermediate) {
                        // write data to file or defer to "tails"
                        if (writeToDisk)
                            writeIntermediate(pair);
                        else {
                            auto &tailsTarget = tails[pair.first];
                            tailsTarget.reserve(tailsTarget.size() + pair.second.size());
                            for (const auto &item : pair.second)
                                tailsTarget.push_back(item);
                        }

                        // build summary information
                        auto &targetTypeCode = summary[std::make_pair(pair.first.first, pair.first.second)];
                        for (const auto &packet : pair.second)
                            ++targetTypeCode[std::make_pair(std::string(packet.sourceIp()), std::string(packet.destinationIp()))];
                    }
                }
        },
        std::move(intermediates));
}

void FeedRefinerIcmpWalk::finalize()
{
    // merge SuperCache data
    if (conditions.cacheFrom) {
        // build duration vector
        struct Segment
        {
            uint32_t index, from, to;
        };
        std::vector<Segment> timestamps;
        const uint32_t interval = 3600;
        for (uint32_t i = conditions.cacheFrom; i < conditions.cacheTo; i += interval)
            timestamps.push_back(Segment{(i - conditions.cacheFrom) / interval, i, i + interval - 1});
        timestamps.back().to = conditions.cacheTo;

        // query in parallel to generate intermediates
        std::vector<Intermediate> hourlyMerged = SuperCodex::parallel_convert<Segment, Intermediate>(timestamps, [&](const Segment &segment) -> Intermediate {
            Intermediate result;

            // query database
            FeatherLite feather(superCachePath, SQLITE_OPEN_READONLY);
            feather.prepare("SELECT originalsize,filepath FROM rows WHERE timestamp>=? AND timestamp<=? AND chapter=?;"s);
            feather.bindInt(1, segment.from);
            feather.bindInt(2, segment.to);
            feather.bindInt(3, cachedChapter);

            // merge records
            while (feather.next() == SQLITE_ROW) {
                // decompress raw data
                std::string compressed(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(std::string(feather.getText(1)), std::ifstream::binary).rdbuf()).str());
                if (compressed.size() <= 12) // exception handling: there's only length bytes or is null
                    continue;
                size_t originalSize = feather.getInt(0);
                const char *decompressedRaw = SuperCodex::decompress(SuperCodex::Glyph{(char *) compressed.data(), static_cast<int32_t>(compressed.size())}, compressed.size(), originalSize), *cursor = decompressedRaw, *cursorEnd = cursor + originalSize;

                // merge data according to the selected cache insertion mode
                const Description *description;
                switch (pmpiCacheMode) {
                case FULL:
                    while (cursor < cursorEnd) {
                        description = (const Description *) cursor;
                        result[std::make_pair(description->type, description->code)].push_back(*description);
                        // go to next record
                        cursor += descriptionSize;
                    }
                    break;
                case FILTERED:
                    if (conditions.includeExternalTransfer)
                        while (cursor < cursorEnd) {
                            description = (const Description *) cursor;
                            if (conditions.allowedIps.contains(description->sourceIp()) || conditions.allowedIps.contains(description->destinationIp()))
                                result[std::make_pair(description->type, description->code)].push_back(*description);

                            // go to next record
                            cursor += descriptionSize;
                        }
                    else
                        while (cursor < cursorEnd) {
                            // prepare to read
                            description = (const Description *) cursor;
                            if (conditions.allowedIps.contains(description->sourceIp()) && conditions.allowedIps.contains(description->destinationIp()))
                                result[std::make_pair(description->type, description->code)].push_back(*description);

                            // go to next record
                            cursor += descriptionSize;
                        }
                    break;
                default:
                    logger.oops("Unexpected cache mode("s + std::to_string(pmpiCacheMode) + "). Not merging cache."s);
                }

                // return used memory
                delete[] decompressedRaw;
            }

            return result;
        });

        // merge hourly cache data
        for (const auto &intermediate : hourlyMerged)
            for (const auto &pair : intermediate) {
                // write data to file
                writeIntermediate(pair);

                // build summary information
                auto &targetTypeCode = summary[std::make_pair(pair.first.first, pair.first.second)];
                for (const auto &packet : pair.second)
                    ++targetTypeCode[std::make_pair(std::string(packet.sourceIp()), std::string(packet.destinationIp()))];
            }
    }

    for (const auto &pair : tails)
        writeIntermediate(pair);

    // build summary
    int64_t totalCount = 0;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootArray = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, rootArray);
    auto summaryVector = summary.values();
    std::sort(summaryVector.begin(), summaryVector.end(), [](const std::pair<std::pair<uint8_t, uint8_t>, ankerl::unordered_dense::map<std::pair<std::string, std::string>, uint64_t>> &a, const std::pair<std::pair<uint8_t, uint8_t>, ankerl::unordered_dense::map<std::pair<std::string, std::string>, uint64_t>> &b) -> bool { return a.first.first < b.first.first || (a.first.first == b.first.first && a.first.second < b.first.second); });
    for (auto &pair : summaryVector) {
        // prepare for object as element for root array
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(rootArray, object);

        // write down type and code
        yyjson_mut_obj_add_int(document, object, "type", pair.first.first);
        yyjson_mut_obj_add_int(document, object, "code", pair.first.second);

        // write down details
        yyjson_mut_val *perIpArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, object, "details", perIpArray);
        auto detailsVector = pair.second.values();
        std::sort(detailsVector.begin(), detailsVector.end(), [](const std::pair<std::pair<std::string, std::string>, uint64_t> &a, const std::pair<std::pair<std::string, std::string>, uint64_t> &b) -> bool { return a.second > b.second; });
        for (const auto &pair2 : detailsVector) {
            // prepare for object for counters per IP pair
            yyjson_mut_val *object2 = yyjson_mut_obj(document);
            yyjson_mut_arr_append(perIpArray, object2);
            // write down contents
            totalCount += pair2.second;
            yyjson_mut_obj_add_int(document, object2, "count", pair2.second);
            std::string ip(SuperCodex::stringToHex(pair2.first.first)), ip2(SuperCodex::stringToHex(pair2.first.second));
            yyjson_mut_obj_add_strncpy(document, object2, "ip", ip.data(), ip.size());
            yyjson_mut_obj_add_strncpy(document, object2, "ip2", ip2.data(), ip2.size());
        }
    }
    size_t resultSize;
    char *resultRaw = yyjson_mut_write(document, YYJSON_WRITE_NOFLAG, &resultSize);
    indexJson.append(resultRaw, resultSize);
    yyjson_mut_doc_free(document);

    // choir
    summary.clear();
    logger.log("Results ready to serve: "s + std::to_string(totalCount));
}

FeedRefinerIcmpWalk::Intermediate FeedRefinerIcmpWalk::buildIntermediateV4(const SuperCodex::Loader *codex)
{
    ankerl::unordered_dense::map<int32_t, Description> toMerge; // packet index + description

    // read packet data
    toMerge.reserve(1024); // this should be enough(hopefully)
    for (const SuperCodex::Packet *packet = codex->firstPacket(); packet; packet = codex->nextPacket(packet)) {
        // prepare for variables
        const SuperCodex::Session *session = codex->sessions.at(packet->sessionId);
        auto &target = toMerge[packet->index];
        const auto ipLength = SuperCodex::ipLength(session->etherType);
        // determine direction of IP for given "session"
        if (session->sourceIsSmall == packet->fromSmallToBig)
            memcpy(target.ips, session->ips, ipLength * 2);
        else { // opposite direction
            memcpy(target.ips, session->ips + ipLength, ipLength);
            memcpy(target.ips + ipLength, session->ips, ipLength);
        }
        target.timestamp = packet->second;
        target.ipLength = ipLength;
        target.type = packet->tcpSeq;
        target.code = packet->tcpAck;
    }

    // extract remarks for certain ICMPv4 packets
    for (auto remarksRaw = codex->firstRemarks(); remarksRaw.content; remarksRaw = codex->nextRemarks(remarksRaw)) {
        std::string remarks(remarksRaw.content, remarksRaw.size);
        std::istringstream lineReader(remarks);
        for (std::string line; std::getline(lineReader, line, '\n');) {
            const size_t separator = line.find('=');
            const int32_t packetIndex = std::stoi(line.substr(4, separator - 4));
            if (toMerge.contains(packetIndex)) {
                // get value from line(each line from remarks looks like `ICMP939=17 a87e3f01c0a8010b350038f`)
                auto &targetPacket = toMerge[packetIndex];
                std::string lineValue = line.substr(separator + 1);
                const size_t recordSplitter = lineValue.find(' '), record2Size = lineValue.size() - recordSplitter - 1;
                bool ipValid = false, hasPortNumbers = false;
                switch (record2Size) {
                case 24: // IPv4
                    hasPortNumbers = true;
                case 16: // IPv4 (no port numbers)
                    ipValid = (targetPacket.ipLength == 4);
                    break;
                }
                if (ipValid) { // we have expected length for IP addresses
                    targetPacket.payloadProtocol = std::stoi(lineValue.substr(0, recordSplitter));
                    std::string ipPortPartRaw = SuperCodex::stringFromHex(lineValue.substr(recordSplitter + 1));
                    const char *remarksRawStart = ipPortPartRaw.data();
                    const size_t ipLengthDouble = targetPacket.ipLength * 2;
                    memcpy(targetPacket.ipsOriginal, remarksRawStart, ipLengthDouble);
                    if (hasPortNumbers) { // port number could be 0, since the original packet may NOT have port number(e.g. original packet is ICMP. :P)
                        targetPacket.port = *(const uint16_t *) (remarksRawStart + ipLengthDouble);
                        targetPacket.port2 = *(const uint16_t *) (remarksRawStart + ipLengthDouble + 2);
                    }
                }
            }
        }
    }

    // reorganize packet description per ICMP type and code
    Intermediate result;
    for (const auto &pair : toMerge)
        result[std::make_pair(pair.second.type, pair.second.code)].push_back(pair.second);
    // sort each type-code group per timestamp
    for (auto &pair : result)
        std::sort(pair.second.begin(), pair.second.end(), [](const Description &a, const Description &b) -> bool { return a.timestamp < b.timestamp; });
    return result;
}

FeedRefinerIcmpWalk::Intermediate FeedRefinerIcmpWalk::buildIntermediateV6(const SuperCodex::Loader *codex)
{
    ankerl::unordered_dense::map<int32_t, Description> toMerge; // packet index + description

    // read packet data
    toMerge.reserve(1024); // this should be enough(hopefully)
    for (const SuperCodex::Packet *packet = codex->firstPacket(); packet; packet = codex->nextPacket(packet)) {
        // prepare for variables
        const SuperCodex::Session *session = codex->sessions.at(packet->sessionId);
        auto &target = toMerge[packet->index];
        const auto ipLength = SuperCodex::ipLength(session->etherType);
        // determine direction of IP for given "session"
        if (session->sourceIsSmall == packet->fromSmallToBig)
            memcpy(target.ips, session->ips, ipLength * 2);
        else { // opposite direction
            memcpy(target.ips, session->ips + ipLength, ipLength);
            memcpy(target.ips + ipLength, session->ips, ipLength);
        }
        target.timestamp = packet->second;
        target.ipLength = ipLength;
        target.type = packet->tcpSeq;
        target.code = packet->tcpAck;
    }

    // extract remarks for certain ICMPv6 packets
    for (auto remarksRaw = codex->firstRemarks(); remarksRaw.content; remarksRaw = codex->nextRemarks(remarksRaw)) {
        std::string remarks(remarksRaw.content, remarksRaw.size);
        std::istringstream lineReader(remarks);
        for (std::string line; std::getline(lineReader, line, '\n');) {
            const size_t separator = line.find('=');
            const int32_t packetIndex = std::stoi(line.substr(6, separator - 6));
            if (toMerge.contains(packetIndex)) {
                // get value from line (each line from remarks looks like `ICMPV6106=3ffe050700000001020086fffe0580da3ffe05010410000002c0dffffe47033e\tU75a0a482` or `ICMPV6131=01010060970769ea05010000000005dc030440c00036ee800036ee8000000000\t`)
                // for IP + port combination, structure of port side is \t + (T or U) + port1 + port2
                auto &targetPacket = toMerge[packetIndex];
                std::string lineValue = line.substr(separator + 1);
                const size_t recordSplitter = lineValue.find('\t');
                bool ipValid = false, hasPortNumbers = false;
                switch (lineValue.size()) {
                case 74: // IPv6 (32 + 32 + \t + T or U + port1 + port2)
                    hasPortNumbers = true;
                case 65: // IPv6 (no port number) -> 32 + 32 + \t
                    ipValid = (targetPacket.ipLength == 16);
                    break;
                }
                if (ipValid) { // we have expected length for IP addresses
                    // set IP addresses
                    std::string ipPartRaw = SuperCodex::stringFromHex(lineValue.substr(0, recordSplitter));
                    memcpy(targetPacket.ipsOriginal, ipPartRaw.data(), targetPacket.ipLength * 2);

                    // optional: set port numbers
                    if (hasPortNumbers) {
                        switch (lineValue[recordSplitter + 1]) {
                        case 'T': // TCP
                            targetPacket.payloadProtocol = 0x06;
                            break;
                        case 'U': // UDP
                            targetPacket.payloadProtocol = 0x11;
                            break;
                        }
                        std::string portPartRaw = SuperCodex::stringFromHex(lineValue.substr(recordSplitter + 2));
                        targetPacket.port = *(const uint16_t *) (portPartRaw.data());
                        targetPacket.port2 = *(const uint16_t *) (portPartRaw.data() + 2);
                    }
                }
            }
        }
    }

    // reorganize packet description per ICMP type and code
    Intermediate result;
    for (const auto &pair : toMerge)
        result[std::make_pair(pair.second.type, pair.second.code)].push_back(pair.second);
    // sort each type-code group per timestamp
    for (auto &pair : result)
        std::sort(pair.second.begin(), pair.second.end(), [](const Description &a, const Description &b) -> bool { return a.timestamp < b.timestamp; });
    return result;
}

void FeedRefinerIcmpWalk::writeIntermediate(const std::pair<std::pair<int8_t, int8_t>, std::vector<Description>> &pair)
{
    // write data to file
    std::ofstream file(messyRoomPrefix + '/' + std::to_string(pair.first.first) + '_' + std::to_string(pair.first.second), std::ios::binary | std::ios::app);
    std::unique_ptr<char[]> readBuffer(new char[10485760]); // 10MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 10485760);
    const auto &record = pair.second;
    file.write((const char *) record.data(), record.size() * descriptionSize);
    file.close();
}
