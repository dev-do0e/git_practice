#include "feedrefinertrackers.h"
#include "codexindex.h"
#include "supercache.h"
#include "../fnvhash.h"
#include "../featherlite.h"
#include "civet7.hpp"

#include <algorithm>
#include <filesystem>
#include <regex>
#include <sstream>
#include <fstream>
#include <ctype.h>

#include <tbb/parallel_for.h>
#include <yyjson.h>

FeedRefinerDnsTracker::FeedRefinerDnsTracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerDnsTracker"s);

    orphanedRequests = new ankerl::unordered_dense::map<uint64_t, SessionRecord>();
    descriptions.reserve(100000); // I can't imagine any network with more than 100,000 DNS server IP addresses

    // check whether SuperCache is applicable
    cachedChapter = static_cast<SuperCodex::ChapterType>(SuperCodex::REMARKS + SuperCodex::Session::DNS);
    if (conditions.mplsLabels.empty() && conditions.vlanQTags.empty()) { // preprequsite: no MPLS labels and VLAN tag filter
        if (conditions.allowedIps.isEmpty) // payload protocol shall be anyway UDP and ports will be 53 anyway. :P
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

void FeedRefinerDnsTracker::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // prepare for variables and objects
    std::string temp;
    std::string server, query;
    int detailsTarget = -1; // invalid
    size_t queryLimit = 10, clientLimit = 10;

    // check parameters
    if (parameters.contains("server"s))
        server = SuperCodex::stringFromHex(parameters.at("server"s));
    if (parameters.contains("status"s)) {
        const std::string &statusRaw = parameters.at("status"s);
        if (statusRaw == "resolved"s)
            detailsTarget = 0;
        else if (statusRaw == "zeroanswer"s)
            detailsTarget = 1;
        else if (statusRaw == "answerbroken"s)
            detailsTarget = 2;
        else if (statusRaw == "multiplequeries"s)
            detailsTarget = 3;
        else if (statusRaw == "timeout"s)
            detailsTarget = 4;
        else {
            mg_send_http_error(connection, 400, "Unknown status value.");
            return;
        }
    }
    if (parameters.contains("query"s))
        query = parameters.at("query"s);
    try {
        if (parameters.contains("querylimit"s))
            queryLimit = std::stoi(parameters.at("querylimit"s));
        if (parameters.contains("clientlimit"s))
            clientLimit = std::stoi(parameters.at("clientlimit"s));
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to convert limits to numbers.");
        return;
    }

    // start writing down JSON
    if (server.empty() && query.empty() && detailsTarget == -1) { // send DNS server list
        // determine how many server IPs will be sent
        int32_t upTo = 100;
        if (bindValue == -1)
            upTo = serverListSorted.size();
        else if (bindValue > 0)
            upTo = bindValue;

        // prepare for return
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);
        int32_t ipCounter = 0;
        for (const auto &ip : serverListSorted) {
            yyjson_mut_arr_add_strn(document, rootArray, ip.data(), ip.size());
            ++ipCounter;
            if (ipCounter >= upTo)
                break;
        }

        if (connection)
            Civet7::respond200(connection, document);
        else
            lastInterativeResult = document;
        return;
    } else { // send details
        if (detailsTarget == -1) {
            mg_send_http_error(connection, 404, "parameter \"status\" was not properly set");
            return;
        }

        if (server.empty())
            server = "total"s;
        else {
            // simple sanity test
            if (server != "total"s && !descriptions.contains(server)) {
                logger.log("DNS server not in list"s);
                mg_send_http_error(connection, 400, "No data for DNS server with given IP.");
                return;
            }
        }
        const auto &pack = server == "total"s ? descriptionTotal : descriptions.at(server);

        // prepare for JSON root object
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootObject = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootObject);

        // performance data
        yyjson_mut_val *performanceObject = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, rootObject, "performance", performanceObject);
        yyjson_mut_obj_add_int(document, performanceObject, "fastest", pack.summary.fastest);
        yyjson_mut_obj_add_int(document, performanceObject, "slowest", pack.summary.slowest);
        yyjson_mut_obj_add_int(document, performanceObject, "average", pack.summary.sum / (pack.summary.queriesReceived + pack.summary.resolved + pack.summary.timeout + pack.summary.answerCountZero + pack.summary.answerBroken + pack.summary.multipleQueries));
        yyjson_mut_obj_add_int(document, performanceObject, "clientsserved", pack.summary.clientsServed);
        yyjson_mut_obj_add_int(document, performanceObject, "queriestaken", pack.summary.queriesReceived);
        yyjson_mut_obj_add_int(document, performanceObject, "resolved", pack.summary.resolved);
        yyjson_mut_obj_add_int(document, performanceObject, "timeout", pack.summary.timeout);
        yyjson_mut_obj_add_int(document, performanceObject, "zeroanswer", pack.summary.answerCountZero);
        yyjson_mut_obj_add_int(document, performanceObject, "answerbroken", pack.summary.answerBroken);
        yyjson_mut_obj_add_int(document, performanceObject, "multiplequeries", pack.summary.multipleQueries);

        // build ranking per query and per client
        const auto &targetDetails = pack.details[detailsTarget];
        std::vector<std::pair<std::string, unsigned long long>> topQueriesSorted, topClientsSorted;
        topQueriesSorted.reserve(targetDetails.size());
        for (const auto &pair : targetDetails) {
            unsigned long long hits = 0;
            for (const auto &pair2 : pair.second)
                hits += pair2.second;
            topQueriesSorted.push_back(std::make_pair(pair.first, hits));
        }
        if (!query.empty() && targetDetails.contains(query)) // client list is set only if query is set
            topClientsSorted = targetDetails.at(query).values();
        std::sort(topQueriesSorted.begin(), topQueriesSorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) { return a.second > b.second; });
        std::sort(topClientsSorted.begin(), topClientsSorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) { return a.second > b.second; });

        // queries taken
        yyjson_mut_val *topQueriesArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "topqueries", topQueriesArray);
        for (size_t i = 0, iEnd = std::min(queryLimit, topQueriesSorted.size()); i < iEnd; ++i) {
            const auto &pair = topQueriesSorted.at(i);
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(topQueriesArray, object);
            yyjson_mut_obj_add_strncpy(document, object, "domain", pair.first.data(), pair.first.size());
            yyjson_mut_obj_add_int(document, object, "hits", pair.second);
        }

        // top clients
        yyjson_mut_val *topClientsArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "topclients", topClientsArray);
        for (size_t i = 0, iEnd = std::min(clientLimit, topClientsSorted.size()); i < iEnd; ++i) {
            const auto &pair = topClientsSorted.at(i);
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(topClientsArray, object);
            temp = SuperCodex::stringToHex(pair.first);
            yyjson_mut_obj_add_strncpy(document, object, "ip", temp.data(), temp.size());
            yyjson_mut_obj_add_int(document, object, "hits", pair.second);
        }

        if (connection)
            Civet7::respond200(connection, document);
        else
            lastInterativeResult = document;
    }
}

void FeedRefinerDnsTracker::dumpResults(mg_connection *connection)
{
    // header
    std::string chunk("ClientIP\tDnsServer\tQuery\tStatus\tHits\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // read vector
    std::vector<std::string> statusStrings = {"RESOLVED"s, "ZEROANSWER"s, "ANSWERBROKEN"s, "MULTIPLEQUERIES"s, "TIMEOUT"s};
    for (const auto &pair : descriptions) {
        const std::string humanReadableServerIp = SuperCodex::humanReadableIp(pair.first);
        for (int i = 0; i < 5; ++i) {
            const std::string &status = statusStrings[i];
            for (const auto &detailPair : pair.second.details[i])
                for (const auto &clientPair : detailPair.second) {
                    // write down data
                    chunk.append(SuperCodex::humanReadableIp(clientPair.first) + '\t').append(humanReadableServerIp + '\t').append(detailPair.first + '\t').append(status + '\t').append(std::to_string(clientPair.second)).push_back('\n');

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
        }
    }

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

void FeedRefinerDnsTracker::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    struct IntermediatePack
    {
        bool isAfterCache;
        ankerl::unordered_dense::map<uint64_t, SessionRecord> records;
        std::vector<SessionRecord> requestOnly;
        std::vector<uint64_t> timeouts; // if a timeout is declared, chances are that there will be an orphaned request for that timeout, which contains full request
    };

    // extract intermediary data from each SuperCodex file
    std::vector<IntermediatePack> intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, IntermediatePack>(codices, [&](const SuperCodex::Loader *codex) -> IntermediatePack {
        // prepare for a few variables
        IntermediatePack pack;
        pack.isAfterCache = conditions.cacheTo > 0 && codex->secondEnd > conditions.cacheTo;
        auto &records = pack.records;

        // determine status of the DNS session
        for (auto remarks = codex->firstRemarks(); remarks.content; remarks = codex->nextRemarks(remarks)) {
            // build record
            SessionRecord targetRecord{};
            targetRecord.sessionId = remarks.sessionId;
            targetRecord.remarks = std::string(remarks.content, remarks.size);
            targetRecord.status = determineStatus(targetRecord.remarks);
            targetRecord.query = extractQuery(targetRecord.remarks);

            // extract session data
            auto &session = codex->sessions.at(remarks.sessionId);
            targetRecord.secondStart = session->first.second;
            targetRecord.secondEnd = session->last.second;
            targetRecord.sourceIp = SuperCodex::sourceIp(*session);
            targetRecord.destinationIp = SuperCodex::destinationIp(*session);

            // determine where to put the record
            if (targetRecord.status == REQUESTONLY)
                pack.requestOnly.push_back(std::move(targetRecord));
            else
                records[targetRecord.sessionId] = targetRecord;
        }

        // gather latency data
        for (auto rtt = codex->firstRtt(); rtt; rtt = codex->nextRtt(rtt))
            if (records.contains(rtt->sessionId))
                records[rtt->sessionId].latency = rtt->tail;

        // recognize timeouts
        auto &timeouts = pack.timeouts;
        for (const SuperCodex::Timeout *timeout = codex->firstTimeout(); timeout; timeout = codex->nextTimeout(timeout))
            if (timeout->session.detectedL7 == SuperCodex::Session::DNS)
                timeouts.push_back(timeout->session.id);

        return pack;
    });

    // merge
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<IntermediatePack> resultRawsFuture, const bool isFinalLap) {
            // walk through extracted data
            for (auto &resultRaw : resultRawsFuture) {
                // process timeouts
                for (auto &sessionId : resultRaw.timeouts)
                    if (orphanedRequests->contains(sessionId)) { // if there's a timed out session, chances are there can be a orphaned request before the timeout
                        // initialize some stuff
                        auto &originalRequest = (*orphanedRequests)[sessionId];
                        originalRequest.status = TIMEOUT;
                        originalRequest.latency = -1;

                        // merge data to descriptions
                        descriptionTotal.mergeSessionRecord(originalRequest);
                        descriptions[originalRequest.destinationIp].mergeSessionRecord(originalRequest);

                        // remove orphaned request
                        orphanedRequests->erase(sessionId);
                    } else if (resultRaw.isAfterCache)
                        timeouts.push_back(sessionId); // save orphaned timeouts only if the timout occurred after cached data

                // merge full records
                for (auto &pair : resultRaw.records) {
                    auto &record = pair.second;
                    // update timestamps
                    if (secondStart > record.secondStart)
                        secondStart = record.secondStart;
                    if (secondEnd < record.secondEnd)
                        secondEnd = record.secondEnd;

                    // merge data to descriptions
                    descriptionTotal.mergeSessionRecord(record);
                    descriptions[record.destinationIp].mergeSessionRecord(record);

                    // delete orphaned requests as needed
                    if (orphanedRequests->contains(record.sessionId))
                        orphanedRequests->erase(record.sessionId);
                }

                // merge orphaned requests, whose response pair or timeouts can be found in future SuperCodex files
                for (auto &request : resultRaw.requestOnly)
                    (*orphanedRequests)[request.sessionId] = request;
            }
        },
        std::move(intermediates),
        codices.back()->fileName == conditions.codicesToGo.back()); // check whether this is the final lap before finalize()
}

void FeedRefinerDnsTracker::finalize()
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

        // query in parallel
        struct CachePack
        {
            ankerl::unordered_dense::map<uint64_t, SessionRecord> orphanedRequests;
            ankerl::unordered_dense::map<std::string, Description> descriptions;
            std::vector<uint64_t> timeouts;
        };
        std::vector<CachePack> hourlyMerged = SuperCodex::parallel_convert<Segment, CachePack>(timestamps, [&](const Segment &segment) -> CachePack {
            CachePack result;

            // query database
            FeatherLite feather(superCachePath, SQLITE_OPEN_READONLY);
            feather.prepare("SELECT originalsize,filepath FROM rows WHERE timestamp>=? AND timestamp<=? AND chapter=?;"s);
            feather.bindInt(1, segment.from);
            feather.bindInt(2, segment.to);
            feather.bindInt(3, cachedChapter);

            // merge records
            while (feather.next() == SQLITE_ROW) {
                // get triplet and add some syntatic sugar
                auto pmpiTriplet = SuperCache::getPmpiTriplet(std::string(feather.getText(1)), feather.getInt(0));
                if (pmpiTriplet.decompressedRaw == nullptr)
                    continue;
                const std::string_view &timeouts = pmpiTriplet.perSourceRaw, &requestOnly = pmpiTriplet.perDestinationRaw, &details = pmpiTriplet.perIpToServiceRaw;

                // (common) merge timed out sessions: there are only orphaned requests with given IP filter conditions
                for (const uint64_t *sessionId = (const uint64_t *) timeouts.data(), *sessionIdEnd = (const uint64_t *) (timeouts.data() + timeouts.size()); sessionId < sessionIdEnd; ++sessionId)
                    if (result.orphanedRequests.contains(*sessionId)) {
                        // initialize some stuff
                        auto &originalRequest = result.orphanedRequests[*sessionId];
                        originalRequest.status = TIMEOUT;
                        originalRequest.latency = -1;

                        // merge data to descriptions
                        result.descriptions[originalRequest.destinationIp].mergeSessionRecord(originalRequest);

                        // remove orphaned request
                        result.orphanedRequests.erase(*sessionId);
                    } else
                        result.timeouts.push_back(*sessionId);

                // merge data according to the selected cache insertion mode
                const SuperCache::DnsSessionHeader *header;
                switch (pmpiCacheMode) {
                case FULL: {
                    // merge orphaned requests
                    const char *cursor = requestOnly.data(), *cursorEnd = cursor + requestOnly.size();
                    while (cursor < cursorEnd) {
                        // extract new record
                        header = (const SuperCache::DnsSessionHeader *) cursor;
                        cursor += SuperCache::dnsSessionHeaderSize;
                        SessionRecord record = header->toDnsTrackerSessionRecord();
                        record.query.append(cursor, header->queryLength);
                        cursor += header->queryLength;

                        // push
                        if (conditions.allowedIps.isEmpty || conditions.allowedIps.contains(record.destinationIp) || conditions.allowedIps.contains(record.sourceIp))
                            result.orphanedRequests[record.sessionId] = record;
                    }

                    // merge main records
                    std::string temp;
                    yyjson_doc *document = yyjson_read(details.data(), details.size(), YYJSON_READ_NOFLAG);
                    yyjson_val *rootObject = yyjson_doc_get_root(document);
                    yyjson_obj_iter serverIpIterator = yyjson_obj_iter_with(rootObject);
                    for (yyjson_val *serverIpRaw = yyjson_obj_iter_next(&serverIpIterator); serverIpRaw; serverIpRaw = yyjson_obj_iter_next(&serverIpIterator)) {
                        // obtain server IP
                        auto &targetServer = result.descriptions[SuperCodex::stringFromHex(yyjson_get_str(serverIpRaw))];

                        yyjson_val *statusArray = yyjson_obj_iter_get_val(serverIpRaw);
                        size_t statusIndex, statusIndexEnd;
                        yyjson_val *queryStringWithClientHits;
                        yyjson_arr_foreach(statusArray, statusIndex, statusIndexEnd, queryStringWithClientHits)
                        { // for each status(0~4)
                            // determine target summary value too add hits
                            uint64_t *targetSummary;
                            switch (statusIndex) {
                            case 0: // RESOLVED
                                targetSummary = &targetServer.summary.resolved;
                                break;
                            case 1: // ZEROANSWER
                                targetSummary = &targetServer.summary.answerCountZero;
                                break;
                            case 2: // ANSWERBROKEN
                                targetSummary = &targetServer.summary.answerBroken;
                                break;
                            case 3: // MULTIPLEQUERIES
                                targetSummary = &targetServer.summary.multipleQueries;
                                break;
                            case 4: // TIMEOUT
                                targetSummary = &targetServer.summary.multipleQueries;
                                break;
                            }

                            auto &targetStatus = targetServer.details[statusIndex];
                            yyjson_obj_iter queryStringIterator = yyjson_obj_iter_with(queryStringWithClientHits);
                            for (yyjson_val *queryStringRaw = yyjson_obj_iter_next(&queryStringIterator); queryStringRaw; queryStringRaw = yyjson_obj_iter_next(&queryStringIterator)) {
                                // recognize query string
                                const std::string queryString(yyjson_get_str(queryStringRaw));
                                auto &targetQuery = targetStatus[queryString];

                                // merge client hits
                                yyjson_obj_iter clientIpIterator = yyjson_obj_iter_with(yyjson_obj_iter_get_val(queryStringRaw));
                                for (yyjson_val *clientIpRaw = yyjson_obj_iter_next(&clientIpIterator); queryStringRaw; queryStringRaw = yyjson_obj_iter_next(&clientIpIterator)) {
                                    const std::string clientIp = SuperCodex::stringFromHex(yyjson_get_str(clientIpRaw));
                                    yyjson_val *usage = yyjson_obj_iter_get_val(clientIpRaw);
                                    const uint64_t hits = yyjson_get_uint(yyjson_obj_get(usage, "hits"));
                                    targetQuery[clientIp] += hits;
                                    (*targetSummary) += hits;

                                    // update latency statistics
                                    const uint64_t fastest = yyjson_get_uint(yyjson_obj_get(usage, "fastest")), slowest = yyjson_get_uint(yyjson_obj_get(usage, "slowest")), sum = yyjson_get_uint(yyjson_obj_get(usage, "sum"));
                                    // update for target server
                                    targetServer.summary.sum += sum;
                                    if (targetServer.summary.fastest > fastest)
                                        targetServer.summary.fastest = fastest;
                                    if (targetServer.summary.slowest < slowest)
                                        targetServer.summary.slowest = slowest;
                                }
                            }
                        }
                    }
                } break;

                case FILTERED: {
                    // merge orphaned requests
                    const char *cursor = requestOnly.data(), *cursorEnd = cursor + requestOnly.size();
                    while (cursor < cursorEnd) {
                        // extract new record
                        header = (const SuperCache::DnsSessionHeader *) cursor;
                        cursor += SuperCache::dnsSessionHeaderSize;
                        SessionRecord record = header->toDnsTrackerSessionRecord();
                        record.query.append(cursor, header->queryLength);
                        cursor += header->queryLength;

                        // push
                        if (conditions.includeExternalTransfer) {
                            if (conditions.allowedIps.contains(record.destinationIp) || conditions.allowedIps.contains(record.sourceIp))
                                result.orphanedRequests[record.sessionId] = record;
                        } else {
                            if (conditions.allowedIps.contains(record.destinationIp) && conditions.allowedIps.contains(record.sourceIp))
                                result.orphanedRequests[record.sessionId] = record;
                        }
                    }

                    // merge main records
                    std::string temp;
                    yyjson_doc *document = yyjson_read(details.data(), details.size(), YYJSON_READ_NOFLAG);
                    yyjson_val *rootObject = yyjson_doc_get_root(document);
                    yyjson_obj_iter serverIpIterator = yyjson_obj_iter_with(rootObject);
                    for (yyjson_val *serverIpRaw = yyjson_obj_iter_next(&serverIpIterator); serverIpRaw; serverIpRaw = yyjson_obj_iter_next(&serverIpIterator)) {
                        // obtain server IP
                        const std::string targetServerIp = SuperCodex::stringFromHex(yyjson_get_str(serverIpRaw));
                        const bool serverIpHitsTarget = conditions.allowedIps.contains(targetServerIp);
                        if (!conditions.includeExternalTransfer && !serverIpHitsTarget)
                            continue;
                        auto &targetServer = result.descriptions[targetServerIp];
                        yyjson_val *statusArray = yyjson_obj_iter_get_val(serverIpRaw);
                        size_t statusIndex, statusIndexEnd;
                        yyjson_val *queryStringWithClientHits;
                        yyjson_arr_foreach(statusArray, statusIndex, statusIndexEnd, queryStringWithClientHits)
                        { // for each status(0~4)
                            // determine target summary value to add hits
                            uint64_t *targetSummary;
                            switch (statusIndex) {
                            case 0: // RESOLVED
                                targetSummary = &targetServer.summary.resolved;
                                break;
                            case 1: // ZEROANSWER
                                targetSummary = &targetServer.summary.answerCountZero;
                                break;
                            case 2: // ANSWERBROKEN
                                targetSummary = &targetServer.summary.answerBroken;
                                break;
                            case 3: // MULTIPLEQUERIES
                                targetSummary = &targetServer.summary.multipleQueries;
                                break;
                            case 4: // TIMEOUT
                                targetSummary = &targetServer.summary.multipleQueries;
                                break;
                            }

                            auto &targetStatus = targetServer.details[statusIndex];
                            yyjson_obj_iter queryStringIterator = yyjson_obj_iter_with(queryStringWithClientHits);
                            for (yyjson_val *queryStringRaw = yyjson_obj_iter_next(&queryStringIterator); queryStringRaw; queryStringRaw = yyjson_obj_iter_next(&queryStringIterator)) {
                                // recognize query string
                                const std::string queryString(yyjson_get_str(queryStringRaw));
                                auto &targetQuery = targetStatus[queryString];

                                // merge client hits
                                yyjson_obj_iter clientIpIterator = yyjson_obj_iter_with(yyjson_obj_iter_get_val(queryStringRaw));
                                for (yyjson_val *clientIpRaw = yyjson_obj_iter_next(&clientIpIterator); queryStringRaw; queryStringRaw = yyjson_obj_iter_next(&clientIpIterator)) {
                                    const std::string clientIp = SuperCodex::stringFromHex(yyjson_get_str(clientIpRaw));
                                    if (conditions.includeExternalTransfer) {
                                        if (!serverIpHitsTarget && !conditions.allowedIps.contains(clientIp))
                                            continue;
                                    } else {
                                        if (!conditions.allowedIps.contains(clientIp)) // serverIpHitsTarget is already evaluated
                                            continue;
                                    }
                                    if (serverIpHitsTarget || conditions.allowedIps.contains(clientIp)) { // check IP filtering condition
                                        yyjson_val *usage = yyjson_obj_iter_get_val(clientIpRaw);
                                        const uint64_t hits = yyjson_get_uint(yyjson_obj_get(usage, "hits"));
                                        targetQuery[clientIp] += hits;
                                        (*targetSummary) += hits;

                                        // update latency statistics
                                        const uint64_t fastest = yyjson_get_uint(yyjson_obj_get(usage, "fastest")), slowest = yyjson_get_uint(yyjson_obj_get(usage, "slowest")), sum = yyjson_get_uint(yyjson_obj_get(usage, "sum"));
                                        // update for target server
                                        targetServer.summary.sum += sum;
                                        if (targetServer.summary.fastest > fastest)
                                            targetServer.summary.fastest = fastest;
                                        if (targetServer.summary.slowest < slowest)
                                            targetServer.summary.slowest = slowest;
                                    }
                                }
                            }
                        }
                    }
                } break;
                }

                // return used memory
                delete[] pmpiTriplet.decompressedRaw;
            }

            return result;
        });

        // merge cache packs
        for (const auto &pack : hourlyMerged) {
            // merge timeouts
            for (const auto &sessionId : pack.timeouts)
                if (orphanedRequests->contains(sessionId)) {
                    // initialize some stuff
                    auto &originalRequest = (*orphanedRequests)[sessionId];
                    originalRequest.status = TIMEOUT;
                    originalRequest.latency = -1;

                    // merge data to descriptions
                    descriptionTotal.mergeSessionRecord(originalRequest);
                    descriptions[originalRequest.destinationIp].mergeSessionRecord(originalRequest);

                    // remove orphaned request
                    orphanedRequests->erase(sessionId);
                } else
                    timeouts.push_back(sessionId);

            // merge orphaned requests
            for (const auto &request : pack.orphanedRequests)
                (*orphanedRequests).insert(request);

            // merge main records
            for (const auto &serverIpPair : pack.descriptions) {
                // update summary
                descriptionTotal.summary += serverIpPair.second.summary;
                auto &targetDescription = descriptions[serverIpPair.first];
                targetDescription.summary += serverIpPair.second.summary;

                for (size_t i = 0; i < 5; ++i) {
                    const auto &sourceStatus = serverIpPair.second.details[i];
                    auto &targetStatus = targetDescription.details[i], &targetStatus2 = descriptionTotal.details[i];
                    for (const auto &queryPair : sourceStatus) {
                        auto &targetQuery = targetStatus[queryPair.first], &targetQuery2 = targetStatus2[queryPair.first];
                        for (const auto &clientPair : queryPair.second) {
                            targetQuery[clientPair.first] += clientPair.second;
                            targetQuery2[clientPair.first] += clientPair.second;
                        }
                    }
                }
            }
        }
    }

    // free memories for partial records(they can be used along with partial records from cache)
    delete orphanedRequests;

    // count number of clients served
    descriptionTotal.setNumberOfDeduplicatedClients();
    for (auto &pair : descriptions)
        pair.second.setNumberOfDeduplicatedClients();

    // remove some dummies
    descriptions.erase(""s);
    for (auto i = descriptions.begin(); i != descriptions.end();) { // no action counters
        const auto &summary = i->second.summary;
        uint64_t summarySum = summary.timeout + summary.resolved + summary.answerCountZero + summary.answerBroken + summary.multipleQueries;
        if (summarySum == 0)
            i = descriptions.erase(i);
        else
            ++i;
    }

    // build server list in JSON
    std::vector<std::pair<std::string, unsigned long long>> serverListRaw;
    serverListRaw.reserve(descriptions.size());
    for (const auto &pair : descriptions)
        serverListRaw.push_back(std::make_pair(pair.first, pair.second.summary.clientsServed));
    std::sort(serverListRaw.begin(), serverListRaw.end(), [](const std::pair<std::string, unsigned long long> &a, const std::pair<std::string, unsigned long long> &b) -> bool { return a.second > b.second; });
    serverListSorted.reserve(descriptions.size());
    for (const auto &pair : serverListRaw)
        serverListSorted.push_back(SuperCodex::stringToHex(pair.first));

    // the final result is not written in disk, which can take more than tens of seconds

    // do some choirs
    logger.log("Results ready to serve: "s + std::to_string(descriptionTotal.summary.queriesReceived));
}

FeedRefinerDnsTracker::Status FeedRefinerDnsTracker::determineStatus(const std::string &remarks)
{
    if (remarks.find("DnsAnswerRRs="s) != std::string::npos) // found resource record for answer
        return RESOLVED;
    else { // find exception
        auto exceptionIndex = remarks.find("DnsException="s);
        if (exceptionIndex != std::string::npos) { // detected an exception
            switch (remarks.at(exceptionIndex + 13)) {
            case 'A':
                return ZEROANSWER; // DnsException=AnswerCountZero
            case 'R':
                return ANSWERBROKEN; // DnsException=ReadIndexOutOfBound
            case 'M':
                return MULTIPLEQUERIES; // DnsException=MultipleQueries
            }
        }
    }

    // in any case, if the session is detected as DNS, at least DNS query from client to server exists
    return REQUESTONLY;
}

std::string FeedRefinerDnsTracker::extractQuery(const std::string &remarks)
{
    std::string result;
    auto queryStart = remarks.find("DnsQuestion="s);
    if (queryStart == std::string::npos)
        return result;

    return remarks.substr(queryStart + 12, remarks.find(',', queryStart) - queryStart - 12);
}

FeedRefinerPop3Tracker::FeedRefinerPop3Tracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerPop3Tracker"s);

    // initialize session store
    sessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();
}

void FeedRefinerPop3Tracker::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // prepare for variables and objects
    std::string temp;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    std::string client, server;
    int busiestLimit = 10, erroneousLimit = 10;

    // check parameters
    if (parameters.contains("server"s))
        server = parameters.at("server"s);
    if (parameters.contains("client"s))
        client = parameters.at("client"s);
    try {
        if (parameters.contains("busiestlimit"s))
            busiestLimit = std::stoi(parameters.at("busiestlimit"s));
        if (parameters.contains("erroneouslimit"s))
            erroneousLimit = std::stoi(parameters.at("erroneouslimit"s));
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to convert limits to numbers.");
        return;
    }

    if (server.empty()) { // send server list
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);
        for (const std::string &ip : servers) {
            temp = SuperCodex::stringToHex(ip);
            yyjson_mut_arr_add_strncpy(document, rootArray, temp.data(), temp.size());
        }
    } else if (client.empty()) { // only server is selected: show ranking
        std::ifstream file(messyRoomPrefix + "/perpair"s, std::ios::binary);
        Record record;

        // build statistics
        ankerl::unordered_dense::map<std::string, int64_t> busiestClients, mostErroneousClients;
        if (server == "total"s) { // sequentially read all
            // read first record
            file.read((char *) &record, recordSize);
            while (file.gcount()) {
                // gather statistics
                std::string sourceIp(record.sourceIp, record.ipLength);
                busiestClients[sourceIp] += record.bytesTransferred;
                mostErroneousClients[sourceIp] += record.errorCount;

                // skip error string and read next record
                if (record.remarksSize)
                    file.seekg(record.remarksSize, std::ios::cur);
                file.read((char *) &record, recordSize);
            }
        } else { // read via index
            std::ifstream index(messyRoomPrefix + '/' + server, std::ios::binary);
            int64_t offset;
            // read first offset
            index.read((char *) &offset, 8);
            while (index.gcount()) {
                // adjust file cursor and read record
                file.seekg(offset, std::ios::beg);
                file.read((char *) &record, recordSize);

                // gather statistics
                std::string sourceIp(record.sourceIp, record.ipLength);
                busiestClients[sourceIp] += record.bytesTransferred;
                mostErroneousClients[sourceIp] += record.errorCount;

                // read next offset
                index.read((char *) &offset, 8);
            }
        }
        file.close();

        // sort statistics
        std::vector<std::pair<std::string, int64_t>> busiestClientsSorted, mostErroneousClientsSorted;
        busiestClientsSorted.reserve(busiestClients.size());
        mostErroneousClientsSorted.reserve(mostErroneousClients.size());
        for (const auto &pair : busiestClients)
            busiestClientsSorted.push_back(std::make_pair(pair.first, pair.second));
        for (const auto &pair : mostErroneousClients)
            mostErroneousClientsSorted.push_back(std::make_pair(pair.first, pair.second));
        std::sort(busiestClientsSorted.begin(), busiestClientsSorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) -> bool { return a.second > b.second; });
        std::sort(mostErroneousClientsSorted.begin(), mostErroneousClientsSorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) -> bool { return a.second > b.second; });

        // prepare for JSON root object
        yyjson_mut_val *rootObject = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootObject);

        // busiest clients
        yyjson_mut_val *busiestClientsArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "busiestclients", busiestClientsArray);
        for (int i = 0, iEnd = std::min(busiestLimit, static_cast<int>(busiestClientsSorted.size())); i < iEnd; ++i) {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(busiestClientsArray, object);
            const auto &pair = busiestClientsSorted.at(i);

            temp = SuperCodex::stringToHex(pair.first);
            yyjson_mut_obj_add_strncpy(document, object, "ip", temp.data(), temp.size());
            yyjson_mut_obj_add_int(document, object, "bytestransferred", pair.second);
        }

        // most erroneous clients
        yyjson_mut_val *mostErroneousClientsArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "mosterroneousclients", mostErroneousClientsArray);
        for (int i = 0, iEnd = std::min(erroneousLimit, static_cast<int>(mostErroneousClientsSorted.size())); i < iEnd; ++i) {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(mostErroneousClientsArray, object);
            const auto &pair = mostErroneousClientsSorted.at(i);

            temp = SuperCodex::stringToHex(pair.first);
            yyjson_mut_obj_add_strncpy(document, object, "ip", temp.data(), temp.size());
            yyjson_mut_obj_add_int(document, object, "errors", pair.second);
        }
    } else { // client is set: show error details
        client = SuperCodex::stringFromHex(client);
        // obtain error messages
        std::string errorMessges;
        std::ifstream file(messyRoomPrefix + "/perpair"s, std::ios::binary);
        Record record;
        if (server == "total"s) { // find all that matches to target destination IP
            // read first record
            file.read((char *) &record, recordSize);
            while (file.gcount()) {
                if (std::string(record.sourceIp, record.ipLength) == client && record.remarksSize) { // client is found
                    // read from file and write to buffer
                    char *errorBuffer = new char[record.remarksSize];
                    file.read(errorBuffer, record.remarksSize);
                    errorMessges.append(errorBuffer, record.remarksSize);

                    // free memory
                    delete[] errorBuffer;
                } else if (record.remarksSize)
                    file.seekg(record.remarksSize, std::ios::cur);

                // read next record
                file.read((char *) &record, recordSize);
            }
        } else {
            std::ifstream index(messyRoomPrefix + '/' + server, std::ios::binary);
            int64_t offset;
            // read first offset
            index.read((char *) &offset, 8);
            while (index.gcount()) {
                // adjust file cursor and read record
                file.seekg(offset, std::ios::beg);
                file.read((char *) &record, recordSize);

                // read error messages if client is found
                if (std::string(record.sourceIp, record.ipLength) == client && record.remarksSize) {
                    // read from file and write to buffer
                    char *errorBuffer = new char[record.remarksSize];
                    file.read(errorBuffer, record.remarksSize);
                    errorMessges.append(errorBuffer, record.remarksSize);

                    // free memory
                    delete[] errorBuffer;
                }

                // read next offset
                index.read((char *) &offset, 8);
            }
        }
        file.close();

        // count
        ankerl::unordered_dense::map<std::string, unsigned int> hits;
        std::istringstream lineReader(errorMessges);
        for (std::string line; std::getline(lineReader, line);)
            ++hits[line];

        // ranking
        std::vector<std::pair<std::string, unsigned int>> ranking;
        ranking.reserve(hits.size());
        for (const auto &pair : hits)
            ranking.push_back(pair);
        std::sort(ranking.begin(), ranking.end(), [](const std::pair<std::string, unsigned int> &a, const std::pair<std::string, unsigned int> &b) -> bool { return a.second > b.second; });

        // build JSON
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);
        for (const auto &pair : ranking) {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(rootArray, object);
            yyjson_mut_obj_add_strncpy(document, object, "message", pair.first.data(), pair.first.size());
            yyjson_mut_obj_add_int(document, object, "hits", pair.second);
        }
    }

    Civet7::respond200(connection, document);
}

void FeedRefinerPop3Tracker::dumpResults(mg_connection *connection)
{
    // header
    std::string chunk("Client\tServer\tBytesTransferred\tErrorCounts\tErrors\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // read file
    Record record;
    char *remarksBuffer;
    std::ifstream file(messyRoomPrefix + "/perpair"s, std::ios::binary);
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);
    // read first record
    file.read((char *) &record, recordSize);
    while (file.gcount()) {
        // write down
        chunk.append(SuperCodex::humanReadableIp(std::string(record.sourceIp, record.ipLength)) + '\t').append(SuperCodex::humanReadableIp(std::string(record.destinationIp, record.ipLength)) + '\t').append(std::to_string(record.bytesTransferred) + '\t').append(std::to_string(record.errorCount) + '\t');
        if (record.errorCount) { // gather error messages
            remarksBuffer = new char[record.remarksSize];
            file.read(remarksBuffer, record.remarksSize);

            // count
            ankerl::unordered_dense::map<std::string, unsigned int> hits;
            std::istringstream lineReader(std::string(remarksBuffer, record.remarksSize));
            for (std::string line; std::getline(lineReader, line);)
                ++hits[line];

            // build ranking
            std::vector<std::pair<std::string, unsigned int>> ranking;
            ranking.reserve(hits.size());
            for (const auto &pair : hits)
                ranking.push_back(pair);
            std::sort(ranking.begin(), ranking.end(), [](const std::pair<std::string, unsigned int> &a, const std::pair<std::string, unsigned int> &b) -> bool { return a.second > b.second; });

            // add to chunk
            for (const auto &pair : ranking) {
                chunk.append(pair.first).append(": "s).append(std::to_string(pair.second)).push_back('|');
            }

            // remove redundant pipe
            chunk.pop_back();

            // free memory
            delete[] remarksBuffer;
        }
        chunk.push_back('\n'); // end of the line

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
    file.close();

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

void FeedRefinerPop3Tracker::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    auto resultParts = SuperCodex::parallel_convert<SuperCodex::Loader *, Pack>(codices, [&](const SuperCodex::Loader *codex) -> Pack {
        Pack rawData;

        // load session data
        for (const auto &pair : codex->sessions)
            if (pair.second->detectedL7 == SuperCodex::Session::POP3) {
                rawData.sessions.push_back(*pair.second);
                rawData.descriptions[pair.first]; // create new empty record
            }

        // load statistics
        for (auto bps = codex->firstBpsPerSession(); bps; bps = codex->nextBpsPerSession(bps))
            if (rawData.descriptions.contains(bps->sessionId))
                rawData.descriptions[bps->sessionId].bytesTransferred += bps->fromSmallToBig + bps->fromBigToSmall;

        // load remarks
        for (auto remarks = codex->firstRemarks(); remarks.content; remarks = codex->nextRemarks(remarks))
            if (rawData.descriptions.contains(remarks.sessionId)) {
                // filter lines starting with "Pop3Err="
                int32_t errorCount = 0;
                std::string rawString(remarks.content, remarks.size), filtered;
                std::istringstream lineReader(rawString);
                for (std::string line; std::getline(lineReader, line);)
                    if (line.find("Pop3Err="s) != std::string::npos) {
                        while (line.back() == '\r' || line.back() == '\n')
                            line.pop_back();
                        filtered.append(line.substr(8)).push_back('\n');
                        ++errorCount;
                    }
                rawData.descriptions[remarks.sessionId].remarks.append(filtered);
                rawData.descriptions[remarks.sessionId].errorCount += errorCount;
            }

        return rawData;
    });

    // merge
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Pack> resultRawsFuture) {
            // background: update session information
            std::thread updateSessionInformationFuture([&]() {
                for (const auto &resultRaw : resultRawsFuture)
                    updateTimestampAndMergeSessions(resultRaw.sessions);
            });

            std::ofstream file(messyRoomPrefix + "/persession"s, std::ios::binary | std::ios::app);
            Record record;
            for (const auto &resultRaw : resultRawsFuture)
                for (const auto &description : resultRaw.descriptions) {
                    record.setSessionId(description.first);
                    record.errorCount = description.second.errorCount;
                    record.bytesTransferred = description.second.bytesTransferred;
                    record.remarksSize = description.second.remarks.size();
                    file.write((const char *) &record, recordSize);
                    file.write(description.second.remarks.data(), description.second.remarks.size());
                }

            // wait for session organizer to finish its job
            updateSessionInformationFuture.join();
        },
        resultParts);
}

void FeedRefinerPop3Tracker::finalize()
{
    // prepare to merge per-session records to client-server pair based ones
    ankerl::unordered_dense::map<std::string, std::pair<Record, std::string>> merged; // <source IP+destination IP> + <merged record + merged remarks>
    std::ifstream input(messyRoomPrefix + "/persession"s, std::ios::binary);
    Record readBuffer;
    char *textBuffer;

    // read first record
    input.read((char *) &readBuffer, recordSize);
    while (input.gcount()) {
        // merge
        auto &session = sessions->at(readBuffer.sessionId());
        std::string sourceIp = SuperCodex::sourceIp(session), destinationIp = SuperCodex::destinationIp(session);
        // if the pair is new, initialize the record with IP information
        if (merged.contains(sourceIp + destinationIp) == 0) {
            auto &target = merged[sourceIp + destinationIp];
            target.first.ipLength = sourceIp.size();
            memcpy(target.first.sourceIp, sourceIp.data(), target.first.ipLength);
            memcpy(target.first.destinationIp, destinationIp.data(), target.first.ipLength);
        }
        auto &target = merged[sourceIp + destinationIp];
        target.first.bytesTransferred += readBuffer.bytesTransferred;
        target.first.errorCount += readBuffer.errorCount;
        // read remarks as needed
        if (readBuffer.remarksSize) {
            textBuffer = new char[readBuffer.remarksSize];
            input.read(textBuffer, readBuffer.remarksSize);
            target.second.append(textBuffer, readBuffer.remarksSize);
            delete[] textBuffer;
        }
        // remarksSize will be set after this loop

        // read next record
        input.read((char *) &readBuffer, recordSize);
    }

    // set remarksSize for each record
    for (auto &pair : merged)
        pair.second.first.remarksSize = pair.second.second.size();

    // write down merged data as well as index
    std::ofstream file(messyRoomPrefix + "/perpair"s, std::ios::binary);
    ankerl::unordered_dense::map<std::string, std::vector<int64_t>> index; // destination IP + vector of offsets for "/perpair" file
    size_t offset = 0;
    for (const auto &pair : merged) {
        // build index
        index[pair.first.substr(pair.first.size() / 2)].push_back(offset);

        // write down file
        const auto &targetRecord = pair.second;
        file.write((const char *) &targetRecord.first, recordSize);
        file.write((const char *) targetRecord.second.data(), targetRecord.first.remarksSize);

        // calculate next offset
        offset += recordSize + targetRecord.first.remarksSize;
    }

    // write index and server list
    servers.reserve(index.size());
    for (const auto &pair : index) {
        std::ofstream indexFile(messyRoomPrefix + '/' + SuperCodex::stringToHex(pair.first), std::ios::binary);
        indexFile.write((const char *) pair.second.data(), pair.second.size() * 8);
        servers.push_back(pair.first);
    }
    std::sort(servers.begin(), servers.end());

    // log
    input.close();
    std::filesystem::remove(messyRoomPrefix + "/persession"s);
    logger.log("Results ready to serve: "s + std::to_string(merged.size()));
}

FeedRefinerImapTracker::FeedRefinerImapTracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerImapTracker"s);

    // initialize session store
    sessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();
}

void FeedRefinerImapTracker::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // prepare for variables and objects
    std::string temp;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    std::string client, server;
    int busiestLimit = 10, erroneousLimit = 10, alertsLimit = 10;

    // check parameters
    if (parameters.contains("server"s))
        server = parameters.at("server"s);
    if (parameters.contains("client"s))
        client = parameters.at("client"s);
    try {
        if (parameters.contains("busiestlimit"s))
            busiestLimit = std::stoi(parameters.at("busiestlimit"s));
        if (parameters.contains("erroneouslimit"s))
            erroneousLimit = std::stoi(parameters.at("erroneouslimit"s));
        if (parameters.contains("mostalertedlimit"s))
            alertsLimit = std::stoi(parameters.at("mostalertedlimit"s));
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to convert limits to numbers.");
        return;
    }

    if (server.empty()) { // send server list
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);

        for (const std::string &ip : servers) {
            temp = SuperCodex::stringToHex(ip);
            yyjson_mut_arr_add_strncpy(document, rootArray, temp.data(), temp.size());
        }
    } else if (client.empty()) { // only server is selected: show ranking
        std::ifstream file(messyRoomPrefix + "/perpair"s, std::ios::binary);
        Record record;

        // build statistics
        ankerl::unordered_dense::map<std::string, int64_t> busiestClients, mostErroneousClients, mostAlertedClients;
        if (server == "total"s) { // sequentially read all
            // read first record
            file.read((char *) &record, recordSize);
            while (file.gcount()) {
                // gather statistics
                std::string sourceIp(record.sourceIp, record.ipLength);
                busiestClients[sourceIp] += record.bytesTransferred;
                mostErroneousClients[sourceIp] += record.noCount + record.badCount;
                mostAlertedClients[sourceIp] += record.alertCount;

                // skip error string and read next record
                size_t skipLength = record.noSize + record.badSize + record.alertSize;
                if (skipLength)
                    file.seekg(skipLength, std::ios::cur);
                file.read((char *) &record, recordSize);
            }
        } else { // read via index
            std::ifstream index(messyRoomPrefix + '/' + server, std::ios::binary);
            int64_t offset;
            // read first offset
            index.read((char *) &offset, 8);
            while (index.gcount()) {
                // adjust file cursor and read record
                file.seekg(offset, std::ios::beg);
                file.read((char *) &record, recordSize);

                // gather statistics
                std::string sourceIp(record.sourceIp, record.ipLength);
                busiestClients[sourceIp] += record.bytesTransferred;
                mostErroneousClients[sourceIp] += record.noCount + record.badCount;
                mostAlertedClients[sourceIp] += record.alertCount;

                // read next offset
                index.read((char *) &offset, 8);
            }
        }

        // sort statistics
        std::vector<std::pair<std::string, int64_t>> busiestClientsSorted, mostErroneousClientsSorted, mostAlertedClientsSorted;
        busiestClientsSorted.reserve(busiestClients.size());
        mostErroneousClientsSorted.reserve(mostErroneousClients.size());
        mostAlertedClientsSorted.reserve(mostAlertedClients.size());
        for (const auto &pair : busiestClients)
            busiestClientsSorted.push_back(std::make_pair(pair.first, pair.second));
        for (const auto &pair : mostErroneousClients)
            mostErroneousClientsSorted.push_back(std::make_pair(pair.first, pair.second));
        for (const auto &pair : mostAlertedClients)
            mostAlertedClientsSorted.push_back(std::make_pair(pair.first, pair.second));
        std::sort(busiestClientsSorted.begin(), busiestClientsSorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) -> bool { return a.second > b.second; });
        std::sort(mostErroneousClientsSorted.begin(), mostErroneousClientsSorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) -> bool { return a.second > b.second; });
        std::sort(mostAlertedClientsSorted.begin(), mostAlertedClientsSorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) -> bool { return a.second > b.second; });

        // prepare for JSON root object
        yyjson_mut_val *rootObject = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootObject);

        // busiest clients
        yyjson_mut_val *busiestClientsArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "busiestclients", busiestClientsArray);
        for (int i = 0, iEnd = std::min(busiestLimit, static_cast<int>(busiestClientsSorted.size())); i < iEnd; ++i)
            if (busiestClientsSorted.at(i).second) {
                yyjson_mut_val *object = yyjson_mut_obj(document);
                yyjson_mut_arr_append(busiestClientsArray, object);
                const auto &pair = busiestClientsSorted.at(i);

                temp = SuperCodex::stringToHex(pair.first);
                yyjson_mut_obj_add_strncpy(document, object, "ip", temp.data(), temp.size());
                yyjson_mut_obj_add_int(document, object, "bytestransferred", pair.second);
            }

        // clients with warnings and errors
        yyjson_mut_val *mostErroneousClientsArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "mosterroneousclients", mostErroneousClientsArray);
        for (int i = 0, iEnd = std::min(erroneousLimit, static_cast<int>(mostErroneousClientsSorted.size())); i < iEnd; ++i) /*if(mostErroneousClientsSorted.at(i).second)*/ {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(mostErroneousClientsArray, object);
            const auto &pair = mostErroneousClientsSorted.at(i);

            temp = SuperCodex::stringToHex(pair.first);
            yyjson_mut_obj_add_strncpy(document, object, "ip", temp.data(), temp.size());
            yyjson_mut_obj_add_int(document, object, "errors", pair.second);
        }

        // clients with most alerts
        yyjson_mut_val *mostAlertedClientsArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "mostalertedclients", mostAlertedClientsArray);
        for (int i = 0, iEnd = std::min(alertsLimit, static_cast<int>(mostAlertedClientsSorted.size())); i < iEnd; ++i) /*if(mostAlertedClientsSorted.at(i).second)*/ {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(mostAlertedClientsArray, object);
            const auto &pair = mostAlertedClientsSorted.at(i);

            temp = SuperCodex::stringToHex(pair.first);
            yyjson_mut_obj_add_strncpy(document, object, "ip", temp.data(), temp.size());
            yyjson_mut_obj_add_int(document, object, "errors", pair.second);
        }
    } else { // client is set: show details
        // obtain messages
        std::string nos, bads, alerts;
        std::ifstream file(messyRoomPrefix + "/perpair"s, std::ios::binary);
        Record record;

        if (server == "total"s) { // find all that matches to target destination IP
            // read first record
            file.read((char *) &record, recordSize);
            while (file.gcount()) {
                size_t messageCount = record.noCount + record.badCount + record.alertCount;
                if (std::string(record.sourceIp, record.ipLength) == client && messageCount) { // client is found
                    char *textBuffer;
                    if (record.noCount) {
                        // read from file and write to buffer
                        textBuffer = new char[record.noSize];
                        file.read(textBuffer, record.noSize);
                        nos.append(textBuffer, record.noSize);
                        delete[] textBuffer;
                    }
                    if (record.badCount) {
                        // read from file and write to buffer
                        textBuffer = new char[record.badSize];
                        file.read(textBuffer, record.badSize);
                        bads.append(textBuffer, record.badSize);
                        delete[] textBuffer;
                    }
                    if (record.alertCount) {
                        // read from file and write to buffer
                        textBuffer = new char[record.alertSize];
                        file.read(textBuffer, record.alertSize);
                        alerts.append(textBuffer, record.alertSize);
                        delete[] textBuffer;
                    }
                } else if (messageCount)
                    file.seekg(messageCount, std::ios::cur);

                // read next record
                file.read((char *) &record, recordSize);
            }
        } else {
            std::ifstream index(messyRoomPrefix + '/' + server, std::ios::binary);
            int64_t offset;
            // read first offset
            index.read((char *) &offset, 8);
            while (index.gcount()) {
                // adjust file cursor and read record
                file.seekg(offset, std::ios::beg);
                file.read((char *) &record, recordSize);

                char *textBuffer;
                if (record.noCount) {
                    // read from file and write to buffer
                    textBuffer = new char[record.noSize];
                    file.read(textBuffer, record.noSize);
                    nos.append(textBuffer, record.noSize);
                    delete[] textBuffer;
                }
                if (record.badCount) {
                    // read from file and write to buffer
                    textBuffer = new char[record.badSize];
                    file.read(textBuffer, record.badSize);
                    bads.append(textBuffer, record.badSize);
                    delete[] textBuffer;
                }
                if (record.alertCount) {
                    // read from file and write to buffer
                    textBuffer = new char[record.alertSize];
                    file.read(textBuffer, record.alertSize);
                    alerts.append(textBuffer, record.alertSize);
                    delete[] textBuffer;
                }

                // read next offset
                index.read((char *) &offset, 8);
            }
        }

        // count
        ankerl::unordered_dense::map<std::string, unsigned int> errorHits, alertHits;
        std::istringstream lineReader;
        lineReader.str(nos);
        for (std::string line; std::getline(lineReader, line);)
            ++errorHits['n' + line];
        lineReader.str(bads);
        for (std::string line; std::getline(lineReader, line);)
            ++errorHits['b' + line];
        lineReader.str(alerts);
        for (std::string line; std::getline(lineReader, line);)
            ++alertHits[line];

        // arrange ranks
        std::vector<std::pair<std::string, unsigned int>> errorRanking, alertRanking;
        errorRanking.reserve(errorHits.size());
        alertRanking.reserve(alertHits.size());
        for (const auto &pair : errorHits)
            errorRanking.push_back(pair);
        for (const auto &pair : alertHits)
            alertRanking.push_back(pair);
        std::sort(errorRanking.begin(), errorRanking.end(), [](const std::pair<std::string, unsigned int> &a, const std::pair<std::string, unsigned int> &b) -> bool { return a.second > b.second; });
        std::sort(alertRanking.begin(), alertRanking.end(), [](const std::pair<std::string, unsigned int> &a, const std::pair<std::string, unsigned int> &b) -> bool { return a.second > b.second; });

        // prepare for JSON root object
        yyjson_mut_val *rootObject = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootObject);

        // error ranking
        yyjson_mut_val *errorDetailsArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "errordetails", errorDetailsArray);
        for (const auto &pair : errorRanking) {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(errorDetailsArray, object);

            yyjson_mut_obj_add_strncpy(document, object, "message", pair.first.data() + 1, pair.first.size() - 1);
            yyjson_mut_obj_add_int(document, object, "hits", pair.second);
            switch (pair.first.at(0)) {
            case 'n':
                yyjson_mut_obj_add_strncpy(document, object, "type", "no", 2);
                break;
            case 'b':
                yyjson_mut_obj_add_strncpy(document, object, "type", "bad", 3);
                break;
            }
        }

        // alert ranking
        yyjson_mut_val *alertDetailsArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "alertdetails", alertDetailsArray);
        for (const auto &pair : alertRanking) {
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(alertDetailsArray, object);

            yyjson_mut_obj_add_strncpy(document, object, "message", pair.first.data(), pair.first.size());
            yyjson_mut_obj_add_int(document, object, "hits", pair.second);
        }
    }

    Civet7::respond200(connection, document);
}

void FeedRefinerImapTracker::dumpResults(mg_connection *connection)
{
    // header
    std::string chunk("Client\tServer\tBytesTransferred\tErrorCounts\tErrors\tAlertCounts\tAlerts\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    std::ifstream file(messyRoomPrefix + "/perpair"s, std::ios::binary);
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);
    Record record;
    // read first record
    file.read((char *) &record, recordSize);
    while (file.gcount()) {
        chunk.append(SuperCodex::humanReadableIp(std::string(record.sourceIp, record.ipLength)) + '\t').append(SuperCodex::humanReadableIp(std::string(record.sourceIp, record.ipLength)) + '\t').append(std::to_string(record.bytesTransferred) + '\t').append(std::to_string(record.badCount + record.noCount) + '\t');

        // gather 'no' and 'bad' messages
        if (record.badCount + record.noCount) {
            // read 'no's and 'bad's
            std::string errorMessges;
            char *textBuffer;
            if (record.noCount) {
                textBuffer = new char[record.noSize];
                file.read(textBuffer, record.noSize);
                errorMessges.append(textBuffer, record.noSize);
                delete[] textBuffer;
            }
            if (record.badCount) {
                textBuffer = new char[record.badSize];
                file.read(textBuffer, record.badSize);
                errorMessges.append(textBuffer, record.badSize);
                delete[] textBuffer;
            }

            // count
            ankerl::unordered_dense::map<std::string, unsigned int> hits;
            std::istringstream lineReader(errorMessges);
            for (std::string line; std::getline(lineReader, line);)
                ++hits[line];

            // build ranking
            std::vector<std::pair<std::string, unsigned int>> ranking;
            ranking.reserve(hits.size());
            for (const auto &pair : hits)
                ranking.push_back(pair);
            std::sort(ranking.begin(), ranking.end(), [](const std::pair<std::string, unsigned int> &a, const std::pair<std::string, unsigned int> &b) -> bool { return a.second > b.second; });

            // add to chunk
            for (const auto &pair : ranking) {
                chunk.append(pair.first).append(": "s).append(std::to_string(pair.second)).push_back('|');
            }

            // remove redundant pipe
            chunk.pop_back();
        }
        chunk.push_back('\t'); // end of the line

        // gather alert messages
        chunk.append(std::to_string(record.alertCount) + '\t');
        if (record.alertCount) {
            std::string alertMessages;
            char *textBuffer = new char[record.badSize];
            file.read(textBuffer, record.badSize);
            alertMessages.append(textBuffer, record.badSize);
            delete[] textBuffer;

            // count
            ankerl::unordered_dense::map<std::string, unsigned int> hits;
            std::istringstream lineReader(alertMessages);
            for (std::string line; std::getline(lineReader, line);)
                ++hits[line];

            // build ranking
            std::vector<std::pair<std::string, unsigned int>> ranking;
            ranking.reserve(hits.size());
            for (const auto &pair : hits)
                ranking.push_back(pair);
            std::sort(ranking.begin(), ranking.end(), [](const std::pair<std::string, unsigned int> &a, const std::pair<std::string, unsigned int> &b) -> bool { return a.second > b.second; });

            // add to chunk
            for (const auto &pair : ranking) {
                chunk.append(pair.first).append(": "s).append(std::to_string(pair.second)).push_back('|');
            }

            // remove redundant pipe
            chunk.pop_back();
        }
        chunk.push_back('\n'); // end of the line

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

void FeedRefinerImapTracker::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    auto resultParts = SuperCodex::parallel_convert<SuperCodex::Loader *, Pack>(codices, [&](const SuperCodex::Loader *codex) -> Pack {
        Pack rawData;

        // load session data
        for (const auto &pair : codex->sessions)
            if (pair.second->detectedL7 == SuperCodex::Session::IMAP) {
                rawData.sessions.push_back(*pair.second);
                rawData.descriptions[pair.first]; // create a blank description
            }

        // load statistics
        for (auto bps = codex->firstBpsPerSession(); bps; bps = codex->nextBpsPerSession(bps))
            if (rawData.descriptions.contains(bps->sessionId))
                rawData.descriptions[bps->sessionId].bytesTransferred += bps->fromSmallToBig + bps->fromBigToSmall;

        // load remarks
        for (auto remarks = codex->firstRemarks(); remarks.content; remarks = codex->nextRemarks(remarks))
            if (rawData.descriptions.contains(remarks.sessionId)) {
                // filter lines for IMAP nos, bads, or alerts
                int32_t noCount = 0, badCount = 0, alertCount = 0;
                std::string rawString(remarks.content, remarks.size), nos, bads, alerts;
                std::istringstream lineReader(rawString);
                for (std::string line; std::getline(lineReader, line);) {
                    while (line.back() == '\r' || line.back() == '\n')
                        line.pop_back();
                    if (line.find("ImapNo="s) != std::string::npos) {
                        nos.append(line.substr(8)).push_back('\n');
                        ++noCount;
                    } else if (line.find("ImapBad="s) != std::string::npos) {
                        bads.append(line.substr(8)).push_back('\n');
                        ++badCount;
                    } else if (line.find("ImapAlert="s) != std::string::npos) {
                        alerts.append(line.substr(10)).push_back('\n');
                        ++alertCount;
                    }
                }

                // put arranged data
                auto &description = rawData.descriptions[remarks.sessionId];
                description.nos.append(nos);
                description.noCount += noCount;
                description.bads.append(bads);
                description.badCount += badCount;
                description.alerts.append(alerts);
                description.alertCount += alertCount;
            }

        return rawData;
    });

    // merge
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Pack> resultRawsFuture) {
            // background: update session information
            std::thread updateSessionInformationFuture([&]() {
                for (const auto &resultRaw : resultRawsFuture)
                    updateTimestampAndMergeSessions(resultRaw.sessions);
            });

            std::ofstream file(messyRoomPrefix + "/persession"s, std::ios::binary | std::ios::app);
            Record record;
            for (const auto &resultRaw : resultRawsFuture)
                for (const auto &description : resultRaw.descriptions) {
                    record.setSessionId(description.first);
                    record.noCount = description.second.noCount;
                    record.badCount = description.second.badCount;
                    record.alertCount = description.second.alertCount;
                    record.bytesTransferred = description.second.bytesTransferred;
                    record.noSize = description.second.nos.size();
                    record.badSize = description.second.bads.size();
                    record.alertSize = description.second.alerts.size();
                    file.write((const char *) &record, recordSize);
                    file.write(description.second.nos.data(), description.second.nos.size());
                    file.write(description.second.bads.data(), description.second.bads.size());
                    file.write(description.second.alerts.data(), description.second.alerts.size());
                }

            // wait for session organizer to finish its job
            updateSessionInformationFuture.join();
        },
        resultParts);
}

void FeedRefinerImapTracker::finalize()
{
    // prepare to merge per-session records to client-server pair based ones
    ankerl::unordered_dense::map<std::string, std::pair<Record, std::string[3]>> merged; // <source IP+destination IP> + <merged record + merged nos, bads, alerts>
    std::ifstream input(messyRoomPrefix + "/persession"s, std::ios::binary);
    Record readBuffer;
    char *textBuffer;

    // read first
    input.read((char *) &readBuffer, recordSize);
    while (input.gcount()) {
        // merge
        auto &session = sessions->at(readBuffer.sessionId());
        std::string sourceIp = SuperCodex::sourceIp(session), destinationIp = SuperCodex::destinationIp(session);
        // if the pair is new, initialize the record with IP information
        if (merged.contains(sourceIp + destinationIp) == 0) {
            auto &target = merged[sourceIp + destinationIp];
            target.first.ipLength = sourceIp.size();
            memcpy(target.first.sourceIp, sourceIp.data(), target.first.ipLength);
            memcpy(target.first.destinationIp, destinationIp.data(), target.first.ipLength);
        }
        auto &target = merged[sourceIp + destinationIp];
        target.first.bytesTransferred += readBuffer.bytesTransferred;
        // read nos, bads, and alerts
        if (readBuffer.noCount) {
            target.first.noCount += readBuffer.noCount;
            textBuffer = new char[readBuffer.noSize];
            input.read(textBuffer, readBuffer.noSize);
            target.second[0].append(textBuffer, readBuffer.noSize);
            delete[] textBuffer;
        }
        if (readBuffer.badCount) {
            target.first.badCount += readBuffer.badCount;
            textBuffer = new char[readBuffer.badSize];
            input.read(textBuffer, readBuffer.badSize);
            target.second[1].append(textBuffer, readBuffer.badSize);
            delete[] textBuffer;
        }
        if (readBuffer.alertCount) {
            target.first.alertCount += readBuffer.alertCount;
            textBuffer = new char[readBuffer.alertSize];
            input.read(textBuffer, readBuffer.alertSize);
            target.second[2].append(textBuffer, readBuffer.alertSize);
            delete[] textBuffer;
        }
        // noSize, badSize, alertSize will be set after this loop

        // read next record
        input.read((char *) &readBuffer, recordSize);
    }

    // set noSize, badSize, alertSize for each record
    for (auto &pair : merged) {
        pair.second.first.noSize = pair.second.second[0].size();
        pair.second.first.badSize = pair.second.second[1].size();
        pair.second.first.alertSize = pair.second.second[2].size();
    }

    // write down merged data as well as index
    std::ofstream file(messyRoomPrefix + "/perpair"s, std::ios::binary);
    ankerl::unordered_dense::map<std::string, std::vector<int64_t>> index; // destination IP + vector of offsets for "/perpair" file
    size_t offset = 0;
    for (const auto &pair : merged) {
        // build index
        index[pair.first.substr(pair.first.size() / 2)].push_back(offset);

        // write down file
        const auto &targetRecord = pair.second;
        file.write((const char *) &targetRecord.first, recordSize);
        if (targetRecord.first.noSize)
            file.write((const char *) targetRecord.second[0].data(), targetRecord.first.noSize);
        if (targetRecord.first.badSize)
            file.write((const char *) targetRecord.second[1].data(), targetRecord.first.badSize);
        if (targetRecord.first.alertSize)
            file.write((const char *) targetRecord.second[2].data(), targetRecord.first.alertSize);

        // calculate next offset
        offset += recordSize + targetRecord.first.noSize + targetRecord.first.badSize + targetRecord.first.alertSize;
    }

    // write index and enumerate servers
    servers.reserve(index.size());
    for (const auto &pair : index) {
        std::ofstream indexFile(messyRoomPrefix + '/' + SuperCodex::stringToHex(pair.first), std::ios::binary);
        indexFile.write((const char *) pair.second.data(), pair.second.size() * 8);
        servers.push_back(pair.first);
    }
    std::sort(servers.begin(), servers.end());

    // log
    input.close();
    std::filesystem::remove(messyRoomPrefix + "/persession"s);
    logger.log("Results ready to serve: "s + std::to_string(merged.size()));
}

FeedRefinerHttpTracker::FeedRefinerHttpTracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerHttpTracker"s);

    // build IPv4 GeoLocation lookup table
    std::istringstream lineReader(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream("IP2LOCATION-LITE-DB1.CSV"s, std::ifstream::binary).rdbuf()).str());
    for (std::string line; std::getline(lineReader, line);) {
        GeoLocationIpV4 record;
        std::istringstream splitter(line);
        std::string recordRaw;
        std::getline(splitter, recordRaw, ',');
        record.ipFrom = std::stoul(recordRaw.substr(1, recordRaw.size() - 2));
        std::getline(splitter, recordRaw, ',');
        record.ipTo = std::stoul(recordRaw.substr(1, recordRaw.size() - 2));
        std::getline(splitter, recordRaw, ',');
        record.country = recordRaw.substr(1, recordRaw.size() - 2);
        if (record.country == "-"s)
            record.country = "--"s; // to match length for 2 byte country code
        geoLocationStoreIpV4.push_back(std::move(record));
    }
    if (geoLocationStoreIpV4.empty())
        logger.oops("Failed to build IPv4 geolocation store. Geolocation for IPv4 will be unavailable.");

    // initialize session store
    sessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();

    // create hashmap for orphaned requests
    orphanedRequests = new ankerl::unordered_dense::map<uint64_t, std::string>();

    // recognize regular expression
    if (conditions.parameters.contains("regex"s)) {
        regex = conditions.parameters.at("regex"s);
        logger.log("Regex set: " + regex);
    }
}

FeedRefinerHttpTracker::~FeedRefinerHttpTracker()
{
    // delete hash
    delete orphanedRequests;
}

void FeedRefinerHttpTracker::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // prepare for variables and objects
    std::string temp;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    std::string service, page;

    // check parameters
    if (parameters.contains("page"s))
        page = parameters.at("page"s); // clientprofile, performance, errordetails
    if (parameters.contains("service"s))
        service = parameters.at("service"s);

    // describe
    if (page.empty()) { // no target service or options to describe: enumerate services
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);
        for (const std::string &service : services)
            yyjson_mut_arr_add_strn(document, rootArray, service.data(), service.size());
    } else {
        if (service.empty()) {
            logger.log("Page requested without parameter 'service'.");
            mg_send_http_error(connection, 400, "page requested without parameter 'service'.");
            return;
        }

        // build contents
        if (page == "clientprofile"s)
            writeClientProfile(parameters, document, service);
        else if (page == "performance")
            writePerformance(parameters, document, service, bindValue);
        else if (page == "errordetails") {
            if (parameters.contains("path"s) == 0) {
                mg_send_http_error(connection, 400, "page requested without parameter 'path'.");
                return;
            }
            writeErrorDetails(parameters, document, service, parameters.at("path"s));
        }
    }

    // send result
    Civet7::respond200(connection, document);
}

void FeedRefinerHttpTracker::dumpResults(mg_connection *connection)
{
    // header
    std::string chunk("ClientIP\tServerIP\tServerPort\tHost\tMethod\tPath\tStatus\tBrowser\tOS\tResponseTime\tReferer\tCountry\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    std::ifstream file(messyRoomPrefix + "/v2"s, std::ios::binary);
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);
    Parsed buffer;
    char *textBuffer;
    // read first record
    file.read((char *) &buffer, parsedSize);
    while (file.gcount()) {
        chunk.append(SuperCodex::humanReadableIp(std::string(buffer.sourceIp, buffer.ipLength)) + '\t').append(SuperCodex::humanReadableIp(std::string(buffer.destinationIp, buffer.ipLength)) + '\t').append(std::to_string(buffer.destinationPort) + '\t');

        // host
        if (buffer.hostLength) {
            textBuffer = new char[buffer.hostLength];
            file.read(textBuffer, buffer.hostLength);
            chunk.append(textBuffer, buffer.hostLength);
            delete[] textBuffer;
        }
        chunk.push_back('\t');

        // method
        textBuffer = new char[buffer.methodLength];
        file.read(textBuffer, buffer.methodLength);
        chunk.append(textBuffer, buffer.methodLength).push_back('\t');
        delete[] textBuffer;

        // path
        textBuffer = new char[buffer.pathLength];
        file.read(textBuffer, buffer.pathLength);
        chunk.append(textBuffer, buffer.pathLength).push_back('\t');
        delete[] textBuffer;

        // status code, browser, OS
        chunk.append(std::to_string(buffer.statusCode)).push_back('\t');
        chunk.append(browserString(buffer.browser)).push_back('\t');
        chunk.append(operatingSystemString(buffer.os)).push_back('\t');

        // response time
        if (buffer.responseAt > -1)
            chunk.append(std::to_string(buffer.responseAt - buffer.requestAt)).push_back('\t');
        else
            chunk.append("-1\t");

        // referer
        if (buffer.refererLength) {
            textBuffer = new char[buffer.refererLength];
            file.read(textBuffer, buffer.refererLength);
            chunk.append(textBuffer, buffer.refererLength).push_back('\t');
            delete[] textBuffer;
        }
        chunk.push_back('\t');

        // the very last: country
        chunk.append(buffer.country, 2).push_back('\n');

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
        file.read((char *) &buffer, parsedSize);
    }

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

void FeedRefinerHttpTracker::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    auto resultParts = SuperCodex::parallel_convert<SuperCodex::Loader *, Pack>(codices, [&](const SuperCodex::Loader *codex) -> Pack {
        Pack rawData;

        // load session data
        for (const auto &pair : codex->sessions)
            if (pair.second->detectedL7 == SuperCodex::Session::HTTP) {
                rawData.sessions.push_back(*pair.second);
                rawData.descriptions[pair.first];
            }

        // load remarks
        for (auto remarks = codex->firstRemarks(); remarks.content; remarks = codex->nextRemarks(remarks))
            if (rawData.descriptions.contains(remarks.sessionId)) {
                std::string raw(remarks.content, remarks.size);
                size_t cursor, cursorEnd, requestStart = 0, requestEnd = 0;
                auto &target = rawData.descriptions[remarks.sessionId];

                cursor = raw.find("HttpRe"s); // find begin of HTTP block
                // check whether starting block is actually HTTP response and save if it is(it could be response from orphaned request from previous codex)
                if (cursor != std::string::npos && raw.at(cursor + 6) == 's') {
                    cursorEnd = raw.find("\nHttpEnd=Re"s, cursor + 6) + 1; // find end of HTTP block
                    if (cursorEnd == std::string::npos) { // fallback recovery mechanism
                        logger.log("Failed to find HttpEnd(step 1). Falling back. Session ID: "s + std::to_string(remarks.sessionId) + '\n' + raw);
                        cursorEnd = raw.size();
                    }
                    target.responseInHead = raw.substr(cursor, cursorEnd - cursor);
                    cursor = raw.find("HttpRe"s, cursorEnd + 10);
                }

                while (cursor != std::string::npos) {
                    // determine boundary of a HTTP block(start ~ end)
                    cursorEnd = raw.find("\nHttpEnd=Re"s, cursor + 6) + 1; // find end of HTTP block
                    if (cursorEnd == std::string::npos) { // fallback recovery mechanism
                        logger.log("Failed to find HttpEnd(step 2). Falling back. Session ID: "s + std::to_string(remarks.sessionId) + '\n' + raw);
                        cursorEnd = raw.size();
                    }

                    // determine block type(request vs. response)
                    if (raw.at(cursor + 6) == 'q') { // HTTP request(HttpRequest=)
                        if (requestEnd != 0) { // request after request=no response
                            target.noResponses.push_back(raw.substr(requestStart, requestEnd - requestStart));
                        }

                        // fill recognized new request to the slice
                        requestStart = cursor;
                        requestEnd = cursorEnd;
                    } else { // HTTP response
                        if (requestEnd != 0) { // there's a request before this
                            // register new complete request-response pair
                            target.completes.push_back(raw.substr(requestStart, requestEnd - requestStart) + raw.substr(cursor, cursorEnd - cursor));

                            // clear buffer
                            requestStart = 0;
                            requestEnd = 0;
                        } // response without request is simply ignored
                    }

                    // find next HTTP block
                    cursor = raw.find("HttpRe"s, cursorEnd + 10); // find next begin of HTTP block
                }

                if (requestEnd != 0) {
                    target.requestInTail = raw.substr(requestStart, requestEnd - requestStart);
                    if (!target.noResponses.empty())
                        target.noResponses.pop_back(); // by business logic, it's already registered as no response, which should be removed
                }
            }

        return rawData;
    });

    // merge
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Pack> resultRawsFuture) {
            LogStopwatch stopwatch(&logger, "Merged"s);

            // background: update session information
            std::thread updateSessionInformationThread([&]() {
                for (const auto &resultRaw : resultRawsFuture)
                    updateTimestampAndMergeSessions(resultRaw.sessions);
            });

            // match inter-codex request-response pairs and register new orphaned requests
            std::vector<std::pair<uint64_t, std::string>> interCodexCompletes, interCodexNoResponses;
            for (const auto &resultRaw : resultRawsFuture) {
                for (auto i = resultRaw.descriptions.begin(), iEnd = resultRaw.descriptions.end(); i != iEnd; ++i) {
                    auto &sessionId = i->first;
                    auto &pack = i->second;
                    // find matching requests among responses
                    if (!pack.responseInHead.empty() && orphanedRequests->count(sessionId)) {
                        interCodexCompletes.push_back(std::make_pair(sessionId, orphanedRequests->at(sessionId) + pack.responseInHead));
                        orphanedRequests->erase(sessionId);
                    }

                    // register new orphaned request if there's one
                    if (!pack.requestInTail.empty())
                        (*orphanedRequests)[sessionId] = pack.requestInTail;
                }
            }

            // check timeout of orphaned requests
            uint32_t timeoutBase = 0;
            for (const auto &session : resultRawsFuture.back().sessions)
                if (session.last.second > timeoutBase)
                    timeoutBase = session.last.second;
            timeoutBase -= 72;
            for (auto i = orphanedRequests->begin(); i != orphanedRequests->end();) {
                // find "HttpRequest" pair
                const auto requestStart = i->second.find("HttpRequest="s);
                if (requestStart == std::string::npos) { // this must not be happened, but just in case
                    logger.log("HTTP request without HttpRequest. Session ID: "s + std::to_string(i->first));
                    i = orphanedRequests->erase(i); // silently remove dummy data
                    continue;
                }

                // try to obtain timestamp for request and check timeout(72 seconds)
                try {
                    uint32_t requestTimestamp = static_cast<uint32_t>(std::stoull(i->second.substr(requestStart + 13, 19)) / 1000000000);
                    if (requestTimestamp < timeoutBase) {
                        interCodexNoResponses.push_back(std::make_pair(i->first, i->second));
                        i = orphanedRequests->erase(i);
                        continue;
                    }
                } catch (...) { // this must not be happened either, but just in case
                    logger.log("HTTP request without HttpRequest. Session ID: "s + std::to_string(i->first));
                    i = orphanedRequests->erase(i); // silently remove data
                    continue;
                }

                // this request didn't reach the timeout
                ++i;
            }

            // prepare for dump
            std::vector<ParserPack> packs;
            packs.reserve(1000000);
            std::function<void()> flushToDisk = [&]() {
                tbb::parallel_for(tbb::blocked_range<int>(0, packs.size()), [&](tbb::blocked_range<int> r) {
                    for (int i = r.begin(); i < r.end(); ++i)
                        FeedRefinerHttpTracker::parseRemarks(packs[i]);
                });
                // write to disk
                std::ofstream file(messyRoomPrefix + "/v1"s, std::ios::binary | std::ios::app);
                std::unique_ptr<char[]> fileBuffer(new char[536870912]); // 512MB
                file.rdbuf()->pubsetbuf(fileBuffer.get(), 536870912);
                for (const auto &pack : packs)
                    if (pack.includeToResult) {
                        file.write((const char *) &pack.parsed, parsedSize);
                        if (!pack.host.empty())
                            file.write(pack.host.data(), pack.parsed.hostLength);
                        if (!pack.method.empty())
                            file.write(pack.method.data(), pack.parsed.methodLength);
                        if (!pack.path.empty())
                            file.write(pack.path.data(), pack.parsed.pathLength);
                        if (!pack.referer.empty())
                            file.write(pack.referer.data(), pack.parsed.refererLength);
                    }
                file.close();
                packs.clear();
            };
            for (const auto &item : interCodexNoResponses)
                packs.push_back(ParserPack{item.first, &item.second, &regex, true, {}, {}, {}, {}, {}});
            if (packs.size() > 500000)
                flushToDisk();
            for (const auto &item : interCodexCompletes)
                packs.push_back(ParserPack{item.first, &item.second, &regex, true, {}, {}, {}, {}, {}});
            if (packs.size() > 500000)
                flushToDisk();
            for (const auto &resultRaw : resultRawsFuture) {
                // gather data
                for (const auto &pair : resultRaw.descriptions) {
                    for (const auto &item : pair.second.noResponses)
                        packs.push_back(ParserPack{pair.first, &item, &regex, true, {}, {}, {}, {}, {}});
                    if (packs.size() > 500000)
                        flushToDisk();
                    for (const auto &item : pair.second.completes)
                        packs.push_back(ParserPack{pair.first, &item, &regex, true, {}, {}, {}, {}, {}});
                    if (packs.size() > 500000)
                        flushToDisk();
                }
                if (packs.size() > 500000)
                    flushToDisk();
            }
            // flush the remaining
            if (!packs.empty())
                flushToDisk();

            // wait for session information update to finish
            updateSessionInformationThread.join();
        },
        resultParts);
}

void FeedRefinerHttpTracker::finalize()
{
    // update parsed pack with IP pair and country code in place
    std::ifstream input(messyRoomPrefix + "/v1"s, std::ios::binary);
    std::ofstream file(messyRoomPrefix + "/v2"s, std::ios::binary);
    std::unique_ptr<char[]> fileBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(fileBuffer.get(), 536870912);
    char *textBuffer;
    Parsed buffer;
    std::string stringBuffer;
    int counter = 0;
    ankerl::unordered_dense::set<std::string> *hostname1 = new ankerl::unordered_dense::set<std::string>(),
                                              *hostname2 = new ankerl::unordered_dense::set<std::string>(); // 1: hostname from Host header, 2: hostname generated from IP+port pair wiithout hostname on the request
    ankerl::unordered_dense::map<std::string, std::vector<std::uint64_t>> *index = new ankerl::unordered_dense::map<std::string, std::vector<std::uint64_t>>();
    size_t offset = 0;

    // read first record
    input.read((char *) &buffer, parsedSize);
    while (input.gcount()) {
        ++counter;
        const SuperCodex::Session &session = sessions->at(buffer.sessionId());
        // set destination IP, IP length, and destination port
        stringBuffer = SuperCodex::destinationIp(session);
        buffer.ipLength = stringBuffer.length();
        memcpy(buffer.destinationIp, stringBuffer.data(), buffer.ipLength);
        buffer.destinationPort = session.destinationPort;

        // set source IP
        stringBuffer = SuperCodex::sourceIp(session);
        memcpy(buffer.sourceIp, stringBuffer.data(), buffer.ipLength);

        // get country code
        stringBuffer = geoLocationIpV4(stringBuffer);
        memcpy(buffer.country, stringBuffer.data(), 2);

        // write data
        // main record(header)
        file.write((const char *) &buffer, parsedSize);
        // host: it may not exist. Index is also built here(index is based on hostname)
        if (buffer.hostLength) {
            textBuffer = new char[buffer.hostLength];
            input.read(textBuffer, buffer.hostLength);
            file.write(textBuffer, buffer.hostLength);

            // register hostname and build index
            std::string name(textBuffer, buffer.hostLength);
            hostname1->insert(name);
            (*index)[hashed(name)].push_back(offset);

            // free memory
            delete[] textBuffer;
        } else {
            // prepare for hostname as IP+port
            std::string name = SuperCodex::destinationIp(session) + std::string((const char *) &session.destinationPort, 2);

            // register hostname and build index
            hostname2->insert(name); // raw string is used here to sort based on IP address and port number in hexadecimal
            (*index)[hashed(SuperCodex::humanReadableIp(name.substr(0, name.size() - 2)) + ':' + std::to_string(session.destinationPort) + "(N)"s)].push_back(offset);
        }
        // method: it must exist everywhere
        textBuffer = new char[buffer.methodLength];
        input.read(textBuffer, buffer.methodLength);
        file.write(textBuffer, buffer.methodLength);
        delete[] textBuffer;
        // path: it must exist everywhere
        textBuffer = new char[buffer.pathLength];
        input.read(textBuffer, buffer.pathLength);
        file.write(textBuffer, buffer.pathLength);
        delete[] textBuffer;
        // referer: it may not exist
        if (buffer.refererLength) {
            textBuffer = new char[buffer.refererLength];
            input.read(textBuffer, buffer.refererLength);
            file.write(textBuffer, buffer.refererLength);
            delete[] textBuffer;
        }

        // move offset and read next record
        offset += parsedSize + buffer.hostLength + buffer.methodLength + buffer.pathLength + buffer.refererLength;
        input.read((char *) &buffer, parsedSize);
    }
    file.close();

    // register services
    std::vector<std::string> hostname2Sorted;
    services.reserve(hostname1->size() + hostname2->size());
    hostname2Sorted.reserve(hostname2->size());
    // register data from Host header to services
    for (const auto &name : *hostname1)
        services.push_back(name);
    std::sort(services.begin(), services.end());
    // sort data from IP-port pairs
    for (const auto &name : *hostname2)
        hostname2Sorted.push_back(name);
    std::sort(hostname2Sorted.begin(), hostname2Sorted.end());
    // register sorted IP-port pairs to services
    for (const auto &name : hostname2Sorted) {
        uint16_t port = *(const uint16_t *) name.substr(name.size() - 2).data();
        services.push_back(SuperCodex::humanReadableIp(name.substr(0, name.size() - 2)) + ':' + std::to_string(port) + "(N)"s);
    }

    // save index
    for (const auto &pair : *index) {
        std::ofstream indexFile(messyRoomPrefix + '/' + SuperCodex::stringToHex(pair.first),
                                std::ios::binary); // key is already hashed
        indexFile.write((const char *) pair.second.data(), pair.second.size() * 8);
    }

    // free RAM and log
    delete hostname1;
    delete hostname2;
    delete index;
    input.close();
    std::filesystem::remove(messyRoomPrefix + "/v1"s);
    logger.log("Results ready to serve: "s + std::to_string(counter));
}

std::string FeedRefinerHttpTracker::browserString(const FeedRefinerHttpTracker::Browser &browser)
{
    switch (browser) {
    case BROWSER_CHROME:
        return std::string("Chrome"s);
    case BROWSER_FIREFOX:
        return std::string("Firefox"s);
    case BROWSER_EDGE:
        return std::string("Edge"s);
    case BROWSER_MSIE:
        return std::string("Internet Explorer"s);
    case BROWSER_SAFARI:
        return std::string("Safari"s);
    case BROWSER_OTHER:
        return std::string("Other"s);
    }
}

std::string FeedRefinerHttpTracker::operatingSystemString(const FeedRefinerHttpTracker::OperatingSystem &os)
{
    switch (os) {
    case OS_WIN10:
        return std::string("Windows 10"s);
    case OS_WIN81:
        return std::string("Windows 8.1"s);
    case OS_WIN8:
        return std::string("Windows 8"s);
    case OS_WIN7:
        return std::string("Windows 7"s);
    case OS_WINOTHER:
        return std::string("Windows/Other"s);
    case OS_ANDROID:
        return std::string("Android"s);
    case OS_MACOSX:
        return std::string("MAC OS X"s);
    case OS_IPHONEOS:
        return std::string("iPhone OS"s);
    case OS_IPADOS:
        return std::string("iPad OS"s);
    case OS_LINUX:
        return std::string("Linux"s);
    case OS_OTHER:
        return std::string("Other"s);
    }
}

void FeedRefinerHttpTracker::parseRemarks(ParserPack &rawData)
{
    // apply regex as needed
    if (!rawData.regex->empty()) {
        std::regex regexFilter(*rawData.regex);
        std::smatch match;
        if (!std::regex_search(*rawData.remarks, match, regexFilter)) {
            rawData.includeToResult = false;
            return;
        }
    }

    // main process start: extract data from HTTP headers
    rawData.parsed.setSessionId(rawData.sessionId);
    const std::string &remarks = *rawData.remarks;
    std::string line;
    Logger logger("ParseRemarks"s);

    // extract necessary data from request headers
    line = remarksValue(remarks, "HttpRequest"s);
    if (line.empty()) { // it must not happen, but if it happens, ignore
        logger.log("Ignoring remarks without HttpRequest. Details:\n"s + remarks);
        return;
    }

    // get request timestamp
    try {
        rawData.parsed.requestAt = std::stoll(line.substr(0, 19));
    } catch (...) {
        logger.log("Failed to convert timestamp from HTTP response."s);
        return;
    }

    // method and path
    line.erase(0, 20);
    size_t delimiter = line.find(' ');
    rawData.method = line.substr(0, delimiter);
    rawData.path = line.substr(delimiter + 1);

    // get host, user agent string, and referer
    std::string userAgent;
    if (remarks.find("Raw="s) != std::string::npos) {
        rawData.host = remarksValueHttpHeader(remarks, "Host"s);
        userAgent = remarksValueHttpHeader(remarks, "User-Agent"s);
        rawData.referer = remarksValueHttpHeader(remarks, "Referer"s);
    }

    // determine web browser
    if (userAgent.find("Chrome"s) != std::string::npos)
        rawData.parsed.browser = BROWSER_CHROME;
    else if (userAgent.find("Firefox"s) != std::string::npos)
        rawData.parsed.browser = BROWSER_FIREFOX;
    else if (userAgent.find("Edg/"s) != std::string::npos)
        rawData.parsed.browser = BROWSER_EDGE;
    else if (userAgent.find("Trident/"s) != std::string::npos || userAgent.find("MSIE"s) != std::string::npos)
        rawData.parsed.browser = BROWSER_MSIE;
    else if (userAgent.find("Safari"s) != std::string::npos)
        rawData.parsed.browser = BROWSER_SAFARI;
    else
        rawData.parsed.browser = BROWSER_OTHER;

    // determine client OS
    if (userAgent.find("Windows NT 10"s) != std::string::npos)
        rawData.parsed.os = OS_WIN10;
    else if (userAgent.find("Windows NT 6.3"s) != std::string::npos)
        rawData.parsed.os = OS_WIN81;
    else if (userAgent.find("Windows NT 6.2"s) != std::string::npos)
        rawData.parsed.os = OS_WIN8;
    else if (userAgent.find("Windows NT 6.1"s) != std::string::npos)
        rawData.parsed.os = OS_WIN7;
    else if (userAgent.find("Windows"s) != std::string::npos)
        rawData.parsed.os = OS_WINOTHER;
    else if (userAgent.find("Android"s) != std::string::npos)
        rawData.parsed.os = OS_ANDROID;
    else if (userAgent.find("Mac OS X"s) != std::string::npos)
        rawData.parsed.os = OS_MACOSX;
    else if (userAgent.find("iPhone OS"s) != std::string::npos)
        rawData.parsed.os = OS_IPHONEOS;
    else if (userAgent.find("iPad"s) != std::string::npos)
        rawData.parsed.os = OS_IPADOS;
    else if (userAgent.find("Linux"s) != std::string::npos)
        rawData.parsed.os = OS_LINUX;
    else
        rawData.parsed.os = OS_OTHER;

    // extract data from response headers
    line = remarksValue(remarks, "HttpResponse"s);
    if (!line.empty()) {
        try {
            rawData.parsed.responseAt = std::stoll(line.substr(0, 19));
            rawData.parsed.statusCode = std::stoi(line.substr(20, 3));
        } catch (...) {
            logger.log("Failed to convert numbers from HTTP response."s);
            return;
        }
    }

    // length of variable-length fields
    rawData.parsed.hostLength = rawData.host.size();
    rawData.parsed.methodLength = rawData.method.size();
    rawData.parsed.pathLength = rawData.path.size();
    rawData.parsed.refererLength = rawData.referer.size();
}

std::string FeedRefinerHttpTracker::geoLocationIpV4(const std::string &ip)
{
    if (geoLocationStoreIpV4.empty())
        return "No Data"s;

    std::string reversed(ip);
    std::reverse(reversed.begin(), reversed.end());
    uint32_t target = *(uint32_t *) reversed.data();
    int left = 0, right = geoLocationStoreIpV4.size() - 1;
    if (target < geoLocationStoreIpV4.front().ipFrom || target > geoLocationStoreIpV4.back().ipTo)
        return std::string(); // IP range is out of bound

    // using binary search
    while (right - left != 0) {
        const auto middleIndex = (left + right) / 2;
        const auto &middle = geoLocationStoreIpV4.at(middleIndex);
        if (target >= middle.ipFrom && target <= middle.ipTo)
            return middle.country;
        else if (target > middle.ipTo)
            left = middleIndex + 1;
        else
            right = middleIndex - 1;
    }
    return geoLocationStoreIpV4.at(left).country; // worst case. :P
}

std::string FeedRefinerHttpTracker::hashed(const std::string &source)
{
    uint64_t result = fnv64a(source.data(), source.size());
    return std::string((const char *) &result, 8);
}

void FeedRefinerHttpTracker::writeClientProfile(const ankerl::unordered_dense::map<std::string, std::string> &requestParameters, yyjson_mut_doc *document, const std::string &service)
{
    // prepare for JSON root object
    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);

    int countryLimit = 10, referersLimit = 10, browsersLimit = 10, osLimit = 10;

    // check parameters
    try {
        if (requestParameters.contains("countrylimit"s))
            countryLimit = std::stoi(requestParameters.at("countrylimit"s));
        if (requestParameters.contains("refererslimit"s))
            referersLimit = std::stoi(requestParameters.at("refererslimit"s));
        if (requestParameters.contains("browserslimit"s))
            browsersLimit = std::stoi(requestParameters.at("browserslimit"s));
        if (requestParameters.contains("oslimit"s))
            osLimit = std::stoi(requestParameters.at("oslimit"s));
    } catch (...) {
        yyjson_mut_obj_add_str(document, rootObject, "error", "Failed to convert limits to numbers.");
        return;
    }

    // prepare for regex filter for path
    bool applyPathFilter = (requestParameters.contains("path"s) != 0);
    std::regex regexFilter;
    std::smatch match;
    if (applyPathFilter) {
        std::regex toSwap(requestParameters.at("path"s));
        regexFilter.swap(toSwap);
    }

    // iterate file and build hashmaps
    ankerl::unordered_dense::map<std::string, int64_t> perCountry, perBrowser, perOs, topReferers;
    std::ifstream file(messyRoomPrefix + "/v2"s, std::ios::binary);
    std::unique_ptr<char[]> fileBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(fileBuffer.get(), 536870912);
    Parsed record;
    char *textBuffer;

    // read first record
    if (service == "total"s || service == "Total"s) {
        file.read((char *) &record, parsedSize);
        while (file.gcount()) {
            // check path regex as needed
            if (applyPathFilter) {
                file.seekg(record.hostLength + record.methodLength, std::ios::cur);
                textBuffer = new char[record.pathLength];
                file.read(textBuffer, record.pathLength);
                std::string path(textBuffer, record.pathLength);
                delete[] textBuffer;
                if (!std::regex_search(path, match, regexFilter)) {
                    if (record.refererLength)
                        file.seekg(record.refererLength, std::ios::cur);
                    goto readNext1;
                }
            } else
                file.seekg(record.hostLength + record.methodLength + record.pathLength, std::ios::cur);
            ++perCountry[std::string(record.country, 2)];
            ++perBrowser[browserString(record.browser)];
            ++perOs[operatingSystemString(record.os)];

            // count referers
            if (record.refererLength) {
                textBuffer = new char[record.refererLength];
                file.read(textBuffer, record.refererLength);
                ++topReferers[std::string(textBuffer, record.refererLength)];
                delete[] textBuffer;
            }
        readNext1:
            // read next record
            file.read((char *) &record, parsedSize);
        }
    } else {
        // read index: filename is fnv64a hashed service name
        std::ifstream index(messyRoomPrefix + '/' + SuperCodex::stringToHex(hashed(service)), std::ios::binary);
        uint64_t offset;
        // read first index
        index.read((char *) &offset, 8);
        while (index.gcount()) {
            // read record
            file.seekg(offset, std::ios::beg);
            file.read((char *) &record, parsedSize);

            // check path regex as needed
            if (applyPathFilter) {
                file.seekg(record.hostLength + record.methodLength, std::ios::cur);
                textBuffer = new char[record.pathLength];
                file.read(textBuffer, record.pathLength);
                std::string path(textBuffer, record.pathLength);
                delete[] textBuffer;
                if (!std::regex_search(path, match, regexFilter)) {
                    if (record.refererLength)
                        file.seekg(record.refererLength, std::ios::cur);
                    goto readNext2;
                }
            } else
                file.seekg(record.hostLength + record.methodLength + record.pathLength, std::ios::cur);

            ++perCountry[std::string(record.country, 2)];
            ++perBrowser[browserString(record.browser)];
            ++perOs[operatingSystemString(record.os)];

            // count referers
            if (record.refererLength) {
                textBuffer = new char[record.refererLength];
                file.read(textBuffer, record.refererLength);
                ++topReferers[std::string(textBuffer, record.refererLength)];
                delete[] textBuffer;
            }

        readNext2:
            // read next index
            index.read((char *) &offset, 8);
        }
    }
    file.close();

    // sort results
    std::vector<std::pair<std::string, int64_t>> perCountrySorted, perBrowserSorted, perOsSorted, topReferersSorted;
    perCountrySorted.reserve(perCountry.size());
    perBrowserSorted.reserve(perBrowser.size());
    perOsSorted.reserve(perOs.size());
    topReferersSorted.reserve(topReferers.size());
    for (const auto &pair : perCountry)
        perCountrySorted.push_back(std::make_pair(pair.first, pair.second));
    for (const auto &pair : perBrowser)
        perBrowserSorted.push_back(std::make_pair(pair.first, pair.second));
    for (const auto &pair : perOs)
        perOsSorted.push_back(std::make_pair(pair.first, pair.second));
    for (const auto &pair : topReferers)
        topReferersSorted.push_back(std::make_pair(pair.first, pair.second));
    std::sort(perCountrySorted.begin(), perCountrySorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) { return a.second > b.second; });
    std::sort(perBrowserSorted.begin(), perBrowserSorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) { return a.second > b.second; });
    std::sort(perOsSorted.begin(), perOsSorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) { return a.second > b.second; });
    std::sort(topReferersSorted.begin(), topReferersSorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) { return a.second > b.second; });

    // client per country
    yyjson_mut_val *clientsPerCountryArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "clientspercountry", clientsPerCountryArray);
    for (int i = 0, iEnd = std::min(countryLimit, static_cast<int>(perCountrySorted.size())); i < iEnd; ++i) {
        const auto &pair = perCountrySorted.at(i);
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(clientsPerCountryArray, object);
        yyjson_mut_obj_add_strncpy(document, object, "country", pair.first.data(), pair.first.size());
        yyjson_mut_obj_add_int(document, object, "hits", pair.second);
    }

    // client web browsers
    yyjson_mut_val *clientWebBrowsersArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "clientwebbrowsers", clientWebBrowsersArray);
    for (int i = 0, iEnd = std::min(browsersLimit, static_cast<int>(perBrowserSorted.size())); i < iEnd; ++i) {
        const auto &pair = perBrowserSorted.at(i);
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(clientWebBrowsersArray, object);
        yyjson_mut_obj_add_strncpy(document, object, "browser", pair.first.data(), pair.first.size());
        yyjson_mut_obj_add_int(document, object, "hits", pair.second);
    }

    // client operating systems
    yyjson_mut_val *clientOsArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "clientos", clientOsArray);
    for (int i = 0, iEnd = std::min(osLimit, static_cast<int>(perOsSorted.size())); i < iEnd; ++i) {
        const auto &pair = perOsSorted.at(i);
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(clientOsArray, object);
        yyjson_mut_obj_add_strncpy(document, object, "os", pair.first.data(), pair.first.size());
        yyjson_mut_obj_add_int(document, object, "hits", pair.second);
    }

    // top referers
    yyjson_mut_val *topRefersArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "toprefers", topRefersArray);
    for (int i = 0, iEnd = std::min(referersLimit, static_cast<int>(topReferersSorted.size())); i < iEnd; ++i) {
        const auto &pair = topReferersSorted.at(i);
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(topRefersArray, object);
        yyjson_mut_obj_add_strncpy(document, object, "referer", pair.first.data(), pair.first.size());
        yyjson_mut_obj_add_int(document, object, "hits", pair.second);
    }
}

void FeedRefinerHttpTracker::writePerformance(const ankerl::unordered_dense::map<std::string, std::string> &requestParameters, yyjson_mut_doc *document, const std::string &service, const int32_t bindValue)
{
    // prepare for JSON root object
    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);

    int resourcesLimit = 10;
    int32_t adjustedBind = (bindValue == 0 ? 1 : bindValue);

    // check parameters
    try {
        if (requestParameters.contains("resourceslimit"s))
            resourcesLimit = std::stoi(requestParameters.at("resourceslimit"s));
    } catch (...) {
        yyjson_mut_obj_add_str(document, rootObject, "error", "Failed to convert limits to numbers.");
        return;
    }

    // prepare for data structures and containers
    struct PerformancePerResource
    {
        std::string method, path;
        int64_t requests = 0, responses = 0, totalReqToRes = 0, noResponses = 0, http4xx = 0, http5xx = 0;
    };
    ankerl::unordered_dense::map<std::string, PerformancePerResource> performances; // <method + '\t' + path> + performance
    ankerl::unordered_dense::map<int32_t, int64_t> requestsPerSecond; // second-level timestamp+number of requests

    // prepare for regex filter
    bool applyPathFilter = requestParameters.contains("path"s);
    std::regex regexFilter;
    std::smatch match;
    if (applyPathFilter) {
        std::regex toSwap(requestParameters.at("path"s));
        regexFilter.swap(toSwap);
    }

    // iterate file and build hashmaps
    std::ifstream file(messyRoomPrefix + "/v2"s, std::ios::binary);
    std::unique_ptr<char[]> fileBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(fileBuffer.get(), 536870912);
    Parsed record;
    char *textBuffer;

    // read first record
    file.read((char *) &record, parsedSize);
    if (service == "total"s || service == "Total"s) {
        while (file.gcount()) {
            // read method and path
            file.seekg(record.hostLength, std::ios::cur); // skip host
            textBuffer = new char[record.methodLength];
            file.read(textBuffer, record.methodLength);
            std::string methodFromRecord(textBuffer, record.methodLength);
            delete[] textBuffer;
            textBuffer = new char[record.pathLength];
            file.read(textBuffer, record.pathLength);
            std::string pathFromRecord(textBuffer, record.pathLength);
            delete[] textBuffer;

            // move file stream cursor to end of record in advance
            file.seekg(record.refererLength, std::ios::cur);

            // check path aginst regex as needed
            if (!applyPathFilter || std::regex_search(pathFromRecord, match, regexFilter)) {
                // gather performance data
                auto &targetPerformanceItem = performances[methodFromRecord + '\t' + pathFromRecord];
                ++targetPerformanceItem.requests;
                if (record.responseAt > -1) {
                    ++targetPerformanceItem.responses;
                    targetPerformanceItem.totalReqToRes += (record.responseAt - record.requestAt);
                } else
                    ++targetPerformanceItem.noResponses;
                if (record.statusCode >= 500)
                    ++targetPerformanceItem.http5xx;
                else if (record.statusCode >= 400)
                    ++targetPerformanceItem.http4xx;

                // count requests per second
                ++requestsPerSecond[record.requestAt / 1000000000];
            }

            // read next record
            file.read((char *) &record, parsedSize);
        }
    } else {
        // read index: filename is fnv64a hashed service name
        std::ifstream index(messyRoomPrefix + '/' + SuperCodex::stringToHex(hashed(service)), std::ios::binary);
        uint64_t offset;
        // read first index
        index.read((char *) &offset, 8);
        while (index.gcount()) {
            // read record
            file.seekg(offset, std::ios::beg);
            file.read((char *) &record, parsedSize);

            // read method and path
            file.seekg(record.hostLength, std::ios::cur); // skip host
            textBuffer = new char[record.methodLength];
            file.read(textBuffer, record.methodLength);
            std::string methodFromRecord(textBuffer, record.methodLength);
            delete[] textBuffer;
            textBuffer = new char[record.pathLength];
            file.read(textBuffer, record.pathLength);
            std::string pathFromRecord(textBuffer, record.pathLength);
            delete[] textBuffer;

            // move file stream cursor to end of record in advance
            file.seekg(record.refererLength, std::ios::cur);

            // check path aginst regex as needed
            if (!applyPathFilter || std::regex_search(pathFromRecord, match, regexFilter)) {
                // gather performance data
                auto &target = performances[methodFromRecord + '\t' + pathFromRecord];
                ++target.requests;
                if (record.responseAt > -1) {
                    ++target.responses;
                    target.totalReqToRes += (record.responseAt - record.requestAt);
                } else
                    ++target.noResponses;
                if (record.statusCode >= 500)
                    ++target.http5xx;
                else if (record.statusCode >= 400)
                    ++target.http4xx;

                // count requests per second
                ++requestsPerSecond[record.requestAt / 1000000000];
            }

            // read next index
            index.read((char *) &offset, 8);
        }
    }
    file.close();

    // sort performance data by number of requests in descending order
    std::vector<std::pair<std::string, PerformancePerResource>> performancesSorted;
    performancesSorted.reserve(performances.size());
    for (const auto &pair : performances)
        performancesSorted.push_back(std::make_pair(pair.first, pair.second));
    std::sort(performancesSorted.begin(), performancesSorted.end(), [](const std::pair<std::string, PerformancePerResource> &a, const std::pair<std::string, PerformancePerResource> &b) { return a.second.requests > b.second.requests; });
    if (performancesSorted.size() > resourcesLimit)
        performancesSorted.resize(resourcesLimit);

    // build requests per second with binding in order
    struct BindPack
    {
        uint32_t timestamp;
        int64_t containers, total, top;
    };
    std::vector<BindPack> bindPacks;
    uint32_t currentTimestamp = secondStart, nextTimestamp = currentTimestamp + adjustedBind;
    BindPack bindPack{currentTimestamp, adjustedBind, 0, 0};
    for (int i = secondStart, iEnd = secondEnd; i <= iEnd; ++i) {
        if (i >= nextTimestamp) {
            // add bind pack
            bindPacks.push_back(bindPack);

            // reset bind pack for reuse
            bindPack.timestamp = nextTimestamp;
            bindPack.containers = adjustedBind;
            bindPack.top = 0;
            bindPack.total = 0;

            // move next timestamp
            nextTimestamp += adjustedBind;
        }

        // build data
        if (requestsPerSecond.contains(i)) {
            const auto target = requestsPerSecond.at(i);
            bindPack.total += target;
            if (target > bindPack.total)
                bindPack.total = target;
        }
    }
    // add final bind pack
    bindPack.containers -= nextTimestamp - secondEnd;
    bindPacks.push_back(bindPack);

    // performances per resource
    yyjson_mut_val *performanceArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "performance", performanceArray);
    for (const auto &pair : performancesSorted) {
        // prepare for variables
        const auto &item = pair.second;
        const size_t splitterIndex = pair.first.find('\t');
        std::string methodSplitted = pair.first.substr(0, splitterIndex), pathSplitted = pair.first.substr(splitterIndex + 1);

        // write JSON object
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(performanceArray, object);
        yyjson_mut_obj_add_strncpy(document, object, "method", methodSplitted.data(), methodSplitted.size());
        yyjson_mut_obj_add_strncpy(document, object, "path", pathSplitted.data(), pathSplitted.size());
        yyjson_mut_obj_add_int(document, object, "requests", item.requests);
        yyjson_mut_obj_add_int(document, object, "responses", item.responses);
        if (item.responses)
            yyjson_mut_obj_add_int(document, object, "meanreqtores", item.totalReqToRes / item.responses);
        else
            yyjson_mut_obj_add_int(document, object, "meanreqtores", 0);
        yyjson_mut_obj_add_int(document, object, "noresponses", item.noResponses);
        yyjson_mut_obj_add_int(document, object, "clienterrors", item.http4xx);
        yyjson_mut_obj_add_int(document, object, "servererrors", item.http5xx);
    }

    // requests per second
    yyjson_mut_val *requestsArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "requests", requestsArray);
    for (const auto &item : bindPacks) {
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(requestsArray, object);
        yyjson_mut_obj_add_int(document, object, "timestamp", item.timestamp);
        yyjson_mut_obj_add_int(document, object, "containers", item.containers);
        yyjson_mut_obj_add_int(document, object, "total", item.total);
        yyjson_mut_obj_add_int(document, object, "top", item.top);
    }
}

void FeedRefinerHttpTracker::writeErrorDetails(const ankerl::unordered_dense::map<std::string, std::string> &requestParameters, yyjson_mut_doc *document, const std::string &service, const std::string &path)
{
    // prepare for raw containers
    ankerl::unordered_dense::map<int16_t, int64_t> errorCounts; // individual status code(>=400) and count for each

    // prepare for regex filter
    bool applyPathFilter = !path.empty();
    std::regex regexFilter;
    std::smatch match;
    if (applyPathFilter) {
        std::regex toSwap(path);
        regexFilter.swap(toSwap);
    }

    // iterate file and build hashmaps
    std::ifstream file(messyRoomPrefix + "/v2"s, std::ios::binary);
    std::unique_ptr<char[]> fileBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(fileBuffer.get(), 536870912);
    Parsed record;
    char *textBuffer;

    // read first record
    file.read((char *) &record, parsedSize);
    if (service == "total"s || service == "Total"s) {
        while (file.gcount()) {
            // read path
            file.seekg(record.hostLength + record.methodLength,
                       std::ios::cur); // skip host and length
            textBuffer = new char[record.pathLength];
            file.read(textBuffer, record.pathLength);
            std::string pathFromRecord(textBuffer, record.pathLength);
            delete[] textBuffer;

            if (!applyPathFilter || std::regex_search(pathFromRecord, match, regexFilter)) {
                // move file stream cursor to end of record in advance
                file.seekg(record.refererLength, std::ios::cur);

                // check path aginst regex as needed
                if (std::regex_search(pathFromRecord, match, regexFilter))
                    if (record.statusCode >= 400)
                        ++errorCounts[record.statusCode];
            }

            // read next record
            file.read((char *) &record, parsedSize);
        }
    } else {
        // read index: filename is fnv64a hashed service name
        std::ifstream index(messyRoomPrefix + '/' + SuperCodex::stringToHex(hashed(service)), std::ios::binary);
        uint64_t offset;
        // read first index
        index.read((char *) &offset, 8);
        while (index.gcount()) {
            // read record
            file.seekg(offset, std::ios::beg);
            file.read((char *) &record, parsedSize);

            // read path
            file.seekg(record.hostLength + record.methodLength,
                       std::ios::cur); // skip host and length
            textBuffer = new char[record.pathLength];
            file.read(textBuffer, record.pathLength);
            std::string pathFromRecord(textBuffer, record.pathLength);
            delete[] textBuffer;

            if (!applyPathFilter || std::regex_search(pathFromRecord, match, regexFilter)) {
                // move file stream cursor to end of record in advance
                file.seekg(record.refererLength, std::ios::cur);

                // check path aginst regex as needed
                if (std::regex_search(pathFromRecord, match, regexFilter))
                    if (record.statusCode >= 400)
                        ++errorCounts[record.statusCode];
            }

            // read next index
            index.read((char *) &offset, 8);
        }
    }
    file.close();

    // sort results
    std::vector<std::pair<int16_t, int64_t>> errorCountsSorted;
    errorCountsSorted.reserve(errorCounts.size());
    for (const auto &pair : errorCounts)
        errorCountsSorted.push_back(std::make_pair(pair.first, pair.second));
    std::sort(errorCountsSorted.begin(), errorCountsSorted.end(), [](const std::pair<int16_t, int64_t> &a, const std::pair<int16_t, int64_t> &b) { return a.first < b.first; });

    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);
    yyjson_mut_val *errorsArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "clienterrors", errorsArray);

    for (const auto &pair : errorCountsSorted) {
        if (pair.first >= 500) { // HTTP status code 500 or higher: server errors
            errorsArray = yyjson_mut_arr(document);
            yyjson_mut_obj_add_val(document, rootObject, "servererrors", errorsArray);
        }
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(errorsArray, object);
        yyjson_mut_obj_add_int(document, object, "status", pair.first);
        yyjson_mut_obj_add_int(document, object, "hits", pair.second);
    }
}

FeedRefinerSmtpTracker::FeedRefinerSmtpTracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerSmtpTracker"s);

    // initialize session store
    sessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();
}

void FeedRefinerSmtpTracker::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // prepare for variables and objects
    std::string temp;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    std::string server, sender;
    int sendersLimit = 20, recipientsLimit = 20;

    // check parameters
    if (parameters.contains("server"s))
        server = parameters.at("server"s);
    if (parameters.contains("sender"s))
        sender = parameters.at("sender"s);
    try {
        if (parameters.contains("senderslimit"s))
            sendersLimit = std::stoi(parameters.at("senderslimit"s));
        if (parameters.contains("recipientslimit"s))
            recipientsLimit = std::stoi(parameters.at("recipientslimit"s));
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to convert limits to numbers.");
        return;
    }

    if (server.empty()) { // send server list
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);
        for (const auto &ip : servers) {
            temp = SuperCodex::stringToHex(ip);
            yyjson_mut_arr_add_strncpy(document, rootArray, temp.data(), temp.size());
        }
    } else { // send detailed description
        // read parsed records
        std::ifstream file(messyRoomPrefix + "/merged"s, std::ios::binary);
        ankerl::unordered_dense::map<std::string, int64_t> busiestSenders, busiestRecipients, errorsEncountered;
        Record header;
        char *textBuffer;
        if (server == "total"s) { // read all the records to build the ranking
            // read first record
            file.read((char *) &header, recordSize);
            while (file.gcount()) {
                // check sender and determine whether to continue
                bool continueProcess = false;
                if (header.senderLength) {
                    textBuffer = new char[header.senderLength];
                    file.read(textBuffer, header.senderLength);
                    std::string senderRead(textBuffer, header.senderLength);
                    if (sender.empty() || sender == senderRead) {
                        busiestSenders[senderRead] += header.bytesTransferred;
                        continueProcess = true;
                    } else
                        continueProcess = false;
                    delete[] textBuffer;
                }
                if (continueProcess) {
                    if (header.recipientsLength) {
                        textBuffer = new char[header.recipientsLength];
                        file.read(textBuffer, header.recipientsLength);
                        std::string recipients(textBuffer, header.recipientsLength);
                        std::stringstream lineReader(recipients);
                        for (std::string line; std::getline(lineReader, line, ' ');)
                            busiestRecipients[line] += header.bytesTransferred;
                        delete[] textBuffer;
                    }
                    if (header.errorsLength) {
                        textBuffer = new char[header.errorsLength];
                        file.read(textBuffer, header.errorsLength);
                        std::string errors(textBuffer, header.errorsLength);
                        std::stringstream lineReader(errors);
                        for (std::string line; std::getline(lineReader, line, ' ');)
                            ++errorsEncountered[line];
                        delete[] textBuffer;
                    }
                } else
                    file.seekg(header.recipientsLength + header.errorsLength, std::ios::cur);

                // read next record
                file.read((char *) &header, recordSize);
            }
        } else {
            std::ifstream index(messyRoomPrefix + '/' + server, std::ios::binary);
            int64_t offset;
            // read first offset
            index.read((char *) &offset, 8);
            while (index.gcount()) {
                // adjust file cursor and read header
                file.seekg(offset, std::ios::beg);
                file.read((char *) &header, recordSize);

                // check sender and determine whether to continue
                bool continueProcess = false;
                if (header.senderLength) {
                    textBuffer = new char[header.senderLength];
                    file.read(textBuffer, header.senderLength);
                    std::string senderRead(textBuffer, header.senderLength);
                    if (sender.empty() || sender == senderRead) {
                        busiestSenders[senderRead] += header.bytesTransferred;
                        continueProcess = true;
                    } else
                        continueProcess = false;
                    delete[] textBuffer;
                }
                if (continueProcess) {
                    if (header.recipientsLength) {
                        textBuffer = new char[header.recipientsLength];
                        file.read(textBuffer, header.recipientsLength);
                        std::string recipients(textBuffer, header.recipientsLength);
                        std::stringstream lineReader(recipients);
                        for (std::string line; std::getline(lineReader, line, ' ');)
                            busiestRecipients[line] += header.bytesTransferred;
                        delete[] textBuffer;
                    }
                    if (header.errorsLength) {
                        textBuffer = new char[header.errorsLength];
                        file.read(textBuffer, header.errorsLength);
                        std::string errors(textBuffer, header.errorsLength);
                        std::stringstream lineReader(errors);
                        for (std::string line; std::getline(lineReader, line, ' ');)
                            ++errorsEncountered[line];
                        delete[] textBuffer;
                    }
                }

                // read next offset
                index.read((char *) &offset, 8);
            }
        }

        // build ranking
        std::vector<std::pair<std::string, int64_t>> busiestSendersSorted, busiestRecipientsSorted, errorsEncounteredSorted;
        for (const auto &pair : busiestSenders)
            busiestSendersSorted.push_back(std::make_pair(pair.first, pair.second));
        for (const auto &pair : busiestRecipients)
            busiestRecipientsSorted.push_back(std::make_pair(pair.first, pair.second));
        for (const auto &pair : errorsEncountered)
            errorsEncounteredSorted.push_back(std::make_pair(pair.first, pair.second));
        std::sort(busiestSendersSorted.begin(), busiestSendersSorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) { return a.second > b.second; });
        std::sort(busiestRecipientsSorted.begin(), busiestRecipientsSorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) { return a.second > b.second; });
        std::sort(errorsEncounteredSorted.begin(), errorsEncounteredSorted.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) { return a.second > b.second; });

        // prepare for JSON root object
        yyjson_mut_val *rootObject = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootObject);

        // busiest senders
        yyjson_mut_val *busiestSendersArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "busiestsenders", busiestSendersArray);
        for (int i = 0, iEnd = std::min(sendersLimit, static_cast<int>(busiestSendersSorted.size())); i < iEnd; ++i) {
            const auto &pair = busiestSendersSorted.at(i);
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(busiestSendersArray, object);
            yyjson_mut_obj_add_strncpy(document, object, "sender", pair.first.data(), pair.first.size());
            yyjson_mut_obj_add_int(document, object, "bytestransferred", pair.second);
        }

        // busiest recipients
        yyjson_mut_val *busiestRecipientsArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "busiestrecipients", busiestRecipientsArray);
        for (int i = 0, iEnd = std::min(recipientsLimit, static_cast<int>(busiestRecipientsSorted.size())); i < iEnd; ++i) {
            const auto &pair = busiestRecipientsSorted.at(i);
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(busiestRecipientsArray, object);
            yyjson_mut_obj_add_strncpy(document, object, "recipient", pair.first.data(), pair.first.size());
            yyjson_mut_obj_add_int(document, object, "bytestransferred", pair.second);
        }

        // errors encountered
        yyjson_mut_val *errorsEncounteredArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "errorsencountered", errorsEncounteredArray);
        for (int i = 0, iEnd = errorsEncounteredSorted.size(); i < iEnd; ++i) {
            const auto &pair = errorsEncounteredSorted.at(i);
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(errorsEncounteredArray, object);
            yyjson_mut_obj_add_strncpy(document, object, "message", pair.first.data(), pair.first.size());
            yyjson_mut_obj_add_int(document, object, "hits", pair.second);
        }
    }

    Civet7::respond200(connection, document);
}

void FeedRefinerSmtpTracker::dumpResults(mg_connection *connection)
{
    // header for server-recipient pairs
    std::string chunk("ServerIP\tSender\tRecipients\tBytesTransferred\tErrors\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    std::ifstream file(messyRoomPrefix + "/merged"s, std::ios::binary);
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);
    Record header;
    char *textBuffer;
    std::string sender, recipients, errors;
    // read first record
    file.read((char *) &header, recordSize);
    while (file.gcount()) {
        // read additional records
        if (header.senderLength) {
            textBuffer = new char[header.senderLength];
            file.read(textBuffer, header.senderLength);
            sender = std::string(textBuffer, header.senderLength);
            delete[] textBuffer;
        } else
            sender.clear();
        if (header.recipientsLength) {
            textBuffer = new char[header.recipientsLength];
            file.read(textBuffer, header.recipientsLength);
            recipients = std::string(textBuffer, header.recipientsLength);
            delete[] textBuffer;
        } else
            recipients.clear();
        if (header.errorsLength) {
            textBuffer = new char[header.errorsLength];
            file.read(textBuffer, header.errorsLength);
            errors = std::string(textBuffer, header.errorsLength);
            delete[] textBuffer;
        } else
            errors.clear();

        // push data
        chunk.append(SuperCodex::humanReadableIp(std::string(header.destinationIp, header.ipLength)) + '\t').append(sender + '\t').append(recipients + '\t').append(std::to_string(header.bytesTransferred) + '\t').append(errors).push_back('\n');

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
        file.read((char *) &header, recordSize);
    }

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

void FeedRefinerSmtpTracker::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    auto resultParts = SuperCodex::parallel_convert<SuperCodex::Loader *, Pack>(codices, [&](const SuperCodex::Loader *codex) -> Pack {
        Pack rawData;

        // load session data
        for (const auto &pair : codex->sessions)
            if (pair.second->detectedL7 == SuperCodex::Session::SMTP) {
                rawData.sessions.push_back(*pair.second);
                rawData.descriptions[pair.first];
            }

        // load statistics
        for (auto bps = codex->firstBpsPerSession(); bps; bps = codex->nextBpsPerSession(bps))
            if (rawData.descriptions.contains(bps->sessionId))
                rawData.descriptions[bps->sessionId].bytesTransferred += bps->fromSmallToBig + bps->fromBigToSmall;

        // load remarks
        for (auto remarks = codex->firstRemarks(); remarks.content; remarks = codex->nextRemarks(remarks))
            if (rawData.descriptions.contains(remarks.sessionId)) {
                std::stringstream lineReader(std::string(remarks.content, remarks.size));
                // parse remarks line by line
                for (std::string line; std::getline(lineReader, line);) {
                    if (line.find("SmtpMailFrom="s) == 0)
                        rawData.descriptions[remarks.sessionId].sender = line.substr(13);
                    else if (line.find("SmtpRcptTo="s) == 0)
                        rawData.descriptions[remarks.sessionId].recipients.append(line.substr(11)).push_back(' ');
                    else if (line.find("SmtpError="s) == 0)
                        rawData.descriptions[remarks.sessionId].errors.append(line.substr(10)).push_back(' ');
                }
            }

        return rawData;
    });

    // merge
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Pack> resultRawsFuture) {
            // background: update session information
            std::thread sessionUpdateThread([&]() {
                for (const auto &resultRaw : resultRawsFuture)
                    updateTimestampAndMergeSessions(resultRaw.sessions);
            });

            // save records
            std::ofstream file(messyRoomPrefix + "/dispersed"s, std::ios::binary | std::ios::app);
            Record record;
            for (const auto &resultRaw : resultRawsFuture)
                for (const auto &pair : resultRaw.descriptions) {
                    record.setSessionId(pair.first);
                    record.bytesTransferred = pair.second.bytesTransferred;
                    record.senderLength = pair.second.sender.size();
                    record.recipientsLength = pair.second.recipients.size();
                    record.errorsLength = pair.second.errors.size();
                    file.write((const char *) &record, recordSize);
                    if (record.senderLength)
                        file.write(pair.second.sender.data(), record.senderLength);
                    if (record.recipientsLength)
                        file.write(pair.second.recipients.data(), record.recipientsLength);
                    if (record.errorsLength)
                        file.write(pair.second.errors.data(), record.errorsLength);
                }

            // wait for session organizer to finish its job
            sessionUpdateThread.join();
        },
        resultParts);
}

void FeedRefinerSmtpTracker::finalize()
{
    // open raw data
    std::ifstream input(messyRoomPrefix + "/dispersed"s, std::ios::binary);

    // check sessions residing across codices
    Record readBuffer;
    int64_t offset = 0;
    ankerl::unordered_dense::map<uint64_t, std::vector<int64_t>> codexSegments;
    // read first record
    input.read((char *) &readBuffer, recordSize);
    while (input.gcount()) {
        codexSegments[readBuffer.sessionId()].push_back(offset);
        offset += recordSize + readBuffer.senderLength + readBuffer.recipientsLength + readBuffer.errorsLength;
        input.seekg(readBuffer.senderLength + readBuffer.recipientsLength + readBuffer.errorsLength, std::ios::cur);

        // read next record
        input.read((char *) &readBuffer, recordSize);
    }

    // reset some stuff to reuse
    offset = 0;
    input.close();
    input.open(messyRoomPrefix + "/dispersed"s, std::ios::binary);

    // prepare to write merged result
    std::ofstream file(messyRoomPrefix + "/merged"s, std::ios::binary);
    ankerl::unordered_dense::map<std::string, std::vector<uint64_t>> index;
    std::string sender, recipients, errors, destinationIp;
    int64_t bytesTransferred;
    char *textBuffer;
    Record writeBuffer;

    // merge and write result
    for (const auto &pair : codexSegments) {
        // initialize buffers
        sender.clear();
        recipients.clear();
        errors.clear();
        bytesTransferred = 0;

        // merge per session data segments to one
        for (const auto &perSessionOffset : pair.second) {
            input.seekg(perSessionOffset, std::ios::beg);
            input.read((char *) &readBuffer, recordSize);
            // read additional records
            if (readBuffer.senderLength) {
                textBuffer = new char[readBuffer.senderLength];
                input.read(textBuffer, readBuffer.senderLength);
                sender = std::string(textBuffer, readBuffer.senderLength);
                delete[] textBuffer;
            }
            if (readBuffer.recipientsLength) {
                textBuffer = new char[readBuffer.recipientsLength];
                input.read(textBuffer, readBuffer.recipientsLength);
                recipients.append(textBuffer, readBuffer.recipientsLength);
                delete[] textBuffer;
            }
            if (readBuffer.errorsLength) {
                textBuffer = new char[readBuffer.errorsLength];
                input.read(textBuffer, readBuffer.errorsLength);
                errors.append(textBuffer, readBuffer.errorsLength);
                delete[] textBuffer;
            }
            bytesTransferred += readBuffer.bytesTransferred; // accumulate bytes transferred
        }
        if (sender.empty())
            sender = SuperCodex::humanReadableIp(SuperCodex::sourceIp(sessions->at(readBuffer.sessionId()))); // if sender information is empty, fill with client IP

        // write merged record
        destinationIp = SuperCodex::destinationIp(sessions->at(readBuffer.sessionId()));
        writeBuffer.ipLength = destinationIp.size();
        memcpy(writeBuffer.destinationIp, destinationIp.data(), writeBuffer.ipLength);
        writeBuffer.bytesTransferred = bytesTransferred;
        writeBuffer.senderLength = sender.size();
        writeBuffer.recipientsLength = recipients.size();
        writeBuffer.errorsLength = errors.size();

        // write to the file
        file.write((const char *) &writeBuffer, recordSize);
        if (writeBuffer.senderLength)
            file.write(sender.data(), writeBuffer.senderLength);
        if (writeBuffer.recipientsLength)
            file.write(recipients.data(), writeBuffer.recipientsLength);
        if (writeBuffer.errorsLength)
            file.write(errors.data(), writeBuffer.errorsLength);

        // build index and move offset
        index[destinationIp].push_back(offset);
        offset += recordSize + writeBuffer.senderLength + writeBuffer.recipientsLength + writeBuffer.errorsLength;
    }

    // save per-server record index and server list
    servers.reserve(index.size());
    for (const auto &pair : index) {
        std::ofstream indexFile(messyRoomPrefix + '/' + SuperCodex::stringToHex(pair.first), std::ios::binary);
        indexFile.write((const char *) pair.second.data(), pair.second.size() * 8);
        servers.push_back(pair.first);
    }
    std::sort(servers.begin(), servers.end());

    // log
    input.close();
    std::filesystem::remove(messyRoomPrefix + "/dispersed"s);
    logger.log("Results ready to serve: "s + std::to_string(codexSegments.size()));
}

FeedRefinerFtpTracker::FeedRefinerFtpTracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerFtpTracker"s);

    // initialize session store
    sessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();
}

void FeedRefinerFtpTracker::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // prepare for variables and objects
    std::string temp;
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    std::string client, server;
    int busiestLimit = 20;

    // check parameters
    if (parameters.contains("server"s))
        server = parameters.at("server"s);
    if (parameters.contains("client"s))
        client = SuperCodex::stringFromHex(parameters.at("client"s));
    try {
        if (parameters.contains("busiestlimit"s))
            busiestLimit = std::stoi(parameters.at("busiestlimit"s));
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to convert limits to numbers.");
        return;
    }

    if (server.empty()) { // send server list
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);
        for (const std::string &ip : servers) {
            temp = SuperCodex::stringToHex(ip);
            yyjson_mut_arr_add_strncpy(document, rootArray, temp.data(), temp.size());
        }
    } else if (client.empty()) { // only server is selected: show ranking
        std::ifstream file(messyRoomPrefix + "/merged"s, std::ios::binary);
        Record record;
        ankerl::unordered_dense::map<std::string, std::pair<int64_t, int64_t>> busiestClients;
        if (server == "total"s) { // read all the records one by one
            // read first record
            file.read((char *) &record, recordSize);
            while (file.gcount()) {
                busiestClients[std::string(record.sourceIp, record.ipLength)].first += record.fromClientToServer;
                busiestClients[std::string(record.sourceIp, record.ipLength)].second += record.fromServerToClient;

                // read next record
                file.seekg(record.storedLength + record.retrievedLength + record.deletedLength + record.errorsLength, std::ios::cur);
                file.read((char *) &record, recordSize);
            }
        } else { // refer to by index
            std::ifstream index(messyRoomPrefix + '/' + server, std::ios::binary);
            int64_t offset;
            // read first index
            index.read((char *) &offset, 8);
            while (index.gcount()) {
                // seek and read the record
                file.seekg(offset, std::ios::beg);
                file.read((char *) &record, recordSize);

                // update statistics
                busiestClients[std::string(record.sourceIp, record.ipLength)].first += record.fromClientToServer;
                busiestClients[std::string(record.sourceIp, record.ipLength)].second += record.fromServerToClient;

                // read next index
                index.read((char *) &offset, 8);
            }
        }
        // sort and build ranking
        struct RankingRecord
        {
            std::string ip;
            int64_t fromClientToServer, fromServerToClient;
        };
        std::vector<RankingRecord> busiestClientsSorted;
        busiestClientsSorted.reserve(busiestClients.size());
        for (const auto &pair : busiestClients)
            busiestClientsSorted.push_back(RankingRecord{pair.first, pair.second.first, pair.second.second});

        // prepare for JSON root object
        yyjson_mut_val *rootObject = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootObject);

        yyjson_mut_val *busiestClientsArray = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, rootObject, "busiestclients", busiestClientsArray);
        for (int i = 0, iEnd = std::min(busiestLimit, static_cast<int>(busiestClientsSorted.size())); i < iEnd; ++i) {
            const auto &client = busiestClientsSorted.at(i);
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_append(busiestClientsArray, object);

            temp = SuperCodex::stringToHex(client.ip);
            yyjson_mut_obj_add_strncpy(document, object, "ip", temp.data(), temp.size());
            yyjson_mut_obj_add_int(document, object, "clienttoserver", client.fromClientToServer);
            yyjson_mut_obj_add_int(document, object, "servertoclient", client.fromServerToClient);
        }
    } else { // client is set: show error details
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);

        // get individual errors
        std::ifstream file(messyRoomPrefix + "/merged"s, std::ios::binary);
        Record record;
        if (server == "total"s) { // read all the records one by one
            char *textBuffer;

            // read first record
            file.read((char *) &record, recordSize);

            // build JSON on the fly
            while (file.gcount()) {
                if (client == std::string(record.sourceIp, record.ipLength)) {
                    yyjson_mut_val *object = yyjson_mut_obj(document);
                    yyjson_mut_arr_append(rootArray, object);

                    yyjson_mut_obj_add_int(document, object, "from", record.first);
                    yyjson_mut_obj_add_int(document, object, "to", record.last);

                    yyjson_mut_val *storedArray = yyjson_mut_arr(document);
                    yyjson_mut_obj_add_val(document, object, "stored", storedArray);
                    if (record.storedLength) {
                        textBuffer = new char[record.storedLength];
                        file.read(textBuffer, record.storedLength);
                        lineToArray(document, storedArray, std::string(textBuffer, record.storedLength));
                        delete[] textBuffer;
                    }

                    yyjson_mut_val *retrievedArray = yyjson_mut_arr(document);
                    yyjson_mut_obj_add_val(document, object, "retrieved", retrievedArray);
                    if (record.retrievedLength) {
                        textBuffer = new char[record.retrievedLength];
                        file.read(textBuffer, record.retrievedLength);
                        lineToArray(document, storedArray, std::string(textBuffer, record.retrievedLength));
                        delete[] textBuffer;
                    }

                    yyjson_mut_val *deletedArray = yyjson_mut_arr(document);
                    yyjson_mut_obj_add_val(document, object, "deleted", deletedArray);
                    if (record.deletedLength) {
                        textBuffer = new char[record.deletedLength];
                        file.read(textBuffer, record.deletedLength);
                        lineToArray(document, deletedArray, std::string(textBuffer, record.deletedLength));
                        delete[] textBuffer;
                    }

                    yyjson_mut_val *errorsArray = yyjson_mut_arr(document);
                    yyjson_mut_obj_add_val(document, object, "errors", errorsArray);
                    if (record.errorsLength) {
                        textBuffer = new char[record.errorsLength];
                        file.read(textBuffer, record.errorsLength);
                        lineToArray(document, errorsArray, std::string(textBuffer, record.errorsLength));
                        delete[] textBuffer;
                    }
                } else
                    file.seekg(record.storedLength + record.retrievedLength + record.deletedLength + record.errorsLength, std::ios::cur);

                // read next record
                file.read((char *) &record, recordSize);
            }
        } else { // refer to by index
            char *textBuffer;
            std::ifstream index(messyRoomPrefix + '/' + server, std::ios::binary);
            int64_t offset;

            // read first index
            index.read((char *) &offset, 8);
            // build JSON on the fly
            while (index.gcount()) {
                // seek and read the record
                file.seekg(offset, std::ios::beg);
                file.read((char *) &record, recordSize);

                if (client == std::string(record.sourceIp, record.ipLength)) {
                    yyjson_mut_val *object = yyjson_mut_obj(document);
                    yyjson_mut_arr_append(rootArray, object);

                    yyjson_mut_obj_add_int(document, object, "from", record.first);
                    yyjson_mut_obj_add_int(document, object, "to", record.last);

                    yyjson_mut_val *storedArray = yyjson_mut_arr(document);
                    yyjson_mut_obj_add_val(document, object, "stored", storedArray);
                    if (record.storedLength) {
                        textBuffer = new char[record.storedLength];
                        file.read(textBuffer, record.storedLength);
                        lineToArray(document, storedArray, std::string(textBuffer, record.storedLength));
                        delete[] textBuffer;
                    }

                    yyjson_mut_val *retrievedArray = yyjson_mut_arr(document);
                    yyjson_mut_obj_add_val(document, object, "retrieved", retrievedArray);
                    if (record.retrievedLength) {
                        textBuffer = new char[record.retrievedLength];
                        file.read(textBuffer, record.retrievedLength);
                        lineToArray(document, retrievedArray, std::string(textBuffer, record.retrievedLength));
                        delete[] textBuffer;
                    }

                    yyjson_mut_val *deletedArray = yyjson_mut_arr(document);
                    yyjson_mut_obj_add_val(document, object, "deleted", deletedArray);
                    if (record.deletedLength) {
                        textBuffer = new char[record.deletedLength];
                        file.read(textBuffer, record.deletedLength);
                        lineToArray(document, deletedArray, std::string(textBuffer, record.deletedLength));
                        delete[] textBuffer;
                    }

                    yyjson_mut_val *errorsArray = yyjson_mut_arr(document);
                    yyjson_mut_obj_add_val(document, object, "errors", errorsArray);
                    if (record.errorsLength) {
                        textBuffer = new char[record.errorsLength];
                        file.read(textBuffer, record.errorsLength);
                        lineToArray(document, errorsArray, std::string(textBuffer, record.errorsLength));
                        delete[] textBuffer;
                    }
                }

                // read next index
                index.read((char *) &offset, 8);
            }
        }
    }

    Civet7::respond200(connection, document);
}

void FeedRefinerFtpTracker::lineToArray(yyjson_mut_doc *document, yyjson_mut_val *array, const std::string &source)
{
    std::istringstream lineReader(source);
    for (std::string line; std::getline(lineReader, line, '|');)
        yyjson_mut_arr_add_strncpy(document, array, line.data(), line.size());
}

void FeedRefinerFtpTracker::dumpResults(mg_connection *connection)
{
    // header
    std::string chunk("ClientIP\tServerIP\tFrom\tTo\tClientToServer\tServerToClient\tStored\tRetrieved\tDeleted\tErrors\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    std::ifstream file(messyRoomPrefix + "/merged"s, std::ios::binary);
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);
    Record record;
    char *textBuffer;
    // read first record
    file.read((char *) &record, recordSize);
    while (file.gcount()) {
        // write down base
        chunk.append(SuperCodex::humanReadableIp(std::string(record.sourceIp, record.ipLength)) + '\t').append(SuperCodex::humanReadableIp(std::string(record.destinationIp, record.ipLength)) + '\t').append(epochToIsoDate(record.first) + '\t').append(epochToIsoDate(record.last) + '\t').append(std::to_string(record.fromClientToServer) + '\t').append(std::to_string(record.fromServerToClient) + '\t');

        // stored, retrieved, deleted, errors
        if (record.storedLength) {
            textBuffer = new char[record.storedLength];
            file.read(textBuffer, record.storedLength);
            chunk.append(textBuffer, record.storedLength);
            delete[] textBuffer;
        }
        chunk.push_back('\t');
        if (record.retrievedLength) {
            textBuffer = new char[record.retrievedLength];
            file.read(textBuffer, record.retrievedLength);
            chunk.append(textBuffer, record.retrievedLength);
            delete[] textBuffer;
        }
        chunk.push_back('\t');
        if (record.deletedLength) {
            textBuffer = new char[record.deletedLength];
            file.read(textBuffer, record.deletedLength);
            chunk.append(textBuffer, record.deletedLength);
            delete[] textBuffer;
        }
        chunk.push_back('\t');
        if (record.errorsLength) {
            textBuffer = new char[record.errorsLength];
            file.read(textBuffer, record.errorsLength);
            chunk.append(textBuffer, record.errorsLength);
            delete[] textBuffer;
        }
        chunk.push_back('\n');

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

void FeedRefinerFtpTracker::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    auto resultParts = SuperCodex::parallel_convert<SuperCodex::Loader *, Pack>(codices, [&](const SuperCodex::Loader *codex) -> Pack {
        Pack rawData;

        // load session data
        for (const auto &pair : codex->sessions)
            if (pair.second->detectedL7 == SuperCodex::Session::FTP) {
                rawData.sessions.push_back(*pair.second);
                rawData.descriptions[pair.first];
            }

        // load statistics
        for (auto bps = codex->firstBpsPerSession(); bps; bps = codex->nextBpsPerSession(bps))
            if (rawData.descriptions.contains(bps->sessionId)) {
                rawData.descriptions[bps->sessionId].fromSmallToBig += bps->fromSmallToBig;
                rawData.descriptions[bps->sessionId].fromBigToSmall += bps->fromBigToSmall;
            }

        // load remarks
        for (auto remarks = codex->firstRemarks(); remarks.content; remarks = codex->nextRemarks(remarks))
            if (rawData.descriptions.contains(remarks.sessionId)) {
                std::istringstream lineReader(std::string(remarks.content, remarks.size));
                for (std::string line; std::getline(lineReader, line);) {
                    while (line.back() == '\r' || line.back() == '\n')
                        line.pop_back();
                    if (line.find("FtpStor="s) == 0)
                        rawData.descriptions[remarks.sessionId].stored.append(line.substr(8)).push_back('|');
                    else if (line.find("FtpRetr="s) == 0)
                        rawData.descriptions[remarks.sessionId].retrieved.append(line.substr(8)).push_back('|');
                    else if (line.find("FtpDele="s) == 0)
                        rawData.descriptions[remarks.sessionId].deleted.append(line.substr(8)).push_back('|');
                    else if (line.find("FtpError="s) == 0)
                        rawData.descriptions[remarks.sessionId].errors.append(line.substr(9)).push_back('|');
                }
            }

        return rawData;
    });

    // merge
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Pack> resultRawsFuture) {
            // background: update session information
            std::thread updateSessionInformationThread([&]() {
                for (const auto &resultRaw : resultRawsFuture)
                    updateTimestampAndMergeSessions(resultRaw.sessions);
            });

            // write raw data
            std::ofstream file(messyRoomPrefix + "/dispersed"s, std::ios::binary | std::ios::app);
            Record record;
            for (const auto &resultRaw : resultRawsFuture)
                for (const auto &pair : resultRaw.descriptions) {
                    record.setSessionId(pair.first);
                    record.fromClientToServer = pair.second.fromSmallToBig;
                    record.fromServerToClient = pair.second.fromBigToSmall;
                    record.storedLength = pair.second.stored.size();
                    record.retrievedLength = pair.second.retrieved.size();
                    record.deletedLength = pair.second.deleted.size();
                    record.errorsLength = pair.second.errors.size();

                    file.write((const char *) &record, recordSize);
                    if (record.storedLength)
                        file.write(pair.second.stored.data(), record.storedLength);
                    if (record.retrievedLength)
                        file.write(pair.second.retrieved.data(), record.retrievedLength);
                    if (record.deletedLength)
                        file.write(pair.second.deleted.data(), record.deletedLength);
                    if (record.errorsLength)
                        file.write(pair.second.errors.data(), record.errorsLength);
                }

            // wait for session organizer to finish its job
            updateSessionInformationThread.join();
        },
        resultParts);
}

void FeedRefinerFtpTracker::finalize()
{
    // open raw data
    std::ifstream input(messyRoomPrefix + "/dispersed"s, std::ios::binary);

    // check sessions residing across codices
    Record readBuffer;
    int64_t offset = 0;
    ankerl::unordered_dense::map<uint64_t, std::vector<int64_t>> codexSegments;
    // read first record
    input.read((char *) &readBuffer, recordSize);
    while (input.gcount()) {
        codexSegments[readBuffer.sessionId()].push_back(offset);
        offset += recordSize + readBuffer.storedLength + readBuffer.retrievedLength + readBuffer.deletedLength + readBuffer.errorsLength;
        input.seekg(readBuffer.storedLength + readBuffer.retrievedLength + readBuffer.deletedLength + readBuffer.errorsLength, std::ios::cur);

        // read next record
        input.read((char *) &readBuffer, recordSize);
    }

    // reset some stuff to reuse
    offset = 0;
    input.close();
    input.open(messyRoomPrefix + "/dispersed"s, std::ios::binary);

    // prepare to write merged result
    std::ofstream file(messyRoomPrefix + "/merged"s, std::ios::binary);
    ankerl::unordered_dense::map<std::string, std::vector<uint64_t>> index;
    std::string stored, retrieved, deleted, errors, ip;
    int64_t fromClientToServer, fromServerToClient;
    char *textBuffer;
    Record writeBuffer;

    // merge and write result
    for (const auto &pair : codexSegments) {
        // initialize buffers
        stored.clear();
        retrieved.clear();
        deleted.clear();
        errors.clear();
        fromClientToServer = 0;
        fromServerToClient = 0;

        // merge per session data segments to one
        for (const auto &perSessionOffset : pair.second) {
            input.seekg(perSessionOffset, std::ios::beg);
            input.read((char *) &readBuffer, recordSize);
            // read additional records
            if (readBuffer.storedLength) {
                textBuffer = new char[readBuffer.storedLength];
                input.read(textBuffer, readBuffer.storedLength);
                stored.append(textBuffer, readBuffer.storedLength);
                delete[] textBuffer;
            }
            if (readBuffer.retrievedLength) {
                textBuffer = new char[readBuffer.retrievedLength];
                input.read(textBuffer, readBuffer.retrievedLength);
                retrieved.append(textBuffer, readBuffer.retrievedLength);
                delete[] textBuffer;
            }
            if (readBuffer.deletedLength) {
                textBuffer = new char[readBuffer.deletedLength];
                input.read(textBuffer, readBuffer.deletedLength);
                deleted.append(textBuffer, readBuffer.deletedLength);
                delete[] textBuffer;
            }
            if (readBuffer.errorsLength) {
                textBuffer = new char[readBuffer.errorsLength];
                input.read(textBuffer, readBuffer.errorsLength);
                errors.append(textBuffer, readBuffer.errorsLength);
                delete[] textBuffer;
            }

            // accumulate bytes transferred
            fromClientToServer += readBuffer.fromClientToServer;
            fromServerToClient += readBuffer.fromServerToClient;
        }
        const auto &session = sessions->at(readBuffer.sessionId());
        if (session.sourceIsSmall == 0)
            std::swap(fromClientToServer, fromServerToClient);

        // write merged record
        writeBuffer.ipLength = SuperCodex::ipLength(session.etherType);
        ip = SuperCodex::sourceIp(session);
        memcpy(writeBuffer.sourceIp, ip.data(), writeBuffer.ipLength);
        ip = SuperCodex::destinationIp(session);
        memcpy(writeBuffer.destinationIp, ip.data(), writeBuffer.ipLength);
        writeBuffer.first = session.first.second;
        writeBuffer.last = session.last.second;
        writeBuffer.fromClientToServer = fromClientToServer;
        writeBuffer.fromServerToClient = fromServerToClient;
        writeBuffer.storedLength = stored.size();
        writeBuffer.retrievedLength = retrieved.size();
        writeBuffer.deletedLength = deleted.size();
        writeBuffer.errorsLength = errors.size();

        // write to the file
        file.write((const char *) &writeBuffer, recordSize);
        if (writeBuffer.storedLength)
            file.write(stored.data(), writeBuffer.storedLength);
        if (writeBuffer.retrievedLength)
            file.write(retrieved.data(), writeBuffer.retrievedLength);
        if (writeBuffer.deletedLength)
            file.write(deleted.data(), writeBuffer.deletedLength);
        if (writeBuffer.errorsLength)
            file.write(errors.data(), writeBuffer.errorsLength);

        // build index and move offset
        index[ip].push_back(offset);
        offset += recordSize + writeBuffer.storedLength + writeBuffer.retrievedLength + writeBuffer.deletedLength + writeBuffer.errorsLength;
    }

    // save per-server record index and server list
    servers.reserve(index.size());
    for (const auto &pair : index) {
        std::ofstream indexFile(messyRoomPrefix + '/' + SuperCodex::stringToHex(pair.first), std::ios::binary);
        indexFile.write((const char *) pair.second.data(), pair.second.size() * 8);
        servers.push_back(pair.first);
    }
    std::sort(servers.begin(), servers.end());

    // log
    input.close();
    std::filesystem::remove(messyRoomPrefix + "/dispersed"s);
    logger.log("Results ready to serve: "s + std::to_string(codexSegments.size()));
}

FeedRefinerTlsTracker::FeedRefinerTlsTracker(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerTlsTracker"s);

    // prepare for room for accumulated raw data
    snis = new ankerl::unordered_dense::map<uint64_t, std::string>();
    performanceFactors = new ankerl::unordered_dense::map<uint64_t, Description>();

    // initialize session store
    sessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();
}

void FeedRefinerTlsTracker::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // find parameters
    std::string sni, result;
    if (parameters.contains("sni"s))
        sni = parameters.at("sni"s);

    // prepare for result JSON
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootArray = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, rootArray);

    if (sni.empty())
        for (const auto &sni : sniList)
            yyjson_mut_arr_add_strn(document, rootArray, sni.data(),
                                    sni.size()); // build list of SNIs found
    else if (std::filesystem::exists(messyRoomPrefix + '/' + sni)) {
        // read the entire file at once
        std::string rawData = static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(messyRoomPrefix + '/' + sni, std::ifstream::binary).rdbuf()).str();
        for (const ResultRecord *cursor = (const ResultRecord *) rawData.data(), *cursorEnd = (const ResultRecord *) (rawData.data() + rawData.size()); cursor < cursorEnd; ++cursor) {
            // prepare for the object
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_add_val(rootArray, object);

            // add object values
            std::string temp;
            temp = SuperCodex::stringToHex(std::string(cursor->ip + cursor->ipLength, cursor->ipLength));
            yyjson_mut_obj_add_strncpy(document, object, "serverip", temp.data(), temp.size());
            temp = SuperCodex::stringToHex(std::string(cursor->ip, cursor->ipLength));
            yyjson_mut_obj_add_strncpy(document, object, "clientip", temp.data(), temp.size());
            yyjson_mut_obj_add_int(document, object, "sessions", cursor->description.sessions);
            yyjson_mut_obj_add_int(document, object, "bytescs", cursor->description.bytesCs);
            yyjson_mut_obj_add_int(document, object, "bytessc", cursor->description.bytesSc);
            yyjson_mut_obj_add_int(document, object, "rttcscsum", cursor->description.rttSumCsc);
            yyjson_mut_obj_add_int(document, object, "rttcschits", cursor->description.rttHitsCsc);
            yyjson_mut_obj_add_int(document, object, "rttscssum", cursor->description.rttSumScs);
            yyjson_mut_obj_add_int(document, object, "rttscshits", cursor->description.rttHitsScs);
            yyjson_mut_obj_add_int(document, object, "timeouts", cursor->description.timeoutHits);
        }
    }

    Civet7::respond200(connection, document);
}

void FeedRefinerTlsTracker::dumpResults(mg_connection *connection)
{
    // header
    std::string chunk("SNI\tServerIP\tClientIP\tSessions\tBytesClientToServer\tBytesServerToClient\tRTT_CSC-sum\tRTT_CSC-hits\tRTT_SCS-sum\tRTT_SCS-hits\tTimeouts\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    for (const auto &filename : sniList) {
        // read the entire file at once
        std::string rawData = static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(messyRoomPrefix + '/' + filename, std::ifstream::binary).rdbuf()).str();
        for (const ResultRecord *cursor = (const ResultRecord *) rawData.data(), *cursorEnd = (const ResultRecord *) (rawData.data() + rawData.size()); cursor < cursorEnd; ++cursor) {
            // add new line
            chunk.append(filename + '\t').append(SuperCodex::humanReadableIp(std::string(cursor->ip + cursor->ipLength, cursor->ipLength)) + '\t').append(SuperCodex::humanReadableIp(std::string(cursor->ip, cursor->ipLength)) + '\t').append(std::to_string(cursor->description.sessions) + '\t').append(std::to_string(cursor->description.bytesCs) + '\t').append(std::to_string(cursor->description.bytesSc) + '\t').append(std::to_string(cursor->description.rttSumCsc) + '\t').append(std::to_string(cursor->description.rttHitsCsc) + '\t').append(std::to_string(cursor->description.rttSumScs) + '\t').append(std::to_string(cursor->description.rttHitsScs) + '\t').append(std::to_string(cursor->description.timeoutHits) + '\n');

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
    }

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

void FeedRefinerTlsTracker::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    // gather both latencies and timeouts per SNI
    std::vector<Intermediate> intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, Intermediate>(codices, [&](const SuperCodex::Loader *codex) -> Intermediate {
        Intermediate intermediate;

        // reserve some memory
        size_t sizeBase = codex->sessions.size();
        intermediate.sessions.reserve(sizeBase);

        // gather sessions
        for (const auto &pair : codex->sessions)
            intermediate.sessions.push_back(*pair.second);

        // build session-to-SNI dictionary
        for (auto remarks = codex->firstRemarks(); remarks.content; remarks = codex->nextRemarks(remarks))
            intermediate.snis[remarks.sessionId] = remarksValue(std::string_view(remarks.content, remarks.size), "TLSSNI"s);

        // read bytes counter
        for (auto bytes = codex->firstBpsPerSession(); bytes; bytes = codex->nextBpsPerSession(bytes)) {
            const auto &session = codex->sessions.at(bytes->sessionId);
            auto &description = intermediate.performanceFactors[bytes->sessionId];
            if (session->sourceIsSmall) {
                description.bytesCs = bytes->fromSmallToBig;
                description.bytesSc = bytes->fromBigToSmall;
            } else {
                description.bytesCs = bytes->fromBigToSmall;
                description.bytesSc = bytes->fromSmallToBig;
            }
        }
        // read RTTs
        for (auto rtt = codex->firstRtt(); rtt; rtt = codex->nextRtt(rtt)) {
            const auto &session = codex->sessions.at(rtt->sessionId);
            auto &description = intermediate.performanceFactors[rtt->sessionId];
            if (session->sourceIsSmall == rtt->fromSmallToBig) {
                description.rttSumScs += rtt->tail;
                ++description.rttHitsScs;
            } else {
                description.rttSumCsc += rtt->tail;
                ++description.rttHitsCsc;
            }
        }

        // read timeouts
        for (auto timeout = codex->firstTimeout(); timeout; timeout = codex->nextTimeout(timeout))
            ++intermediate.performanceFactors[timeout->session.id].timeoutHits;

        return intermediate;
    });

    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Intermediate> intermediatesFuture) {
            // background: update session information
            std::thread updateSessionInformationThread([&]() {
                for (const auto &resultRaw : intermediatesFuture)
                    updateTimestampAndMergeSessions(resultRaw.sessions);
            });

            // foreground: store per-session performance factors
            for (const auto &intermediate : intermediatesFuture) {
                // merge SNI data
                for (const auto &pair : intermediate.snis)
                    (*snis)[pair.first] = pair.second;

                // merge performance factors
                for (const auto &pair : intermediate.performanceFactors)
                    (*performanceFactors)[pair.first] += pair.second;
            }

            // wait for the background session merge job to be finished
            updateSessionInformationThread.join();
        },
        intermediates);
}

void FeedRefinerTlsTracker::finalize()
{
    // remove garbages(SNI not alphanumeric: there can be some payloads sharing same magic packets with TLS)
    for (auto i = snis->begin(); i != snis->end();) {
        bool containtsNotAllowedCharacters = false;
        for (const auto &c : i->second)
            if (isalnum(c) == 0 && c != '.' && c != '-') {
                containtsNotAllowedCharacters = true;
                break;
            }
        if (containtsNotAllowedCharacters)
            i = snis->erase(i);
        else
            ++i;
    }

    // build accmulated results
    ankerl::unordered_dense::map<std::string, ankerl::unordered_dense::map<std::string, ankerl::unordered_dense::map<std::string, Description>>> accumulated; // SNI + server IP + client IP + performance descriptors
    for (const auto &pair : *performanceFactors) {
        const auto sessionId = pair.first;
        const auto &session = (*sessions)[sessionId];
        accumulated[(*snis)[sessionId]][SuperCodex::destinationIp(session)][SuperCodex::sourceIp(session)] += pair.second;
    }

    // write the result to the disk
    sniList.reserve(accumulated.size());
    for (const auto &sniPair : accumulated) {
        // register index
        sniList.push_back(sniPair.first);

        // write records
        for (const auto &serverIpPair : sniPair.second)
            for (const auto &clientIpPair : serverIpPair.second) {
                ResultRecord record;
                // set IP pair
                record.ipLength = serverIpPair.first.size();
                memcpy(record.ip, serverIpPair.first.data(), record.ipLength);
                memcpy(record.ip + record.ipLength, clientIpPair.first.data(), record.ipLength);
                // set description
                record.description = clientIpPair.second;

                // write to disk
                std::string filename = sniPair.first;
                if (filename.empty())
                    filename = "!!!!!!"s;
                std::ofstream resultFile(messyRoomPrefix + '/' + filename, std::ios::out | std::ios::binary);
                resultFile.write((const char *) &record, resultRecordSize);
                resultFile.close();
            }
    }

    // some chores
    std::sort(sniList.begin(), sniList.end());
    delete snis;
    delete performanceFactors;

    // log
    logger.log("Results ready to serve: "s + std::to_string(sniList.size()));
}

FeedRefinerTlsDump::FeedRefinerTlsDump(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    isStreaming = true;
    logger.setLogHeader("FeedRefinerTlsDumper"s);

    // create database to store filtered records
    dbPath = messyRoomPrefix + "/filtered"s;
    FeatherLite feather(dbPath);
    feather.optimize();
    feather.useWal();
    feather.prepare("CREATE TABLE rows(timestamp INTEGER, clientip BLOB, serverip BLOB, clientport INTEGER, serverport INTEGER, sni TEXT);"
                    "CREATE INDEX idx1 ON rows(timestamp);"s);
    if (feather.next() != SQLITE_DONE)
        logger.oops("Unexpected result code on messy room DB creation. Details: "s + feather.lastError());
}

FeedRefinerTlsDump::~FeedRefinerTlsDump()
{
    // ensure to stop background thread
    continueBackgroundThread = false;
    buildRecordsThread.join();
}

void FeedRefinerTlsDump::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    // do nothing in streaming mode
}

void FeedRefinerTlsDump::finalize()
{
    // start generating records in the background thread
    logger.log("Generate records"s);
    buildRecordsThread = std::thread([&]() {
        // check database availability
        std::string cachePath = CodexIndex::feedRoot + conditions.dataFeed + '/' + SuperCache::dbs.back();
        if (!std::filesystem::exists(cachePath) || std::filesystem::file_size(cachePath) == 0) {
            logger.oops("SuperCache TLS dump database not found or corrupt: "s + cachePath);
            return;
        }

        // connect to SuperCache TLS dump database
        FeatherLite feather(cachePath, SQLITE_OPEN_READONLY), db(dbPath);
        feather.prepare("SELECT timestamp,ips,clientport,serverport,sni FROM rows WHERE timestamp>=? AND timestamp<=? ORDER BY timestamp,sni;"s);
        feather.bindInt64(1, conditions.from);
        feather.bindInt64(2, conditions.to);
        db.prepare("INSERT INTO rows(timestamp, clientip, serverip, clientport, serverport, sni) VALUES(?,?,?,?,?,?);"s);

        // do filtering
        while (feather.next() == SQLITE_ROW && continueBackgroundThread) {
            // apply filter conditions
            // port
            const auto sourcePort = feather.getInt(2), destinationPort = feather.getInt(3);
            const auto &conditionsPorts = conditions.ports;
            if (!conditionsPorts.empty()) {
                if (!conditionsPorts.contains(sourcePort) && !conditionsPorts.contains(destinationPort))
                    continue;
            }

            // extract IPs
            const auto ipsRaw = feather.getBlob(1);
            const char *ipsData = ipsRaw.data();
            const size_t ipLength = ipsRaw.size() / 2;
            std::string sourceIp(ipsData, ipLength), destinationIp(ipsData + ipLength, ipLength);

            // ips && apps
            if (!conditions.allowedIps.isEmpty) {
                if (conditions.includeExternalTransfer) {
                    if (!conditions.allowedIps.contains(destinationIp) || !conditions.allowedIps.contains(sourceIp))
                        continue;
                } else {
                    if (!conditions.allowedIps.contains(destinationIp) && !conditions.allowedIps.contains(sourceIp))
                        continue;
                }
            }

            // add record
            db.bindInt64(1, feather.getInt64(0));
            db.bindBlob(2, sourceIp);
            db.bindBlob(3, destinationIp);
            db.bindInt(4, sourcePort);
            db.bindInt(5, destinationPort);
            db.bindText(6, feather.getText(4));
            if (db.next() != SQLITE_DONE)
                logger.oops("Failed to insert record to filtered list. Details: "s + db.lastError());
            db.reset();
            if (++recordsAdded % 100000 == 0)
                logger.log("Enumerated "s + std::to_string(recordsAdded) + " records"s);
        }

        // declare end of the enumeration
        logger.log("Complete enumerating TLS sessions. Total "s + std::to_string(recordsAdded) + " records"s);
        isComplete = true;

        if (continueBackgroundThread)
            logger.log("Job finished gracefully"s);
        else
            logger.log("Job stopped in the middle as requested"s);
    });

    // wait for up to 5 seconds
    for (int i = 0; i < 5; ++i)
        if (isComplete)
            break;
        else
            std::this_thread::sleep_for(std::chrono::seconds(1));

    // log
    if (!isComplete)
        logger.log("Generated "s + std::to_string(recordsAdded) + " initial records. Generate remaining in the background"s);
}

void FeedRefinerTlsDump::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // prepare for JSON object
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);

    // describe overall status
    yyjson_mut_obj_add_bool(document, rootObject, "complete", isComplete);
    yyjson_mut_obj_add_int(document, rootObject, "totalrecords", recordsAdded);
    yyjson_mut_val *recordsArray = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "records", recordsArray);

    // enumerate
    FeatherLite feather(dbPath, SQLITE_OPEN_READONLY);
    feather.prepare("SELECT timestamp, clientip, clientport, serverip, serverport, sni FROM rows ORDER BY timestamp LIMIT ?,?;"s);
    feather.bindInt64(1, from);
    feather.bindInt64(2, to - from + 1);
    while (feather.next() == SQLITE_ROW) {
        // register object to array
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_add_val(recordsArray, object);

        // organize record
        std::string temp;
        // timestamp
        yyjson_mut_obj_add_int(document, object, "timestamp", feather.getInt64(0));
        // client information
        temp = SuperCodex::stringToHex(feather.getBlob(1));
        yyjson_mut_obj_add_strncpy(document, object, "clientip", temp.data(), temp.size());
        yyjson_mut_obj_add_int(document, object, "clientport", feather.getInt(2));
        // server information
        temp = SuperCodex::stringToHex(feather.getBlob(3));
        yyjson_mut_obj_add_strncpy(document, object, "serverip", temp.data(), temp.size());
        yyjson_mut_obj_add_int(document, object, "serverport", feather.getInt(4));
        // server name identification (SNI)
        temp = feather.getText(5);
        yyjson_mut_obj_add_strncpy(document, object, "sni", temp.data(), temp.size());
    }

    Civet7::respond200(connection, document);
}

void FeedRefinerTlsDump::dumpResults(mg_connection *connection)
{
    // header
    std::string chunk("Timestamp\tClient\tServer\tSNI\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // connect to the database
    FeatherLite feather(dbPath, SQLITE_OPEN_READONLY);
    feather.prepare("SELECT timestamp, clientip, clientport, serverip, serverport, sni FROM rows ORDER BY timestamp;"s);
    while (feather.next() == SQLITE_ROW) {
        chunk
            .append(epochToIsoDate(feather.getInt64(0)) + '\t') // timestamp
            .append(SuperCodex::humanReadableIp(feather.getBlob(1)) + ':' + std::to_string(feather.getInt(2)) + '\t') // client
            .append(SuperCodex::humanReadableIp(feather.getBlob(3)) + ':' + std::to_string(feather.getInt(4)) + '\t') // server
            .append(feather.getText(5)) // SNI
            .push_back('\n');

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
