#include "feedrefinerspecialized.h"
#include "../fnvhash.h"
#include "civet7.hpp"
#include "datafeed.h"

#include <filesystem>
#include <fstream>
#include <functional>
#include <regex>
#include <sstream>
#include <charconv>
#include <shared_mutex>
#include <iterator>

#include <tbb/parallel_for.h>

FeedRefinerHttt::FeedRefinerHttt(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerHttt"s);

    // initialize session store and others
    requestsOnly = new ankerl::unordered_dense::map<uint64_t, Description>();
    refererChain = new ankerl::unordered_dense::map<std::string, std::string>();
}

void FeedRefinerHttt::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // check parameters, including testing regex filter
    std::string clients;
    std::regex regex;
    bool regexAssigned = false;
    if (parameters.contains("clients"s))
        clients = parameters.at("clients"s);
    if (parameters.contains("searchstring"s)) {
        try {
            regex.assign(parameters.at("searchstring"s));
            regexAssigned = true;
        } catch (std::exception &e) {
            mg_send_http_error(connection, 500, e.what());
            return;
        } catch (...) {
            mg_send_http_error(connection, 500, "Internal server error: reason unknown");
            return;
        }
    }

    // common initialization for building JSON
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);

    // build JSON
    if (clients.empty() && !regexAssigned) {
        yyjson_mut_val *root = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, root);
        for (const auto &ip : sourceIps)
            yyjson_mut_arr_add_strncpy(document, root, ip.data(), ip.size()); // enumerate all the source IPs
    } else {
        // enumerate each target source IP
        std::vector<std::string> targetSourceIps;
        if (clients == "all"s)
            targetSourceIps = sourceIps;
        else {
            std::istringstream splitter(clients);
            for (std::string ip; std::getline(splitter, ip, ',');)
                targetSourceIps.push_back(ip);
        }

        // prepare for root
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        // yyjson_mut_val *rootArray = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootArray);

        for (const auto &ip : targetSourceIps) {
            // build directory path and check its existence
            std::string directory = messyRoomPrefix + '/' + ip;
            if (!std::filesystem::exists(directory)) {
                logger.log("Skip unknown target directory: "s + directory);
                continue;
            }

            // prepare for key for the most outer part
            std::string keyPrefix = ip + '-';
            long long counter = 0;
            ankerl::unordered_dense::map<std::string, yyjson_mut_val *> referers; // referer URL + JSON array for key "children"

            // enumerate files
            for (const auto &file : std::filesystem::directory_iterator(directory)) {
                // load raw data to the RAM
                std::string rawData(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(file.path(), std::ifstream::binary).rdbuf()).str());

                // skip if regular expression doesn't hit
                if (regexAssigned) {
                    std::smatch match;
                    if (!std::regex_search(rawData, match, regex))
                        continue;
                }

                // prepare to read file
                std::string url, referer;
                yyjson_mut_val *entryForChildren;
                std::istringstream lineReader(rawData);

                // read line by line
                for (std::string line; std::getline(lineReader, line, '\n');) {
                    yyjson_mut_val *object = lineToJsonObject(document, ip, line, url, referer, entryForChildren);
                    std::string key = keyPrefix + std::to_string(counter++);
                    yyjson_mut_obj_add_strncpy(document, object, "key", key.data(), key.size());

                    // check existence of referer object
                    if (!referer.empty() && !referers.contains(referer)) {
                        yyjson_mut_val *blankObject, *blankChildrenEntry;
                        blankObject = blankJsonObject(document, ip, referer, blankChildrenEntry);
                        std::string key = keyPrefix + std::to_string(counter++);
                        yyjson_mut_obj_add_strncpy(document, blankObject, "key", key.data(), key.size());
                        referers[referer] = blankChildrenEntry;
                        yyjson_mut_arr_append(rootArray, blankObject);
                    }

                    // register to parent(or root, if referer is blank)
                    if (referer.empty())
                        yyjson_mut_arr_append(rootArray, object);
                    else
                        yyjson_mut_arr_append(referers[referer], object);
                }
            }
        }
    }

    // prepare for result and return
    Civet7::respond200(connection, document);
}

void FeedRefinerHttt::dumpResults(mg_connection *connection)
{
    // send header
    std::string chunk("Source IP\tRoot\tStatus Code\tIs HTML?\tRequest Time\tLatency(ns)\tHost\tPath\tReferer\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // send body chunks
    for (const auto &directory : std::filesystem::directory_iterator(messyRoomPrefix))
        if (directory.is_directory()) {
            // determine source IP
            std::string sourceIp = SuperCodex::humanReadableIp(SuperCodex::stringFromHex(directory.path().filename().string()));

            for (const auto &transaction : std::filesystem::directory_iterator(directory))
                if (transaction.is_regular_file()) {
                    // read the whole file to RAM
                    std::string file(std::string(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(transaction.path(), std::ifstream::binary).rdbuf()).str()));

                    // determine root URL and build line prefix: if the first line is HTML it's root. For others, the first referer is the root
                    std::string linePrefix(sourceIp + '\t' + extractRootUrl(file) + '\t');

                    // generate result, line by line
                    std::istringstream lineFeeder(file);
                    for (std::string line; std::getline(lineFeeder, line, '\n');) {
                        // append prefix and status code
                        chunk.append(linePrefix).append(line.substr(0, 3)).push_back('\t');

                        // check whether the URL is HTML or not
                        if (line.at(3) == 'h')
                            chunk.append("HTML\t"s);
                        else
                            chunk.append("non-HTML\t"s);

                        // add human readable timestamp and anything else
                        chunk.append(epochToIsoDate(std::stoul(line.substr(4, 10)))).append(line.substr(23)).push_back('\n');

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

void FeedRefinerHttt::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    std::vector<Intermediate> intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, Intermediate>(codices, [&](const SuperCodex::Loader *loader) -> Intermediate {
        Intermediate intermediate;
        for (auto remarks = loader->firstRemarks(); remarks.content; remarks = loader->nextRemarks(remarks))
            if (loader->sessions.at(remarks.sessionId)->detectedL7 == SuperCodex::Session::HTTP) {
                // prepare for separation
                size_t cursor, cursorEnd;
                std::string_view view(remarks.content, remarks.size);
                std::vector<std::string_view> headers;

                // build list of HTTP headers
                cursor = view.find("HttpRe"s);
                while (cursor != std::string::npos) {
                    cursorEnd = view.find("\nHttpEnd=Re"s, cursor + 6);
                    if (cursorEnd == std::string_view::npos)
                        cursorEnd = view.size() - 2;
                    headers.push_back(std::string_view(remarks.content + cursor, cursorEnd + 2 - cursor));

                    // find next HTTP header
                    cursor = view.find("HttpRe"s, cursorEnd + 11);
                }

                // check whether this is actually "partial" persistent connection, which may start with HTTP reponse or end with request
                if (headers.front()[6] == 's') { // HttpResponse=.......
                    Description description;
                    description.sessionId = remarks.sessionId;
                    fillResponse(description, headers.front());
                    intermediate.responsesOnly.push_back(std::move(description));
                    headers.erase(headers.begin()); // remove item
                }
                if (!headers.empty() && headers.back()[6] == 'q') { // HttpRequest=......
                    Description description = fillRequest(headers.back(), loader->sessions.at(remarks.sessionId));
                    intermediate.requestsOnly.push_back(std::move(description));
                    headers.pop_back(); // remove item
                }

                Description description{};
                for (const auto &header : headers)
                    if (header[6] == 'q') { // HttpRequest=......
                        // prepare for new description
                        description = fillRequest(header, loader->sessions.at(remarks.sessionId));
                    } else { // HttpResponse=......
                        if (description.sessionId) { // check whether request side is filled. there may be successive response after response(e.g. HTTP 207 Multi-status or packet loss from request side)
                            // fill response data and add new complete request-response pair
                            fillResponse(description, header);
                            intermediate.fullDescriptions.push_back(std::move(description));
                        }

                        // reset description for new record
                        description = Description{};
                    }
            }

        // return results
        std::sort(intermediate.fullDescriptions.begin(), intermediate.fullDescriptions.end(), [](const Description &a, const Description &b) { return a.responseAt < b.responseAt; });
        return intermediate;
    });

    // merge data
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](std::vector<Intermediate> intermediatesFuture) {
            std::thread writeBufferFuture; // writing to the file is done in the background
            for (auto &intermediate : intermediatesFuture) {
                // prepare for merging partial requests
                auto &fullDescriptions = intermediate.fullDescriptions;
                auto fullDescriptionsOriginalSize = fullDescriptions.size();

                // merge responses with requests and add new full descriptions to the vector
                for (const auto &response : intermediate.responsesOnly)
                    if ((*requestsOnly).contains(response.sessionId)) {
                        auto &description = (*requestsOnly)[response.sessionId];
                        description.responseAt = response.responseAt;
                        description.statusCode = response.statusCode;
                        description.isHtml = response.isHtml;
                        fullDescriptions.push_back(std::move(description));
                        requestsOnly->erase(response.sessionId);
                    }
                if (fullDescriptionsOriginalSize != fullDescriptions.size())
                    std::sort(fullDescriptions.begin(), fullDescriptions.end(), [](const Description &a, const Description &b) { return a.responseAt < b.responseAt; });

                // register new partial requests
                for (const auto &request : intermediate.requestsOnly)
                    (*requestsOnly)[request.sessionId] = request;

                // prepare for buffer for full descriptions
                ankerl::unordered_dense::map<std::string, std::string> writeBuffer; // (directory+fnv64a-hased root URL) + <file content+root URL>
                for (const auto &description : fullDescriptions) {
                    // create directory for source IP if it doesn't exist
                    const std::string directory = messyRoomPrefix + '/' + SuperCodex::stringToHex(description.sourceIp) + '/';
                    if (!std::filesystem::exists(directory))
                        std::filesystem::create_directory(directory);

                    // determine where to push the record
                    std::string url;
                    if (description.path.find("http://"s) == 0)
                        url = description.path.substr(7); // sometimes the path can be full URL, instead of just path
                    else {
                        if (!description.isHtml && description.referer.size() > 7 && url != description.referer.substr(7))
                            url = root(description);
                        else
                            url = description.host + description.path; // (1)path is HTML page or (2)referer is invalid (empty or something unusable, e.g. */*)
                    }

                    // write buffer
                    auto &target = writeBuffer[directory + std::to_string(fnv64a(url.data(), url.size()))];
                    if (target.empty())
                        target.reserve(16384); // 16KB. Most of time this is more than enough
                    target.append(descriptionToRecord(description));
                }

                // write down buffers to the disk in the background
                if (writeBufferFuture.joinable())
                    writeBufferFuture.join();
                writeBufferFuture = std::thread(
                    [&](const ankerl::unordered_dense::map<std::string, std::string> bufferFuture) {
                        for (const auto &pair : bufferFuture) {
                            std::ofstream file(pair.first, std::ios::binary | std::ios::app);
                            file.write(pair.second.data(), pair.second.size());
                        }
                    },
                    std::move(writeBuffer));
            }
            // wait for final write
            if (writeBufferFuture.joinable())
                writeBufferFuture.join();
        },
        std::move(intermediates));
}

void FeedRefinerHttt::finalize()
{
    // cache source IPs to vector for faster enumeration
    for (const auto &directory : std::filesystem::directory_iterator(messyRoomPrefix))
        if (directory.is_directory())
            sourceIps.push_back(directory.path().filename().string());
    std::sort(sourceIps.begin(), sourceIps.end());

    // clean up
    delete requestsOnly;
    delete refererChain;
    logger.log("Results ready to serve: "s + std::to_string(sourceIps.size()));
}

FeedRefinerHttt::Description FeedRefinerHttt::fillRequest(const std::string_view &header, SuperCodex::Session *session)
{
    // initialize with fill session information
    Description description{SuperCodex::sourceIp(*session), SuperCodex::destinationIp(*session), session->destinationPort, session->id, {}, {}, {}, {}, {}, {}, {}, {}, {}};

    // parse first line(HttpRequest=......)
    std::string line;
    std::istringstream headerStream(std::string(header.data() + 12, header.find('\n') - 12));
    std::getline(headerStream, line, ' ');
    description.requestAt = std::stoull(line); // timestamp
    std::getline(headerStream, description.method, ' '); // method
    std::getline(headerStream, description.path, '\n'); // path

    // information from request header
    description.host = remarksValueHttpHeader(header, "Host");
    if (description.host.empty()) { // if "Host" header is not found, use human readable IP and port combination(optional. only if server port is not 80) as host name
        description.host = SuperCodex::humanReadableIp(description.destinationIp);
        if (description.destinationPort != 80)
            description.host.append(':' + std::to_string(description.destinationPort));
    }
    description.userAgent = remarksValueHttpHeader(header, "User-Agent");
    description.referer = remarksValueHttpHeader(header, "Referer");

    // "refine" Referer value
    if (description.referer.find("http://"s) == 0)
        description.referer.erase(0, 7); // remove protocol scheme('http://') from Referer
    else
        description.referer.clear(); // found out referer can be sometimes "*/*". no idea why, but...... :P

    return description;
}

void FeedRefinerHttt::fillResponse(Description &description, const std::string_view &header)
{
    // parse first line(HttpResponse=......)
    std::string line;
    std::istringstream headerStream(std::string(header.data() + 13, header.find('\n')));
    std::getline(headerStream, line, ' ');
    description.responseAt = std::stoull(line); // timestamp
    std::getline(headerStream, line, ' ');
    description.statusCode = std::stoi(line); // status code

    // determine whether content type is HTML
    std::string contentType = remarksValueHttpHeader(header, "Content-Type");
    if (contentType.empty()) {
        if (description.path.empty())
            return; // no request information
        // use some heuristics/wild guess from URL path
        description.isHtml = (description.path.back() == '/' || description.path.find('.', description.path.find_last_of('/')) || description.path.find(".jsp") == description.path.size() - 4 || description.path.find(".php") == description.path.size() - 4 || description.path.find(".aspx") == description.path.size() - 5 || description.path.find(".asp") == description.path.size() - 4 || description.path.find(".html") == description.path.size() - 5 || description.path.find(".htm") == description.path.size() - 4);
    } else
        description.isHtml = (contentType.find("text/html"s) == 0); // most of the time, content type contains its text encoding, e.g. "text/html;charset=UTF-8"
}

std::string FeedRefinerHttt::descriptionToRecord(const Description &description)
{
    // initialize result string with status code
    std::string result(description.statusCode == 0 ? "000"s : std::to_string(description.statusCode));
    result.reserve(43 + description.host.size() + description.path.size() + description.referer.size());

    // line structure: flag(1byte)+request timestamp+elapsed time+host+path+referer
    if (description.isHtml)
        result.push_back('h');
    else
        result.push_back('n'); // h: HTML. n: not HTML
    result.append(std::to_string(description.requestAt) + '\t')
        .append(std::to_string(description.responseAt - description.requestAt) + '\t') // nanosecond-level timestamp for request and elapsed time until response
        .append(description.host + '\t')
        .append(description.path + '\t') // host and path + direct referer. c.f. sometimes path can be full URL, not just path(e.g. http://www.....)
        .append(description.referer)
        .push_back('\n'); // referer

    return result;
}

yyjson_mut_val *FeedRefinerHttt::lineToJsonObject(yyjson_mut_doc *document, const std::string &sourceIp, const std::string &line, std::string &url, std::string &referer, yyjson_mut_val *&entryForChildren)
{
    yyjson_mut_val *object = yyjson_mut_obj(document), *data = yyjson_mut_obj(document);

    // register data: status code, is_html, timestamp
    yyjson_mut_obj_add_val(document, object, "data", data);
    yyjson_mut_obj_add_strncpy(document, data, "ip", sourceIp.data(), sourceIp.size());
    yyjson_mut_obj_add_int(document, data, "statuscode", std::stoi(line.substr(0, 3)));
    yyjson_mut_obj_add_bool(document, data, "ishtml", (line.at(3) == 'h'));
    yyjson_mut_obj_add_int(document, data, "timestamp", std::stoull(line.substr(4, 19)));

    // RTT
    std::string temp, temp2;
    std::istringstream recordSplitter(line);
    std::getline(recordSplitter, temp, '\t'); // skip request timestamp
    std::getline(recordSplitter, temp, '\t'); // timestamp between request and response in nanosecond precision
    yyjson_mut_obj_add_int(document, data, "rtt", std::stoull(temp));

    // full URL
    std::getline(recordSplitter, temp, '\t'); // host
    std::getline(recordSplitter, temp2, '\t'); // path
    if (temp2.find("http://"s) == 0)
        url = temp2.substr(7);
    else
        url = temp + temp2;
    yyjson_mut_obj_add_strncpy(document, data, "url", url.data(), url.size());

    // referer
    std::getline(recordSplitter, referer, '\t');

    // children
    entryForChildren = yyjson_mut_arr(document);
    yyjson_mut_obj_add(object, yyjson_mut_strn(document, "children", 8), entryForChildren);

    return object;
}

yyjson_mut_val *FeedRefinerHttt::blankJsonObject(yyjson_mut_doc *document, const std::string &sourceIp, std::string &url, yyjson_mut_val *&entryForChildren)
{
    yyjson_mut_val *object = yyjson_mut_obj(document), *data = yyjson_mut_obj(document);

    // put dummy data
    yyjson_mut_obj_add_val(document, object, "data", data);
    yyjson_mut_obj_add_strncpy(document, data, "ip", sourceIp.data(), sourceIp.size());
    yyjson_mut_obj_add_int(document, data, "statuscode", -1);
    yyjson_mut_obj_add_bool(document, data, "ishtml", true);
    yyjson_mut_obj_add_int(document, data, "timestamp", -1);
    yyjson_mut_obj_add_int(document, data, "rtt", -1);
    yyjson_mut_obj_add_strncpy(document, data, "url", url.data(), url.size());

    // children
    entryForChildren = yyjson_mut_arr(document);
    yyjson_mut_obj_add(object, yyjson_mut_strn(document, "children", 8), entryForChildren);

    return object;
}

std::string FeedRefinerHttt::root(const Description &description)
{
    // register referer information and find root from the referer chain
    (*refererChain)[description.host + description.path] = description.referer;

    // prepare to track root
    std::string nextReferer = description.referer;
    ankerl::unordered_dense::set<std::string> parents; // to check loop

    // find root
    while (refererChain->count(nextReferer)) {
        // if there's a loop in referer chain, cut before restart of the chain
        if (parents.contains(nextReferer))
            return nextReferer;

        // register "parent" in referer chain and go up
        parents.insert(nextReferer);
        nextReferer = (*refererChain)[nextReferer];
    }

    return nextReferer;
}

std::string FeedRefinerHttt::extractRootUrl(const std::string &rawData)
{
    std::string firstLine(rawData.data(), rawData.find('\n'));
    if (firstLine.at(3) == 'h' || firstLine.back() == '\t') { // first line is HTML or Referer URL is not found on first line
        std::string host, path;
        std::istringstream recordSplitter(firstLine);
        std::getline(recordSplitter, host, '\t'); // request timestamp
        std::getline(recordSplitter, host, '\t'); // elapsed time in nanosecond
        std::getline(recordSplitter, host, '\t'); // host
        std::getline(recordSplitter, path, '\t'); // path
        if (path.find("http://"s) == 0)
            return path.substr(7);
        else
            return host + path;
    } else
        return firstLine.substr(firstLine.find_last_of('\t') + 1);
}

FeedRefinerJitter::FeedRefinerJitter(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    logger.setLogHeader("FeedRefinerJitter"s);

    // initialize session store
    sessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();
    accumulatedRtts = new ankerl::unordered_dense::map<uint64_t, Intermediate::RttRecord>();
}

void FeedRefinerJitter::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // determine how many records will be shown
    int recordsToShow = bindValue, recordsShown = 0;
    if (recordsToShow == 0)
        recordsToShow = 100;

    // prepare for result array
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootArray = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, rootArray);

    // open files
    std::ifstream indexFile(messyRoomPrefix + "/index"s, std::ios::binary);
    std::pair<int64_t, uint64_t> indexItemBuffer;
    std::ifstream file(messyRoomPrefix + "/results", std::ios::binary);
    Result record;
    while (recordsShown < recordsToShow) {
        // read index
        indexFile.read((char *) &indexItemBuffer, indexSize); // read first record
        if (indexFile.gcount() == 0)
            break;

        // move file cursor
        file.seekg(indexItemBuffer.first, std::ios::beg);

        // read record
        file.read((char *) &record.head, resultHeadSize);
        size_t macBufferSize = record.head.macClientSize + record.head.macServerSize;
        char *macBuffer = new char[macBufferSize];
        file.read(macBuffer, macBufferSize);
        record.macClient.append(macBuffer, record.head.macClientSize);
        record.macServer.append(macBuffer + record.head.macClientSize, record.head.macServerSize);
        delete[] macBuffer;

        // filter based on duration
        auto duration = record.head.to - record.head.from;
        if (duration < from || duration > to)
            continue;

        // write down JSON body
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(rootArray, object);
        std::string temp;
        temp = SuperCodex::stringToHex(std::string((const char *) record.head.ips, record.head.ipLength));
        yyjson_mut_obj_add_strncpy(document, object, "clientip", temp.data(), temp.size());
        yyjson_mut_obj_add_int(document, object, "clientport", record.head.clientPort);
        temp = SuperCodex::stringToHex(std::string((const char *) record.head.ips + record.head.ipLength, record.head.ipLength));
        yyjson_mut_obj_add_strncpy(document, object, "serverip", temp.data(), temp.size());
        yyjson_mut_obj_add_int(document, object, "serverport", record.head.serverPort);
        yyjson_mut_obj_add_int(document, object, "from", record.head.from);
        yyjson_mut_obj_add_int(document, object, "to", record.head.to);
        yyjson_mut_obj_add_int(document, object, "jitter", record.head.csc.average);
        yyjson_mut_obj_add_int(document, object, "count", record.head.csc.count);
        yyjson_mut_obj_add_int(document, object, "jitter2", record.head.scs.average);
        yyjson_mut_obj_add_int(document, object, "count2", record.head.scs.count);
        yyjson_mut_obj_add_int(document, object, "totalpackets", record.head.totalPackets);
        yyjson_mut_obj_add_int(document, object, "payloadprotocol", record.head.payloadProtocol);

        // enumerate MACs
        yyjson_mut_val *clientMacs = yyjson_mut_arr(document);
        yyjson_mut_obj_add(object, yyjson_mut_str(document, "clientmacs"), clientMacs);
        for (int i = 0, iEnd = record.head.macClientSize / 6; i < iEnd; ++i) {
            std::string mac = SuperCodex::stringToHex(record.macClient.substr(i * 6, 6));
            yyjson_mut_arr_append(clientMacs, yyjson_mut_strncpy(document, mac.data(), mac.size()));
        }
        yyjson_mut_val *serverMacs = yyjson_mut_arr(document);
        yyjson_mut_obj_add(object, yyjson_mut_str(document, "servermacs"), serverMacs);
        for (int i = 0, iEnd = record.head.macServerSize / 6; i < iEnd; ++i) {
            std::string mac = SuperCodex::stringToHex(record.macClient.substr(i * 6, 6));
            yyjson_mut_arr_append(serverMacs, yyjson_mut_strncpy(document, mac.data(), mac.size()));
        }

        // count up
        ++recordsShown;
    }

    // send result
    Civet7::respond200(connection, document);
}

void FeedRefinerJitter::dumpResults(mg_connection *connection)
{
    // send header
    std::string chunk("Client\tServer\tFrom\tTo\tClientMAC\tServerMAC\tJitterCS\tCountCS\tStandardDeviationCS\tJitterSC\tCountSC\tStandardDeviationSC\tPayloadProtocol\tTotalPackets\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // send body chunks
    std::ifstream file(messyRoomPrefix + "/results", std::ios::binary);
    std::unique_ptr<char[]> readBuffer(new char[536870912]); // 512MB
    file.rdbuf()->pubsetbuf(readBuffer.get(), 536870912);
    // read first record
    Result record;
    file.read((char *) &record.head, resultHeadSize);
    while (file.gcount()) {
        // build MAC addresses
        size_t macBufferSize = record.head.macClientSize + record.head.macServerSize;
        char *macBuffer = new char[macBufferSize];
        file.read(macBuffer, macBufferSize);
        record.macClient.append(macBuffer, record.head.macClientSize);
        record.macServer.append(macBuffer + record.head.macClientSize, record.head.macServerSize);
        delete[] macBuffer;

        // write record in human readable format
        chunk
            // IP:port pairs
            .append(SuperCodex::humanReadableIp(std::string((const char *) record.head.ips, record.head.ipLength)))
            .append(':' + std::to_string(record.head.clientPort) + '\t')
            .append(SuperCodex::humanReadableIp(std::string((const char *) record.head.ips + record.head.ipLength, record.head.ipLength)))
            .append(':' + std::to_string(record.head.serverPort) + '\t')
            // timestamps
            .append(epochToIsoDate(record.head.from) + '\t')
            .append(epochToIsoDate(record.head.to) + '\t');

        // MAC addresses
        for (int i = 0, iEnd = record.head.macClientSize / 6; i < iEnd; ++i)
            chunk.append(SuperCodex::stringToHex(record.macClient.substr(i * 6, 6))).push_back(',');
        chunk[chunk.size() - 1] = '\t';
        for (int i = 0, iEnd = record.head.macServerSize / 6; i < iEnd; ++i)
            chunk.append(SuperCodex::stringToHex(record.macServer.substr(i * 6, 6))).push_back(',');
        chunk[chunk.size() - 1] = '\t';

        // observed results
        chunk.append(std::to_string(record.head.csc.average) + '\t').append(std::to_string(record.head.csc.count) + '\t').append(std::to_string(record.head.csc.standardDeviation) + '\t').append(std::to_string(record.head.scs.average) + '\t').append(std::to_string(record.head.scs.count) + '\t').append(std::to_string(record.head.scs.standardDeviation) + '\t').append(std::to_string(record.head.payloadProtocol) + '\t').append(std::to_string(record.head.totalPackets) + '\t').push_back('\n');

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
        file.read((char *) &record.head, resultHeadSize);
    }
    file.close();

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

void FeedRefinerJitter::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    // concurrently read timestamps
    auto intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, Intermediate>(codices, [&](const SuperCodex::Loader *loader) -> Intermediate {
        Intermediate intermediate;

        // load file to gather timestamps for selected sessions
        for (auto rtt = loader->firstRtt(); rtt; rtt = loader->nextRtt(rtt)) {
            auto &target = intermediate.rtts[rtt->sessionId];
            if (rtt->fromSmallToBig)
                target.fromSmallToBig.push_back(rtt->tail);
            else
                target.fromBigToSmall.push_back(rtt->tail);
        }
        for (auto packet = loader->firstPacket(); packet; packet = loader->nextPacket(packet)) {
            auto &target = intermediate.rtts[packet->sessionId];
            if (packet->fromSmallToBig) {
                target.macSmall.insert(std::string((const char *) packet->sourceMac, 6));
                target.macBig.insert(std::string((const char *) packet->destinationMac, 6));
            } else {
                target.macSmall.insert(std::string((const char *) packet->destinationMac, 6));
                target.macBig.insert(std::string((const char *) packet->sourceMac, 6));
            }
        }
        for (auto pps = loader->firstPpsPerSession(); pps; pps = loader->nextPpsPerSession(pps))
            intermediate.rtts[pps->sessionId].totalPackets += pps->fromBigToSmall + pps->fromSmallToBig;

        // gather and rearrange session information
        for (const auto &timestampPair : intermediate.rtts)
            intermediate.sessions.push_back(*loader->sessions.at(timestampPair.first));

        return intermediate;
    });

    // merge intermediates
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](const std::vector<Intermediate> intermediatesFuture) {
            // background: merge sessions
            std::thread sessionOrganizerFuture([&]() {
                for (const auto &intermediate : intermediatesFuture)
                    updateTimestampAndMergeSessions(intermediate.sessions);
            });

            for (const auto &intermediate : intermediatesFuture) {
                // merge observed data
                for (const auto &rttRecord : intermediate.rtts) {
                    auto &targetRtt = (*accumulatedRtts)[rttRecord.first];
                    targetRtt.totalPackets += rttRecord.second.totalPackets;
                    targetRtt.fromSmallToBig.reserve(targetRtt.fromSmallToBig.size() + rttRecord.second.fromSmallToBig.size());
                    targetRtt.fromBigToSmall.reserve(targetRtt.fromBigToSmall.size() + rttRecord.second.fromBigToSmall.size());
                    for (const auto &rtt : rttRecord.second.fromSmallToBig)
                        targetRtt.fromSmallToBig.push_back(rtt);
                    for (const auto &rtt : rttRecord.second.fromBigToSmall)
                        targetRtt.fromBigToSmall.push_back(rtt);
                    for (const auto &mac : rttRecord.second.macSmall)
                        targetRtt.macSmall.insert(mac);
                    for (const auto &mac : rttRecord.second.macBig)
                        targetRtt.macBig.insert(mac);
                }
            }

            // wait for session organizer to finish
            sessionOrganizerFuture.join();
        },
        intermediates);
}

void FeedRefinerJitter::finalize()
{
    // adjust client-server direction per ports from the filter
    if (!conditions.ports.empty())
        for (auto &pair : *sessions)
            if (conditions.ports.contains(pair.second.sourcePort))
                SuperCodex::swapIpPortPair(pair.second);

    // write down results to file
    std::vector<std::pair<int64_t, uint64_t>> index; // offset for /results + CSC jitter size
    index.reserve(accumulatedRtts->size());
    int64_t indexOffset = 0;
    std::ofstream resultsFile(messyRoomPrefix + "/results"s, std::ios::out | std::ios::binary | std::ios::trunc);
    std::unique_ptr<char[]> valuesFileBuffer(new char[536870912]); // 512MB
    resultsFile.rdbuf()->pubsetbuf(valuesFileBuffer.get(), 536870912);
    for (auto &pair : *accumulatedRtts) {
        // build record
        const auto &session = sessions->at(pair.first);
        // base
        Result result{{{}, SuperCodex::ipLength(session.etherType), session.sourcePort, session.destinationPort, session.first.second, session.last.second, 0, 0, {}, {}, pair.second.totalPackets, session.payloadProtocol}, {}, {}};
        // IP
        memcpy(result.head.ips, session.ips, 32);
        // statistics and MAC addresses
        if (session.sourceIsSmall) {
            result.head.csc = jitterStatistics(pair.second.fromSmallToBig);
            result.head.scs = jitterStatistics(pair.second.fromBigToSmall);
            result.macClient = convertContainer(pair.second.macSmall);
            result.macServer = convertContainer(pair.second.macBig);
        } else {
            result.head.csc = jitterStatistics(pair.second.fromBigToSmall);
            result.head.scs = jitterStatistics(pair.second.fromSmallToBig);
            result.macClient = convertContainer(pair.second.macBig);
            result.macServer = convertContainer(pair.second.macSmall);
        }
        result.head.macClientSize = result.macClient.size();
        result.head.macServerSize = result.macServer.size();

        // build index
        index.push_back(std::make_pair(indexOffset, std::max(result.head.csc.average, result.head.scs.average))); // choose whatever is "worse", whether it be csc or scs
        indexOffset += resultHeadSize + result.macClient.size() + result.macServer.size();

        // write record to file
        resultsFile.write((const char *) &result.head, resultHeadSize);
        resultsFile.write(result.macClient.data(), result.macClient.size());
        resultsFile.write(result.macServer.data(), result.macServer.size());
    }

    // save index
    std::sort(index.begin(), index.end(), [](const std::pair<int64_t, uint64_t> &a, const std::pair<int64_t, uint64_t> &b) -> bool { return a.second > b.second; });
    std::ofstream indexFile(messyRoomPrefix + "/index"s, std::ios::out | std::ios::binary | std::ios::trunc);
    indexFile.write((const char *) index.data(), indexSize * index.size());

    // clean up
    resultsFile.close();
    resultCount = accumulatedRtts->size();
    delete accumulatedRtts;
    logger.log("Results ready to serve: "s + std::to_string(resultCount));
}

FeedRefinerJitter::Result::Head::Statistics FeedRefinerJitter::jitterStatistics(const std::vector<int64_t> &rtts)
{
    Result::Head::Statistics result{};

    // calculation formula: differences of latencies. https://www.pcwdld.com/network-jitter
    if (rtts.size() > 1) {
        // build raw values
        std::vector<int64_t> values;
        values.reserve(rtts.size() - 1);
        for (int i = 1, iEnd = rtts.size(); i < iEnd; ++i) {
            if (rtts[i] > rtts[i - 1])
                values.push_back(rtts[i] - rtts[i - 1]);
            else
                values.push_back(rtts[i - 1] - rtts[i]);
        }

        // calculate average and count
        for (const auto &value : values)
            result.average += value;
        result.count = values.size();
        result.average /= result.count;

        // get standard deviation
        for (const auto &value : values) {
            int64_t raw = value - result.average;
            result.standardDeviation += raw * raw;
        }
        result.standardDeviation /= result.count;
        result.standardDeviation = sqrt(result.standardDeviation);
    }
    return result;
}

std::string FeedRefinerJitter::convertContainer(const ankerl::unordered_dense::set<std::string> &source)
{
    std::string result;
    result.reserve(source.size() * 6);
    for (const auto &item : source)
        result.append(item);
    return result;
}

FeedRefinerVoip::FeedRefinerVoip(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
    , featherSip(messyRoomPrefix + "/sip"s)
    , featherRtt(messyRoomPrefix + "/rtt"s)
    , featherSdp(messyRoomPrefix + "/sdp"s)
{
    sessions = new ankerl::unordered_dense::segmented_map<uint64_t, SuperCodex::Session>();
    logger.setLogHeader("FeedRefinerVoip"s);

    // prepare for pushing data
    // SIP
    featherSip.useWal();
    featherSip.exec("CREATE TABLE sip(timestamp BIGINT, messagetype INTEGER, raw TEXT, callid TEXT, from_ TEXT, to_ TEXT, via TEXT, cseq TEXT, fromip BLOB, toip BLOB);"s); // if message type is RESPONSE, it contains not message type but response code, which must be bigger than 100
    featherSip.prepare("INSERT INTO sip(timestamp, messagetype, raw, callid, from_, to_, via, cseq, fromip, toip) VALUES(?,?,?,?,?,?,?,?,?,?);"); // RTT is calculated at finalize()
    // SIP RTT is in separate file, since there can be more than 2 SIP packets(1 request-1 response) for given call ID
    featherRtt.useWal();
    featherRtt.exec("CREATE TABLE rtt(from_ TEXT, to_ TEXT, callid TEXT, cseq TEXT, requestmessagetype BIGINT, rtt BIGINT);"s);
    featherRtt.prepare("INSERT INTO rtt(from_, to_, callid, cseq, requestmessagetype, rtt) VALUES(?,?,?,?,?,?);");
    // SDP: there can be only one jitter per given SDP IP-port pair, though a call ID can have multiple IP-port pairs
    featherSdp.useWal();
    featherSdp.exec("CREATE TABLE sdp(sipat INTEGER, from_ TEXT, to_ TEXT, callid TEXT, isreqside INTEGER, ip BLOB, port INTEGER, peerip BLOB, peerport INTEGER, mediatype INTEGER, jitter BIGINT);"s); // sipat: the nanosecond-level timestamp of SIP protocol which contains this SDP in its body, isreqside: IP-port peer is got from request
    featherSdp.prepare("INSERT INTO sdp(sipat, from_, to_, callid, isreqside, ip, port, peerip, peerport, mediatype, jitter) VALUES(?,?,?,?,?,?,?,?,?,?,?);"s);
}

void FeedRefinerVoip::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    // prepare for documnet
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);

    // does the client ask for details?
    if (parameters.contains("mode"s) && parameters.contains("sipfrom"s) && parameters.contains("sipto"s)) {
        const std::string &mode = parameters.at("mode"s);
        if (mode == "details")
            showConversationDetails(document, parameters.at("sipfrom"s), parameters.at("sipto"s));
        else if (mode == "summary")
            showSummary(document, parameters.at("sipfrom"s), parameters.at("sipto"s));
        else
            logger.oops("Unknown mode - "s + mode);
    } else { // show From-To pairs
        // prepare for root array
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);

        // query SIP table to get list of From-To pairs
        FeatherLite sip(messyRoomPrefix + "/sip"s);
        sip.prepare("select distinct from_,to_ FROM sip ORDER BY from_;"s);
        while (sip.next() == SQLITE_ROW) {
            // prepare for JSON object
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_add_val(rootArray, object);

            // read DB table
            std::string temp;
            temp = sip.getText(0);
            yyjson_mut_obj_add_strncpy(document, object, "sipfrom", temp.data(), temp.size());
            temp = sip.getText(1);
            yyjson_mut_obj_add_strncpy(document, object, "sipto", temp.data(), temp.size());
        }
        sip.finalize();
    }

    // return result
    Civet7::respond200(connection, document);
}

void FeedRefinerVoip::showSummary(yyjson_mut_doc *document, const std::string &sipFrom, const std::string &sipTo)
{
    // prepare for database access
    FeatherLite sip(messyRoomPrefix + "/sip"s, SQLITE_OPEN_READONLY), rtt(messyRoomPrefix + "/rtt"s, SQLITE_OPEN_READONLY), sdp(messyRoomPrefix + "/sdp"s, SQLITE_OPEN_READONLY);

    // get number of responses per request
    ankerl::unordered_dense::map<int, int64_t> responses;
    rtt.prepare("SELECT requestmessagetype, count(requestmessagetype) FROM rtt WHERE from_=? AND to_=? GROUP BY requestmessagetype;");
    rtt.bindText(1, sipFrom);
    rtt.bindText(2, sipTo);
    while (rtt.next() == SQLITE_ROW)
        responses[rtt.getInt(0)] = rtt.getInt64(1);
    rtt.reset();
    rtt.finalize();

    // prepare for JSON root object
    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);

    // get data for per-action statistics
    yyjson_mut_val *actions = yyjson_mut_arr(document);
    yyjson_mut_obj_add_val(document, rootObject, "actions", actions);
    sip.prepare("SELECT messagetype, COUNT(messagetype) FROM sip WHERE from_=? AND to_=? GROUP BY messagetype;");
    sip.bindText(1, sipFrom);
    sip.bindText(2, sipTo);
    while (sip.next() == SQLITE_ROW) {
        const int type = sip.getInt(0);
        if (type < 100) { // the work should be done only when the message is request
            // initialize new object
            yyjson_mut_val *action = yyjson_mut_obj(document);
            yyjson_mut_arr_add_val(actions, action);

            // construct JSON object
            const std::string typeString = messageTypeString(static_cast<MessageType>(type));
            yyjson_mut_obj_add_strncpy(document, action, "name", typeString.data(), typeString.size());
            yyjson_mut_obj_add_int(document, action, "requests", sip.getInt64(1));
            yyjson_mut_obj_add_int(document, action, "responses", responses[type]);
        }
    }
    sip.reset();
    sip.finalize();

    // get average SIP RTT
    rtt.prepare("SELECT AVG(rtt) FROM rtt WHERE from_=? AND to_=?;");
    rtt.bindText(1, sipFrom);
    rtt.bindText(2, sipTo);
    if (rtt.next() == SQLITE_ROW)
        yyjson_mut_obj_add_int(document, rootObject, "siprtt", rtt.getInt64(0));
    else
        yyjson_mut_obj_add_int(document, rootObject, "siprtt", -1);
    rtt.reset();
    rtt.finalize();

    // get average RTP jitter
    sdp.prepare("SELECT AVG(jitter) FROM sdp WHERE from_=? AND to_=?;"s);
    sdp.bindText(1, sipFrom);
    sdp.bindText(2, sipTo);
    if (sdp.next() == SQLITE_ROW)
        yyjson_mut_obj_add_int(document, rootObject, "rtpjitter", sdp.getInt64(0));
    else
        yyjson_mut_obj_add_int(document, rootObject, "rtpjitter", -1);
    sdp.reset();
    sdp.finalize();
}

void FeedRefinerVoip::showConversationDetails(yyjson_mut_doc *&document, const std::string &sipFrom, const std::string &sipTo)
{
    // prepare for database access
    FeatherLite sip(messyRoomPrefix + "/sip"s, SQLITE_OPEN_READONLY), rtt(messyRoomPrefix + "/rtt"s, SQLITE_OPEN_READONLY), sdp(messyRoomPrefix + "/sdp"s, SQLITE_OPEN_READONLY);

    // enumerate each call ID and their corresponding timestamp of start
    std::vector<std::pair<std::string, int64_t>> callIds;
    sip.prepare("SELECT callid,min(timestamp) as start FROM sip WHERE from_=? AND to_=?;");
    sip.bindText(1, sipFrom);
    sip.bindText(2, sipTo);
    while (sip.next() == SQLITE_ROW)
        callIds.push_back(std::make_pair(std::string(sip.getText(0)), sip.getInt64(1)));
    sip.reset();
    sip.finalize();
    std::sort(callIds.begin(), callIds.end(), [](const std::pair<std::string, int64_t> &a, const std::pair<std::string, int64_t> &b) -> bool { return a.second < b.second; }); // sort is done by application(instead of DB engine) for faster execution

    // prepare for data push
    sdp.prepare("SELECT isreqside,ip,port,peerip,peerport,mediatype,jitter FROM sdp WHERE callid=? ORDER BY isreqside,ip,peerip;"s);
    sip.prepare("SELECT timestamp,messagetype,from_,to_,cseq,fromip,toip,raw FROM sip WHERE callid=? ORDER BY timestamp;"s);
    rtt.prepare("SELECT rtt FROM rtt WHERE callid=? AND cseq=?;"s);

    // build JSON
    yyjson_mut_val *rootArray = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, rootArray);
    for (const auto &pair : callIds) {
        // prepare for inner object and other variables
        const std::string &callId = pair.first;
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_add_val(rootArray, object);

        // add call ID
        yyjson_mut_obj_add_strncpy(document, object, "callid", callId.data(), callId.size());

        // check any media jitters
        yyjson_mut_val *jitters = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, object, "jitters", jitters);
        sdp.bindText(1, pair.first);
        while (sdp.next() == SQLITE_ROW) {
            // prepare for a few variables
            std::string temp;
            yyjson_mut_val *jitter = yyjson_mut_obj(document);
            yyjson_mut_arr_add_val(jitters, jitter);

            // determine whether "ip" is from request side and describe IPs accordingly
            bool ipBelongsToReqSide = sdp.getInt(0) == 1;
            if (ipBelongsToReqSide) {
                temp = SuperCodex::stringToHex(std::string(sdp.getBlob(1)));
                yyjson_mut_obj_add_strncpy(document, jitter, "ip", temp.data(), temp.size());
                temp = SuperCodex::stringToHex(std::string(sdp.getBlob(3)));
                yyjson_mut_obj_add_strncpy(document, jitter, "ip2", temp.data(), temp.size());
                yyjson_mut_obj_add_int(document, jitter, "port", sdp.getInt(2));
                yyjson_mut_obj_add_int(document, jitter, "port2", sdp.getInt(4));
                yyjson_mut_obj_add_bool(document, jitter, "fromiptoip2", false);
            } else {
                temp = SuperCodex::stringToHex(std::string(sdp.getBlob(1)));
                yyjson_mut_obj_add_strncpy(document, jitter, "ip2", temp.data(), temp.size());
                temp = SuperCodex::stringToHex(std::string(sdp.getBlob(3)));
                yyjson_mut_obj_add_strncpy(document, jitter, "ip", temp.data(), temp.size());
                yyjson_mut_obj_add_int(document, jitter, "port2", sdp.getInt(2));
                yyjson_mut_obj_add_int(document, jitter, "port", sdp.getInt(4));
                yyjson_mut_obj_add_bool(document, jitter, "fromiptoip2", true);
            }

            // set media type and jitter
            temp = mediaTypeString(static_cast<SdpMediaEndpoint::MediaType>(sdp.getInt(5)));
            yyjson_mut_obj_add_strncpy(document, jitter, "mediatype", temp.data(), temp.size());
            yyjson_mut_obj_add_int(document, jitter, "jitter", sdp.getInt64(6));
        }
        sdp.reset();

        // enumerate individual SIP communication
        yyjson_mut_val *details = yyjson_mut_arr(document);
        yyjson_mut_obj_add_val(document, object, "details", details);
        sip.bindText(1, callId);
        while (sip.next() == SQLITE_ROW) {
            // prepare for a few variables
            std::string temp;
            yyjson_mut_val *detail = yyjson_mut_obj(document);
            yyjson_mut_arr_add_val(details, detail);
            yyjson_mut_obj_add_int(document, detail, "timestamp", sip.getInt64(0));
            // distinguish request type and response code
            int type = sip.getInt(1);
            if (type >= 100) {
                // get RTT for given response
                std::string_view cseq = sip.getText(4);
                rtt.bindText(1, callId);
                rtt.bindText(2, cseq);
                if (rtt.next() == SQLITE_ROW) // this response has an RTT
                    yyjson_mut_obj_add_int(document, detail, "rtt", rtt.getInt64(0));
                rtt.reset();

                // build text for type
                temp = "RESPONSE: "s + std::to_string(type);
            } else
                temp = messageTypeString(static_cast<MessageType>(type));
            yyjson_mut_obj_add_strncpy(document, detail, "type", temp.data(), temp.size());
            temp = sip.getText(2);
            yyjson_mut_obj_add_strncpy(document, detail, "sipfrom", temp.data(), temp.size());
            temp = sip.getText(3);
            yyjson_mut_obj_add_strncpy(document, detail, "sipto", temp.data(), temp.size());
            temp = sip.getText(4);
            yyjson_mut_obj_add_strncpy(document, detail, "cseq", temp.data(), temp.size());
            temp = SuperCodex::stringToHex(std::string(sip.getBlob(5)));
            yyjson_mut_obj_add_strncpy(document, detail, "fromip", temp.data(), temp.size());
            temp = SuperCodex::stringToHex(std::string(sip.getBlob(6)));
            yyjson_mut_obj_add_strncpy(document, detail, "toip", temp.data(), temp.size());
            temp = sip.getText(7);
            yyjson_mut_obj_add_strncpy(document, detail, "raw", temp.data(), temp.size());
        }
    }
}

void FeedRefinerVoip::dumpResults(mg_connection *connection)
{
    // dump SIP and RTT
    FeatherLite sip(messyRoomPrefix + "/sip"s, SQLITE_OPEN_READONLY), rtt(messyRoomPrefix + "/rtt"s, SQLITE_OPEN_READONLY);
    sip.prepare("SELECT timestamp,messagetype,callid,from_,to_,via,cseq,fromip,toip FROM sip ORDER BY timestamp;"s);
    rtt.prepare("SELECT rtt FROM rtt WHERE callid=? AND cseq=?;"s);
    std::string chunk("[SIP]\nTimestamp\tMessage Type\tCall ID\tFrom\tTo\tVia\tCSeq\tSource IP\tDestination IP\tStatusCode\tRTT\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();
    while (sip.next() == SQLITE_ROW) {
        // timestamp
        int64_t timestampRaw = sip.getInt64(0);
        std::string timestampBelowDot = std::to_string(timestampRaw % 1000000000);
        while (timestampBelowDot.size() < 9)
            timestampBelowDot = '0' + timestampBelowDot;
        chunk.append(epochToIsoDate(timestampRaw / 1000000000) + '.' + timestampBelowDot).push_back('\t');

        // message type
        int messageTypeRaw = sip.getInt(1);
        if (messageTypeRaw >= 100)
            chunk.append("RESPONSE"s);
        else
            chunk.append(messageTypeString(static_cast<MessageType>(messageTypeRaw)));
        chunk.push_back('\t');

        // call ID, from, to, Via, CSeq, Source IP, destination IP
        chunk.append(sip.getText(2)).push_back('\t'); // call ID
        chunk.append(sip.getText(3)).push_back('\t'); // from, to
        chunk.append(sip.getText(4)).push_back('\t');
        chunk.append(sip.getText(5)).push_back('\t'); // via, cseq
        chunk.append(sip.getText(6)).push_back('\t');
        chunk.append(SuperCodex::humanReadableIp(std::string(sip.getBlob(7))) + '\t').append(SuperCodex::humanReadableIp(std::string(sip.getBlob(8))) + '\t');

        // optional: add response code and RTT if message type is RESPONSE
        if (messageTypeRaw >= 100) {
            // response code
            chunk.append(std::to_string(messageTypeRaw) + '\t');
            // RTT
            rtt.bindText(1, sip.getText(2));
            rtt.bindText(2, sip.getText(6));
            if (rtt.next() == SQLITE_ROW) // we found calculated RTT
                chunk.append(std::to_string(rtt.getInt64(0)));
            rtt.reset();
        }

        // add line ending
        chunk.push_back('\n');

        // flush chunk as needed
        if (chunk.size() > 100000000) {
            mg_send_chunk(connection, chunk.data(), chunk.size());
            chunk.clear();
        }
    }

    // SDP jitter
    FeatherLite sdp(messyRoomPrefix + "/sdp"s, SQLITE_OPEN_READONLY);
    sdp.prepare("SELECT sipat,callid,isreqside,ip,port,peerip,peerport,mediatype,jitter FROM sdp ORDER BY sipat;");
    chunk.append("\n[SDP]\nSIP At\tCall ID\tIP belongs to Request?\tRTP IP\tRTP Port\tRTP Peer IP\tRTP Peer Port\tMedia Type\tJitter\n"s);
    while (sdp.next() == SQLITE_ROW) {
        // timestamp
        int64_t timestampRaw = sip.getInt64(0);
        std::string timestampBelowDot = std::to_string(timestampRaw % 1000000000);
        while (timestampBelowDot.size() < 9)
            timestampBelowDot = '0' + timestampBelowDot;
        chunk.append(epochToIsoDate(timestampRaw / 1000000000) + '.' + timestampBelowDot).push_back('\t');

        // call ID, from request? / IP-port / peer IP-port
        chunk.append(sdp.getText(1)).push_back('\t');
        chunk
            .append(sdp.getInt(2) > 0 ? "TRUE\t"s : "FALSE\t"s) // is this RTP for request side?
            .append(SuperCodex::humanReadableIp(std::string(sdp.getBlob(3))) + '\t') // local IP-port
            .append(std::to_string(sdp.getInt(4)) + '\t')
            .append(SuperCodex::humanReadableIp(std::string(sdp.getBlob(5))) + '\t') // peer IP-port
            .append(std::to_string(sdp.getInt(6)) + '\t');

        // media type, jitter
        chunk.append(mediaTypeString(static_cast<SdpMediaEndpoint::MediaType>(sdp.getInt(7)))).push_back('\t');
        chunk.append(std::to_string(sdp.getInt64(8)));

        // add line feed
        chunk.push_back('\n');

        // flush chunk as needed
        if (chunk.size() > 100000000) {
            mg_send_chunk(connection, chunk.data(), chunk.size());
            chunk.clear();
        }
    }

    // flush final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

void FeedRefinerVoip::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    std::vector<std::vector<SipSummary>> intermediates = SuperCodex::parallel_convert<SuperCodex::Loader *, std::vector<SipSummary>>(codices, [&](const SuperCodex::Loader *codex) -> std::vector<SipSummary> {
        std::vector<SipSummary> results;

        // read and parse remarks
        for (auto remarks = codex->firstRemarks(); remarks.content; remarks = codex->nextRemarks(remarks)) {
            // determine IPs
            const auto &session = codex->sessions.at(remarks.sessionId);
            const std::string sourceIp = SuperCodex::sourceIp(*session), destinationIp = SuperCodex::destinationIp(*session);
            const auto sourceIsSmall = session->sourceIsSmall;
            // determine start and end of a SIP header
            std::string_view remarksView(remarks.content, remarks.size);

            // split SIP messages from chunk in the remarks
            int messageSize = 0;
            for (size_t index = remarksView.find("Sip="s); index != std::string_view::npos; index = remarksView.find("Sip="s, index + 24 + messageSize)) {
                std::string sipDescription = remarksValue(std::string_view(remarks.content + index, remarks.size - index), "Sip");
                if (sipDescription.empty())
                    continue;

                // determine raw message
                messageSize = std::stoi(sipDescription.substr(21)); // length of the message is written in Sip=...... section
                std::string_view rawMessage(remarks.content + index + 5 /* "Sip=" + line feed */ + sipDescription.size(), messageSize);

                // get first port of the message: either request method(REGISTER, INVITE, ......) or response header("SIP/2.0")
                size_t firstPart = rawMessage.find(' ');
                if (firstPart == std::string::npos)
                    continue; // just in case(exceptional)
                std::string_view messageStart = rawMessage.substr(0, firstPart);

                // extract some values to represent this call
                SipSummary message;
                message.callId = remarksValueHttpHeader(rawMessage, "Call-ID"s);
                if (message.callId.empty())
                    continue; // we'll skip this message - it may not be SIP at all
                // extract data from remarks chapter content
                char direction = sipDescription[0] - '0'; // 1: small to big, 0: big to small
                message.timestamp = std::stoll(sipDescription.substr(1, 19));
                message.raw = rawMessage;
                // determine IPs
                if (sourceIsSmall == direction) {
                    message.fromIp = sourceIp;
                    message.toIp = destinationIp;
                } else {
                    message.fromIp = destinationIp;
                    message.toIp = sourceIp;
                }
                // sommarize SIP header
                message.via = remarksValueHttpHeader(rawMessage, "Via"s);
                message.cseq = remarksValueHttpHeader(rawMessage, "CSeq"s);
                size_t semicolonIndex;
                message.from = remarksValueHttpHeader(rawMessage, "From"s); // remove tag and anything optional if one exists. c.f. <sip:3250@192.168.20.4:5060;transport=udp>;tag=1233456
                semicolonIndex = message.from.find(';');
                if (semicolonIndex != std::string::npos) {
                    message.from.erase(semicolonIndex);
                    if (message.from.back() != '>')
                        message.from.push_back('>');
                }
                message.to = remarksValueHttpHeader(rawMessage, "To"s); // remove tag and anything optional if one exists. c.f. <sip:3250@192.168.20.4:5060;transport=udp>;tag=1233456
                semicolonIndex = message.to.find(';');
                if (semicolonIndex != std::string::npos) {
                    message.to.erase(semicolonIndex);
                    if (message.to.back() != '>')
                        message.to.push_back('>');
                }
                // distinguish start of the message - ordered in the most frequently hit message types
                if (messageStart == "SIP/2.0"s) {
                    message.type = MessageType::RESPONSE;
                    // store response code, e.g. 200 from "SIP/2.0 200 OK" to RTT
                    const char *responseCodeStart = rawMessage.data() + firstPart + 1;
                    std::from_chars(responseCodeStart, responseCodeStart + 3, message.responseCode);
                    if (message.cseq.find("INVITE"s) != std::string::npos && rawMessage.find("\r\n\r\n"s) != std::string_view::npos)
                        refineSdp(message);
                } else if (messageStart == "OPTIONS"s)
                    message.type = MessageType::OPTIONS;
                else if (messageStart == "INVITE"s) {
                    message.type = MessageType::INVITE;
                    if (rawMessage.find("\r\n\r\n"s) != std::string_view::npos)
                        refineSdp(message);
                } else if (messageStart == "ACK"s)
                    message.type = MessageType::ACK;
                else if (messageStart == "BYE"s)
                    message.type = MessageType::BYE;
                else if (messageStart == "REGISTER"s)
                    message.type = MessageType::REGISTER;
                else if (messageStart == "UPDATE"s)
                    message.type = MessageType::UPDATE;
                else if (messageStart == "CANCEL"s)
                    message.type = MessageType::CANCEL;
                else if (messageStart == "REFER"s)
                    message.type = MessageType::REFER;
                else if (messageStart == "PRACK"s)
                    message.type = MessageType::PRACK;
                else if (messageStart == "SUBSCRIBE"s)
                    message.type = MessageType::SUBSCRIBE;
                else if (messageStart == "NOTIFY"s)
                    message.type = MessageType::NOTIFY;
                else if (messageStart == "PUBLISH"s)
                    message.type = MessageType::PUBLISH;
                else if (messageStart == "MESSAGE"s)
                    message.type = MessageType::MESSAGE;
                else if (messageStart == "INFO"s)
                    message.type = MessageType::INFO;

                // register
                results.push_back(std::move(message));
            }
        } // end: loop for reading remarks

        return results;
    });

    // extract jitter information(IP, port, call ID, ......)
    struct JitterDataWithOrigin
    {
        std::string from, to, ip;
        uint16_t port;
        JitterData data;
    };
    std::vector<JitterDataWithOrigin> jittersToFlushRequests, jittersToFlushResponses;
    for (size_t i = 0, iEnd = intermediates.size(); i < iEnd; ++i) {
        // find & update media endpoints from SDPs
        const auto &intermediate = intermediates[i];
        for (const auto &message : intermediate)
            if (message.mediaEndpoints && !message.mediaEndpoints->empty()) { // sometimes there are INVITEs or their responses without any SDP, which should be avoided
                if (message.type == INVITE && !sdpRequestsRecognized.contains(message.callId)) { // SDP from request(INVITE) side
                    for (const auto &endpoint : *message.mediaEndpoints) {
                        auto key = std::make_pair(endpoint.ip, endpoint.port);
                        if (jitterBagRequest.contains(key)) // call ID is changed = we're okay to calculate jitter
                            jittersToFlushRequests.push_back(JitterDataWithOrigin{message.from, message.to, key.first, key.second, jitterBagRequest.at(key)});
                        jitterBagRequest[key] = JitterData{endpoint.sipAt, message.from, message.to, endpoint.callId, endpoint.type, {}};
                    }
                    sdpRequestsRecognized.insert(message.callId);
                } else if (message.type == RESPONSE && !sdpResponsesRecognized.contains(message.callId)) { // SDP from response
                    for (const auto &endpoint : *message.mediaEndpoints) {
                        auto key = std::make_pair(endpoint.ip, endpoint.port);
                        if (jitterBagResponse.contains(key)) // call ID is changed = we're okay to calculate jitter
                            jittersToFlushResponses.push_back(JitterDataWithOrigin{message.from, message.to, key.first, key.second, jitterBagResponse.at(key)});
                        jitterBagResponse[key] = JitterData{endpoint.sipAt, message.from, message.to, endpoint.callId, endpoint.type, {}};
                    }
                    sdpResponsesRecognized.insert(message.callId);
                }
            }

        // update SuperCodex session list, filter only necessary RTP sessions described in SDPs, read timestamps for such sessions
        SuperCodex::Loader *loader = codices[i];
        auto newSessions = loader->allSessions();
        for (auto i = newSessions.begin(); i != newSessions.end();)
            if (i->second->payloadProtocol != 0x11) // pre-filter: the session must be UDP(0x11=17)
                i = newSessions.erase(i);
            else { // this is a UDP session
                // does destination pair belong to our target?
                auto ipPortPair = std::make_pair(SuperCodex::destinationIp(*i->second), i->second->destinationPort);
                if (jitterBagRequest.contains(ipPortPair)) {
                    i->second->sourceIsSmall = 3; // this session belongs to RTP to request side media server
                    ++i;
                    continue;
                } else if (jitterBagResponse.contains(ipPortPair)) {
                    i->second->sourceIsSmall = 4; // this session belongs to RTP to response side media server
                    ++i;
                    continue;
                } else { // desination pair doesn't belong to the media server list
                    // check whether source side pair
                    ipPortPair = std::make_pair(SuperCodex::sourceIp(*i->second), i->second->sourcePort);
                    if (jitterBagRequest.contains(ipPortPair)) {
                        logger.oops("Swap IP-port pair(request side): "s + SuperCodex::humanReadableIp(ipPortPair.first) + ':' + std::to_string(ipPortPair.second));
                        SuperCodex::swapIpPortPair(*i->second); // swap IP-port pair so that destination pair is our media server
                        i->second->sourceIsSmall = 3; // this session belongs to RTP to request side media server
                        ++i;
                        continue;
                    } else if (jitterBagResponse.contains(ipPortPair)) {
                        logger.oops("Swap IP-port pair(response side): "s + SuperCodex::humanReadableIp(ipPortPair.first) + ':' + std::to_string(ipPortPair.second));
                        SuperCodex::swapIpPortPair(*i->second); // swap IP-port pair so that destination pair is our media server
                        i->second->sourceIsSmall = 4; // this session belongs to RTP to response side media server
                        ++i;
                        continue;
                    } else // neither source pair nor destination pair belongs to the media server list
                        i = newSessions.erase(i);
                } // closing braket: desination pair doesn't belong to the media server list
            } // closing braket: this is a UDP session
        // install custom-filtered session list
        loader->sessions.swap(newSessions);

        // read RTP timestamps
        for (auto packet = loader->firstPacket(); packet; packet = loader->nextPacket(packet)) {
            const auto &session = loader->sessions.at(packet->sessionId);
            switch (session->sourceIsSmall) {
            case 3:
                jitterBagRequest[std::make_pair(SuperCodex::destinationIp(*session), session->destinationPort)].timestamps[std::make_pair(SuperCodex::sourceIp(*session), session->sourcePort)].push_back(static_cast<int64_t>(packet->second) * 1000000000 + packet->nanosecond);
                break;
            case 4:
                jitterBagResponse[std::make_pair(SuperCodex::destinationIp(*session), session->destinationPort)].timestamps[std::make_pair(SuperCodex::sourceIp(*session), session->sourcePort)].push_back(static_cast<int64_t>(packet->second) * 1000000000 + packet->nanosecond);
                break;
            default: // exception!
                logger.log("Unexpected flag: "s + std::to_string(session->sourceIsSmall) + ". From "s + std::to_string(session->id) + " at "s + loader->fileName);
                break;
            }
        }
    }

    // merge refined SIP summary(it contains full SIP header too, but well...... :P)
    if (mergeFuture.joinable())
        mergeFuture.join();
    mergeFuture = std::thread(
        [&](std::vector<std::vector<SipSummary>> intermediatesFuture, const std::vector<JitterDataWithOrigin> jittersToFlushRequestsFuture, const std::vector<JitterDataWithOrigin> jittersToFlushResponsesFuture) {
            // flush SIP
            for (const auto &intermediate : intermediatesFuture) {
                for (const auto &message : intermediate) {
                    // push data: SIP
                    featherSip.bindInt64(1, message.timestamp);
                    // if message type is RESPONSE, it contains not message type but response code, which must be bigger than 100
                    if (message.type == RESPONSE)
                        featherSip.bindInt(2, message.responseCode);
                    else
                        featherSip.bindInt(2, message.type);
                    featherSip.bindText(3, message.raw);
                    featherSip.bindText(4, message.callId);
                    featherSip.bindText(5, message.from);
                    featherSip.bindText(6, message.to);
                    featherSip.bindText(7, message.via);
                    featherSip.bindText(8, message.cseq);
                    featherSip.bindBlob(9, message.fromIp);
                    featherSip.bindBlob(10, message.toIp);
                    featherSip.next();
                    featherSip.reset();
                }
            }

            // calculate and flush jitters
            for (const auto &data : jittersToFlushRequestsFuture)
                flushRtpJitter(data.data, data.ip, data.port, 1);
            for (const auto &data : jittersToFlushResponsesFuture)
                flushRtpJitter(data.data, data.ip, data.port, 0);
        },
        std::move(intermediates),
        std::move(jittersToFlushRequests),
        std::move(jittersToFlushResponses));
}

void FeedRefinerVoip::flushRtpJitter(const JitterData &data, const std::string &ip, const uint16_t &port, const int isReqSide)
{
    // https://datatracker.ietf.org/doc/html/rfc3550 - go to latter part of page 39 or section 6.4.1 to calculate jitter
    for (const auto &pair : data.timestamps) {
        const auto &timestamps = pair.second;
        int64_t intervalsSize = timestamps.size() - 1;
        if (intervalsSize > 1) {
            // calculate intervals
            std::vector<int64_t> intervals;
            intervals.reserve(intervalsSize);
            for (int i = 0; i < intervalsSize; ++i)
                intervals.push_back(timestamps[i + 1] - timestamps[i]);

            // get average and mean deviation(=jitter)
            int64_t average = std::accumulate(intervals.begin(), intervals.end(), 0LL) / intervalsSize;
            int64_t jitter = std::accumulate(intervals.begin(), intervals.end(), 0LL, [&](const int64_t &a, const int64_t &b) { return a + (b > average ? b - average : average - b); }) / intervalsSize;

            // push jitter
            featherSdp.bindInt64(1, data.sipAt);
            featherSdp.bindText(2, data.from);
            featherSdp.bindText(3, data.to);
            featherSdp.bindText(4, data.callId);
            featherSdp.bindInt(5, isReqSide);
            featherSdp.bindBlob(6, ip);
            featherSdp.bindInt(7, port);
            featherSdp.bindBlob(8, pair.first.first);
            featherSdp.bindInt(9, pair.first.second);
            featherSdp.bindInt(10, data.type);
            featherSdp.bindInt64(11, jitter);
            featherSdp.next();
            featherSdp.reset();
        }
    }
}

void FeedRefinerVoip::finalize()
{
    // background: calculate jitters for remaining data
    std::thread flushJitterThread([&]() {
        for (const auto &pair : jitterBagRequest)
            flushRtpJitter(pair.second, pair.first.first, pair.first.second, 1);
        for (const auto &pair : jitterBagResponse)
            flushRtpJitter(pair.second, pair.first.first, pair.first.second, 0);

        // finalize prepared statement and create index
        featherSdp.finalize();
        featherSdp.exec("CREATE INDEX idxsdp1 ON sdp(callid);"s);
    });

    // finalize prepared statement and create index
    featherSip.finalize();
    featherSip.exec("CREATE INDEX idxsip1 ON sip(timestamp);"
                    "CREATE INDEX idxsip2 ON sip(callid);"
                    "CREATE INDEX idxsip3 ON sip(cseq);"
                    "CREATE INDEX idxsip4 ON sip(from_,to_);"s);

    // calculate RTT. c.f. INSERT for table "rtt" is already prepared in FeedRefinerVoip constructor
    ankerl::unordered_dense::map<std::pair<std::string, std::string>, std::pair<int64_t, int>> requestTimestamps; // <call ID + sequence number> + <timestamp for request + request message type>
    featherSip.prepare("SELECT messagetype,callid,from_,to_,cseq,timestamp FROM sip ORDER BY callid,cseq,timestamp;"s);
    while (featherSip.next() == SQLITE_ROW) {
        int messageTypeRaw = featherSip.getInt(0);
        if (messageTypeRaw >= 100) { // this is response: calculate RTT
            std::string_view callId = featherSip.getText(1), from = featherSip.getText(2), to = featherSip.getText(3), cseq = featherSip.getText(4);
            auto key = std::make_pair(std::string(callId), std::string(cseq));
            if (requestTimestamps.contains(key)) {
                const auto &targetRequest = requestTimestamps.at(key);
                // calculate RTT
                featherRtt.bindText(1, from);
                featherRtt.bindText(2, to);
                featherRtt.bindText(3, callId);
                featherRtt.bindText(4, cseq);
                featherRtt.bindInt(5, targetRequest.second);
                featherRtt.bindInt64(6, featherSip.getInt64(5) - targetRequest.first);
                featherRtt.next();
                featherRtt.reset();
                // remove used request timestamp, which is unnecessary
                requestTimestamps.erase(key);
            }
        } else if (static_cast<MessageType>(messageTypeRaw) != ACK) // register request timestamp except ACK, which doesn't have corresponding responses
            requestTimestamps[std::make_pair(std::string(featherSip.getText(1)), std::string(featherSip.getText(4)))] = std::make_pair(featherSip.getInt64(5), messageTypeRaw);
    }

    // finalize prepared statement for RTT and build indices
    featherRtt.finalize();
    featherRtt.exec("CREATE INDEX idxrtt1 ON rtt(callid,cseq);"
                    "CREATE INDEX idxrtt2 ON rtt(from_,to_);"s);

    // finalize
    flushJitterThread.join();
    logger.log("Results ready to serve"s);
}

void FeedRefinerVoip::trimRight(std::string &target)
{
    while (target.back() == '\r' || target.back() == '\n')
        target.pop_back();
}

std::vector<std::string> FeedRefinerVoip::split(const std::string &source, const char splitter)
{
    std::vector<std::string> results;
    std::istringstream reader(source);
    for (std::string part; getline(reader, part, splitter);)
        results.push_back(part);

    return results;
}

void FeedRefinerVoip::refineSdp(SipSummary &message)
{
    // check whether the raw message contains body(=SDP)
    size_t bodyStart = message.raw.find("\r\n\r\n"); // two CRLFs = blank line to separate message header and body
    if (bodyStart == std::string_view::npos)
        return;
    else
        bodyStart += 4; // skip "\r\n\r\n"

    // initialize environment
    message.mediaEndpoints = std::vector<SdpMediaEndpoint>();
    SdpMediaEndpoint::MediaType mediaType = SdpMediaEndpoint::SDPNOTDETERMINED;
    std::vector<std::string> sessionLevelIps, mediaLevelIps;
    std::vector<unsigned short> ports;
    std::function<void(const std::vector<std::string> &)> registerNewMedia = [&](const std::vector<std::string> &ips) {
        for (const auto &port : ports) {
            SdpMediaEndpoint endpoint{message.timestamp, mediaType, message.callId, {}, port};
            for (const auto &ip : ips) {
                endpoint.ip = ip;
                message.mediaEndpoints.value().push_back(endpoint);
            }
        }
    };
    bool inMediaLevel = false;

    // status
    std::string body(message.raw.substr(bodyStart));
    std::istringstream lineReader(body);
    for (std::string line; std::getline(lineReader, line, '\n');) {
        if (!line.empty()) {
            switch (line.at(0)) {
            case 'c': // connection information: nettype + addrtype + connection-address
                trimRight(line);
                if (!line.empty()) {
                    // retrieve IP information
                    auto &ips = inMediaLevel ? mediaLevelIps : sessionLevelIps;
                    if (inMediaLevel)
                        ips.clear(); // if we're in media level, previous IPs are already registered, so we don't need them anymore. c.f.) if connection information exists for both session level information and media level, media level information overrides session level information
                    std::vector<std::string> cParsed = split(line.substr(9)); // skip "c=IN IP? " where ? shall beg either 4 or 6
                    std::string ip = SuperCodex::computerReadableIp(cParsed.at(0));
                    if (ip.empty()) // exception handling: IP is in format which Spin7 cannot understand
                        logger.oops("Unexpected connection protocol(neither IPv4 nor IPv6): "s + line);
                    else {
                        if (cParsed.size() == 1) // it says single IP
                            ips.push_back(ip);
                        else {
                            // get number of addresses (we're not interesetd in TTL)
                            uint32_t numberOfAddresses = std::stoi(cParsed.back());
                            switch (ip.size()) {
                            case 4: { // IPv4
                                std::reverse(ip.begin(), ip.end());
                                uint32_t ipInNumber = *(const uint32_t *) ip.data();
                                for (uint32_t i = ipInNumber, iEnd = ipInNumber + std::stoi(cParsed.at(2)); i < iEnd; ++i) {
                                    std::string newIp((const char *) &i);
                                    std::reverse(newIp.begin(), newIp.end());
                                    ips.push_back(std::move(newIp));
                                }
                            } break;
                            case 16: { // IPv6
                                // I think it's practically impossible to manage more than millions of IP addresses for media servers
                                std::string ipPrefix = ip.substr(0, 12), ipSuffix = ip.substr(12);
                                std::reverse(ipSuffix.begin(), ipSuffix.end());
                                uint32_t suffixInNumber = *(const uint32_t *) ipSuffix.data();
                                for (uint32_t i = suffixInNumber, iEnd = suffixInNumber + std::stoi(cParsed.at(2)); i < iEnd; ++i) {
                                    std::string newSuffix((const char *) &i);
                                    std::reverse(newSuffix.begin(), newSuffix.end());
                                    ips.push_back(ipPrefix + std::move(newSuffix));
                                }
                            } break;
                            default:
                                logger.oops("Unexpected IP length: "s + std::to_string(ip.size())); // the length can be 5 or 17 considering implementation of SuperCodex::computerReadableIp() (yet still unexpected), which is actually combination of IP + netmask
                                continue;
                            }
                        }
                    }

                    // if we're in media level, register IP-port pairs for media
                    if (inMediaLevel)
                        registerNewMedia(ips);
                } else
                    logger.oops("Connection information empty");
                break;
            case 'm': { // media description(media type + port + proto + format)
                if (inMediaLevel && mediaLevelIps.empty()) // there was a previous media description without media level IPs, meaning that we need to register IP-port pairs
                    registerNewMedia(sessionLevelIps);
                trimRight(line);
                if (!line.empty()) {
                    // retrieve records
                    auto mParsed = split(line.substr(2), ' ');
                    if (mParsed.size() < 3) { // at least media + port + proto should exist
                        logger.log("Not enough elements(at least media, port, proto must be present). Raw data: "s + line);
                        continue;
                    }

                    // declare we've entered media level
                    inMediaLevel = true;

                    // determine media type
                    switch (mParsed[0].at(0)) {
                    case 'a': // audio or application
                        if (mParsed[0].at(1) == 'u')
                            mediaType = SdpMediaEndpoint::SDPAUDIO;
                        else
                            mediaType = SdpMediaEndpoint::SDPAPPLICATION;
                        break;
                    case 'v': // video
                        mediaType = SdpMediaEndpoint::SDPVIDEO;
                        break;
                    case 'c': // control
                        mediaType = SdpMediaEndpoint::SDPCONTROL;
                        break;
                    default:
                        mediaType = SdpMediaEndpoint::SDPOTHER;
                        break;
                    }

                    // enumerate ports
                    ports.clear();
                    auto portParsed = split(mParsed[1]);
                    if (portParsed.size() == 2) // there are multiple ports, e.g. 27799/3
                        for (auto i = stoi(portParsed[0]), iEnd = i + stoi(portParsed[1]); i < iEnd; ++i)
                            ports.push_back(i);
                    else
                        ports.push_back(std::stoi(portParsed[0]));
                } else
                    logger.oops("No media description"s);
            } break;
            default: // do nothing(skip)
                continue;
            }
        }
    }

    // read last line: final registration
    if (inMediaLevel && mediaLevelIps.empty() && !ports.empty()) // there was a previous media description without media level IPs, meaning that we need to register IP-port pairs
        registerNewMedia(sessionLevelIps);
}

const char *FeedRefinerVoip::messageTypeString(const MessageType type)
{
    switch (type) {
    case REGISTER:
        return "REGISTER";
        break;
    case INVITE:
        return "INVITE";
        break;
    case ACK:
        return "ACK";
        break;
    case BYE:
        return "BYE";
        break;
    case CANCEL:
        return "CANCEL";
        break;
    case UPDATE:
        return "UPDATE";
        break;
    case REFER:
        return "REFER";
        break;
    case PRACK:
        return "PRACK";
        break;
    case SUBSCRIBE:
        return "SUBSCRIBE";
        break;
    case NOTIFY:
        return "NOTIFY";
        break;
    case PUBLISH:
        return "PUBLISH";
        break;
    case MESSAGE:
        return "MESSAGE";
        break;
    case INFO:
        return "INFO";
        break;
    case OPTIONS:
        return "OPTIONS";
        break;
    case RESPONSE:
        return "RESPONSE";
        break;
    default:
        return "UNKNOWN";
        break;
    }
}

const char *FeedRefinerVoip::mediaTypeString(const SdpMediaEndpoint::MediaType type)
{
    switch (type) {
    case SdpMediaEndpoint::SDPNOTDETERMINED:
        return "No idea";
    case SdpMediaEndpoint::SDPAUDIO:
        return "Audio";
    case SdpMediaEndpoint::SDPVIDEO:
        return "Video";
    case SdpMediaEndpoint::SDPAPPLICATION:
        return "Application";
    case SdpMediaEndpoint::SDPDATA:
        return "Data";
    case SdpMediaEndpoint::SDPCONTROL:
        return "Control";
    case SdpMediaEndpoint::SDPOTHER:
        return "Other";
    }
}

FeedRefinerSessionAudit::FeedRefinerSessionAudit(const std::string messyRoomName, const SuperCodex::Conditions &conditions)
    : FeedRefinerAbstract(messyRoomName, conditions)
{
    isStreaming = true;
    logger.setLogHeader("FeedRefinerSessionAudit"s);
}

FeedRefinerSessionAudit::~FeedRefinerSessionAudit()
{
    // wait for background thread to stop
    continueBackgroundThread = false;
    buildAuditLogThread.join();
}

void FeedRefinerSessionAudit::resultsInteractive(mg_connection *connection, uint32_t from, uint32_t to, const int32_t bindValue, const ankerl::unordered_dense::map<std::string, std::string> parameters)
{
    std::shared_lock indicesLock(indicesMutex);
    const size_t indicesSize = indices.size();

    // check whether this is the request for view hint
    if (parameters.contains("type"s) && parameters.at("type"s) == "viewhint"s) {
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootObject = yyjson_mut_obj(document);
        yyjson_mut_doc_set_root(document, rootObject);
        yyjson_mut_obj_add_int(document, rootObject, "records", indicesSize);
        yyjson_mut_obj_add_bool(document, rootObject, "fully_generated", fullyGenerated);
        Civet7::respond200(connection, document);
        return;
    }

    // prepare for new JSON
    auto document = yyjson_mut_doc_new(nullptr);
    auto rootArray = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, rootArray);

    // check whether this is for session list or details
    bool hasValidSessionId = false;
    uint64_t sessionId;
    if (parameters.contains("sessionid"s))
        try {
            sessionId = std::stoull(parameters.at("sessionid"s));
            hasValidSessionId = true;
        } catch (...) {
            mg_send_http_error(connection, 400, "Failed to recognize session ID");
            return;
        }

    if (hasValidSessionId) { // send details for specific session
        // search for session
        bool foundSession = false;
        size_t sessionIndex;
        for (size_t i = 0; i < indicesSize; ++i)
            if (indices[i].sessionId == sessionId) {
                sessionIndex = i;
                foundSession = true;
                break;
            }
        if (!foundSession) {
            mg_send_http_error(connection, 404, "Session ID not found: %llu", sessionId);
            return;
        }
        const auto &session = indices[sessionIndex];

        // prepare for file containing details
        SessionEvent record{};
        std::ifstream file(messyRoomPrefix + '/' + std::to_string(session.sessionId), std::ios::binary);
        if (from) // jump to start of the requested record as needed
            file.seekg(from * sessionEventSize, std::ios::beg);

        // read records
        int i = from;
        file.read((char *) &record, sessionEventSize);
        while (file.gcount() == sessionEventSize && i < to) {
            ++i;
            // add record only if index is in boundary
            if (i >= from && i < to) {
                // prepare for inner object
                auto object = yyjson_mut_obj(document);
                yyjson_mut_arr_add_val(rootArray, object);
                yyjson_mut_obj_add_int(document, object, "second", record.second);
                yyjson_mut_obj_add_int(document, object, "nanosecond", record.nanosecond);
                yyjson_mut_obj_add_int(document, object, "value", record.value);
                yyjson_mut_obj_add_bool(document, object, "fromclienttoserver", record.direction == session.sourceIsSmall);
                std::string eventType = eventTypeString(record.type);
                yyjson_mut_obj_add_strncpy(document, object, "event", eventType.data(), eventType.size());
            }

            // read next record
            file.read((char *) &record, sessionEventSize);
        }
        file.close();
    } else { // send list of sessions
        // check index out of bound
        if (from >= indicesSize) {
            mg_send_http_error(connection, 400, "index out of bound for 'from'. Size of index: %llu", indicesSize);
            return;
        }
        std::vector<SessionIndex>::const_iterator i = indices.cbegin(), iEnd = i;
        std::advance(i, from);
        if (to >= indicesSize)
            iEnd = indices.cend();
        else
            std::advance(iEnd, to + 1);

        // start loop
        for (; i != iEnd; ++i) {
            // build session description
            std::string temp;
            auto object = yyjson_mut_obj(document);
            yyjson_mut_arr_add_val(rootArray, object);
            temp = std::to_string(i->sessionId);
            yyjson_mut_obj_add_strncpy(document, object, "sessionid", temp.data(), temp.size());
            temp = SuperCodex::stringToHex(i->sourceIp);
            yyjson_mut_obj_add_strncpy(document, object, "ip", temp.data(), temp.size());
            temp = SuperCodex::stringToHex(i->destinationIp);
            yyjson_mut_obj_add_strncpy(document, object, "ip2", temp.data(), temp.size());
            yyjson_mut_obj_add_int(document, object, "port", i->sourcePort);
            yyjson_mut_obj_add_int(document, object, "port2", i->destinationPort);
            yyjson_mut_obj_add_uint(document, object, "payloadprotocol", i->payloadProtocol);
        }
    }

    // return result
    Civet7::respond200(connection, document);
}

void FeedRefinerSessionAudit::dumpResults(mg_connection *connection)
{
    std::string chunk("IP\tPort\tIP2\tPort2\tPayloadProtocol\tSecond\tNanosecond\tValue\tFromClientToServer\tEvent\n"s);
    chunk.reserve(110000000); // 110 MB
    mg_send_chunk(connection, chunk.data(), chunk.size());
    chunk.clear();

    // send body chunks
    indicesMutex.lock_shared();
    for (const auto &index : indices) {
        // open file
        std::string prefix;
        SessionEvent record{};
        std::ifstream file(messyRoomPrefix + '/' + std::to_string(index.sessionId), std::ios::binary);

        // build session description
        prefix.append(SuperCodex::humanReadableIp(index.sourceIp) + '\t').append(std::to_string(index.sourcePort) + '\t').append(SuperCodex::humanReadableIp(index.destinationIp) + '\t').append(std::to_string(index.destinationPort) + '\t').append(std::to_string(index.payloadProtocol) + '\t');

        // read records
        file.read((char *) &record, sessionEventSize);
        while (file.gcount() == sessionEventSize) {
            chunk.append(prefix).append(std::to_string(record.second) + '\t').append(std::to_string(record.nanosecond) + '\t').append(std::to_string(record.value) + '\t').append(record.direction == index.sourceIsSmall ? "true"s : "false"s + '\t').append(eventTypeString(record.type) + '\t');
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
            file.read((char *) &record, sessionEventSize);
        }
        file.close();
    }
    indicesMutex.unlock_shared();

    // check whether the data is still in "generating" status
    if (!fullyGenerated)
        chunk.append("\nWarning: the data is NOT fully generated. There can be more data after this."s);

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

void FeedRefinerSessionAudit::processCodices(const std::vector<SuperCodex::Loader *> &codices)
{
    // do nothing for streaming mode. :P
}

void FeedRefinerSessionAudit::finalize()
{
    // start generating records in the background thread
    logger.log("Generate records"s);
    buildAuditLogThread = std::thread(
        [&](SuperCodex::Conditions conditionsToGo) {
            FeedConsumer::consumeByChunk(conditionsToGo, static_cast<SuperCodex::ChapterType>(SuperCodex::PACKETS | SuperCodex::RTTS | SuperCodex::TIMEOUTS | SuperCodex::TCPDUPACKS | SuperCodex::TCPRETRANSMISSIONS | SuperCodex::TCPMISCANOMALIES), std::thread::hardware_concurrency(), [&](std::vector<SuperCodex::Loader *> &loaders, const bool codicesEmpty) -> bool {
                // generate multiple audit logs at once
                logger.log("Audit SuperCodex files: "s + loaders.front()->fileName + " -> "s + loaders.back()->fileName);
                auto auditLogs = SuperCodex::parallel_convert<SuperCodex::Loader *, std::vector<std::pair<uint64_t, std::pair<SessionIndex, std::vector<SessionEvent>>>>>(loaders, [&](SuperCodex::Loader *loader) -> std::vector<std::pair<uint64_t, std::pair<SessionIndex, std::vector<SessionEvent>>>> { return buildAuditLog(loader); });

                // merge logs in yet another background thread
                if (mergeFuture.joinable())
                    mergeFuture.join();
                mergeFuture = std::thread(
                    [&](const std::vector<std::vector<std::pair<uint64_t, std::pair<SessionIndex, std::vector<SessionEvent>>>>> toPushFuture) {
                        for (const auto &item : toPushFuture)
                            pushAuditLog(item);
                    },
                    std::move(auditLogs));

                return continueBackgroundThread; // `continueBackgroundThread` will be set to false only when the object is about to be destroyed
            });

            // finalize
            if (mergeFuture.joinable())
                mergeFuture.join();
            fullyGenerated = true;
            if (continueBackgroundThread)
                logger.log("Job finished gracefully"s);
            else
                logger.log("Job stopped in the middle as requested"s);
        },
        conditions);

    // wait for 5 seconds
    for (int i = 0; i < 5; ++i)
        if (fullyGenerated)
            break;
        else
            std::this_thread::sleep_for(std::chrono::seconds(1));

    // log
    logger.log("Generated "s + std::to_string(indices.size()) + "initial records. Generate remaining in the background"s);
}

std::string FeedRefinerSessionAudit::eventTypeString(const SessionEvent::Type event)
{
    switch (event) {
    case SessionEvent::NOTHINGSPECIAL:
        return "Transmit"s;
    case SessionEvent::SYN:
        return "SYN"s;
    case SessionEvent::SYNACK:
        return "SYNACK"s;
    case SessionEvent::ACK:
        return "ACK"s;
    case SessionEvent::TCPZEROWINDOW:
        return "TCP Zero Window"s;
    case SessionEvent::TCPPORTREUSED:
        return "TCP Port Reused"s;
    case SessionEvent::TCPOUTOFORDER:
        return "TCP Out of Order"s;
    case SessionEvent::TCPDUPACK:
        return "TCP DUP ACK"s;
    case SessionEvent::TCPRETRANSMISSION:
        return "TCP Retransmission"s;
    case SessionEvent::TCPRST:
        return "TCP Reset";
    case SessionEvent::TCPFIN:
        return "TCP FIN";
    case SessionEvent::TIMEOUT:
        return "Timeout";
    }
}

std::vector<std::pair<uint64_t, std::pair<FeedRefinerSessionAudit::SessionIndex, std::vector<FeedRefinerSessionAudit::SessionEvent>>>> FeedRefinerSessionAudit::buildAuditLog(SuperCodex::Loader *loader)
{
    // prepare for some variables
    ankerl::unordered_dense::map<uint64_t, std::pair<SessionIndex, std::vector<SessionEvent>>> auditLogs;
    ankerl::unordered_dense::map<uint64_t, std::vector<const SuperCodex::Packet *>> normalPackets;

    // build session index and reserve rooms
    for (const auto &pair : loader->sessions) {
        auto &session = pair.second;
        normalPackets[pair.first].reserve(1000);
        auto &target = auditLogs[pair.first];
        target.first = SessionIndex{session->id, session->first.second, session->first.nanosecond, session->sourcePort, session->destinationPort, session->sourceIsSmall, session->payloadProtocol, SuperCodex::sourceIp(*session), SuperCodex::destinationIp(*session)};
        target.second.reserve(1000);
    }

    // iterate packets step 1: separate event packets and "stack" normal transmissions
    for (auto packet = loader->firstPacket(); packet; packet = loader->nextPacket(packet)) {
        const auto &session = loader->sessions.at(packet->sessionId);
        if (session->payloadProtocol == 0x06) { // this is a TCP session; we're expected to extract stuff
            // find any individual event; these packets are not concerned/counted in data transmission
            auto &eventTarget = auditLogs[packet->sessionId].second;
            if (packet->status & SuperCodex::Packet::Status::TCPSYN) { // SYN or SYNACK
                if ((packet->status & SuperCodex::Packet::Status::TCPSYNACK) == SuperCodex::Packet::Status::TCPSYNACK) // SYNACK
                    eventTarget.push_back(SessionEvent{packet->second, packet->nanosecond, packet->savedLength, SessionEvent::Type::SYNACK, packet->fromSmallToBig});
                else // SYN
                    eventTarget.push_back(SessionEvent{packet->second, packet->nanosecond, packet->savedLength, SessionEvent::Type::SYN, packet->fromSmallToBig});

                // exception handling: there can be zero window overlapping
                if (packet->status & SuperCodex::Packet::TCPZEROWINDOW)
                    eventTarget.push_back(SessionEvent{packet->second, packet->nanosecond, packet->savedLength, SessionEvent::Type::TCPZEROWINDOW, packet->fromSmallToBig});
            } else if (packet->status & SuperCodex::Packet::Status::TCPFIN) { // FIN
                eventTarget.push_back(SessionEvent{packet->second, packet->nanosecond, packet->savedLength, SessionEvent::Type::TCPFIN, packet->fromSmallToBig});

                // exception handling: there can be zero window overlapping
                if (packet->status & SuperCodex::Packet::TCPZEROWINDOW)
                    eventTarget.push_back(SessionEvent{packet->second, packet->nanosecond, packet->savedLength, SessionEvent::Type::TCPZEROWINDOW, packet->fromSmallToBig});
            } else if (packet->status & SuperCodex::Packet::Status::TCPRST) // RST
                eventTarget.push_back(SessionEvent{packet->second, packet->nanosecond, packet->savedLength, SessionEvent::Type::TCPRST, packet->fromSmallToBig});
            else if (packet->tcpWindowSize == 0) // zero window
                eventTarget.push_back(SessionEvent{packet->second, packet->nanosecond, packet->savedLength, SessionEvent::Type::TCPZEROWINDOW, packet->fromSmallToBig});
            else
                normalPackets[packet->sessionId].push_back(packet);
        } else // other than TCP(mostly UDP)
            normalPackets[packet->sessionId].push_back(packet);
    }

    // merge inter-packet events and out of order events to event log
    for (auto item = loader->firstTcpDupAck(); item; item = loader->nextTcpDupAck(item))
        auditLogs[item->sessionId].second.push_back(SessionEvent{item->second, item->nanosecond, 0, SessionEvent::Type::TCPDUPACK, item->fromSmallToBig});
    for (auto item = loader->firstTcpRetransmission(); item; item = loader->nextTcpRetransmission(item))
        auditLogs[item->sessionId].second.push_back(SessionEvent{item->second, item->nanosecond, 0, SessionEvent::Type::TCPRETRANSMISSION, item->fromSmallToBig});
    for (auto item = loader->firstTcpMiscAnomaly(); item; item = loader->nextTcpMiscAnomaly(item))
        if (item->tail == MA_TCPOUTOFORDER)
            auditLogs[item->sessionId].second.push_back(SessionEvent{item->second, item->nanosecond, 0, SessionEvent::Type::TCPOUTOFORDER, item->fromSmallToBig});

    // sort event logs
    for (auto &pair : auditLogs)
        std::sort(pair.second.second.begin(), pair.second.second.end(), [](const SessionEvent &a, const SessionEvent &b) -> bool { return SuperCodex::isPast(a.second, a.nanosecond, b.second, b.nanosecond); });

    // add timeout information in the end. timing is important; timeout occurs in the end
    for (auto timeout = loader->firstTimeout(); timeout; timeout = loader->nextTimeout(timeout)) {
        const auto sessionId = timeout->session.id;
        // register new session if session ID doesn't exist
        if (!auditLogs.contains(sessionId)) {
            const auto &session = timeout->session;
            auditLogs[sessionId].first = SessionIndex{sessionId, session.first.second, session.first.nanosecond, session.sourcePort, session.destinationPort, session.sourceIsSmall, session.payloadProtocol, SuperCodex::sourceIp(session), SuperCodex::destinationIp(session)};
        }

        // register event
        auditLogs[sessionId].second.push_back(SessionEvent{timeout->marker.second, timeout->marker.nanosecond, 0, SessionEvent::Type::TIMEOUT, -1}); // -1: direction information is not applicable
    }

    // merge normal data transmission statistics
    SessionEvent fromSmallToBig{0, 0, 0, SessionEvent::NOTHINGSPECIAL, 1}, fromBigToSmall{0, 0, 0, SessionEvent::NOTHINGSPECIAL, 0}, zero{0, 0, 0, SessionEvent::NOTHINGSPECIAL, 0};
    for (const auto &normalPair : normalPackets)
        if (!normalPair.second.empty()) { // there should be more than 1 normal packets to be merged into the events to proceed
            // prepare for cursors
            auto normalCursor = normalPair.second.cbegin(), normalCursorEnd = normalPair.second.cend();

            // push data between target event log
            auto &targetEventLog = auditLogs[normalPair.first].second;
            if (!targetEventLog.empty()) // target event log can be empty if there's no events associated(e.g. really clean TCP session, or UDP)
                for (auto i = targetEventLog.begin(); i != targetEventLog.end(); ++i)
                    if (normalCursor != normalCursorEnd && !SuperCodex::isPastOrPresent(i->second, i->nanosecond, (*normalCursor)->second, (*normalCursor)->nanosecond)) { // normalCursor is future of event log iterator
                        // initialize counters
                        fromSmallToBig = zero;
                        fromSmallToBig.direction = 1;
                        fromBigToSmall = zero;

                        // build data
                        uint32_t second = i->second, nanosecond = i->nanosecond;
                        while (normalCursor != normalCursorEnd && SuperCodex::isPast((*normalCursor)->second, (*normalCursor)->nanosecond, second, nanosecond)) {
                            // determine direction
                            auto &targetCounter = (*normalCursor)->fromSmallToBig ? fromSmallToBig : fromBigToSmall;
                            // initialize as needed
                            if (targetCounter.second == 0) {
                                targetCounter.second = (*normalCursor)->second;
                                targetCounter.nanosecond = (*normalCursor)->nanosecond;
                            }
                            // add counter, and go to next
                            targetCounter.value += (*normalCursor)->savedLength;
                            ++normalCursor;
                        }

                        // insert
                        if (fromSmallToBig.value)
                            i = targetEventLog.insert(i, fromSmallToBig);
                        if (fromBigToSmall.value)
                            i = targetEventLog.insert(i, fromBigToSmall);
                    }

            // flush remaning data
            if (normalCursor != normalCursorEnd) {
                // initialize counters
                fromSmallToBig = zero;
                fromSmallToBig.direction = 1;
                fromBigToSmall = zero;

                // build data
                while (normalCursor != normalCursorEnd) {
                    // determine direction
                    auto &targetCounter = (*normalCursor)->fromSmallToBig ? fromSmallToBig : fromBigToSmall;
                    // initialize as needed
                    if (targetCounter.second == 0) {
                        targetCounter.second = (*normalCursor)->second;
                        targetCounter.nanosecond = (*normalCursor)->nanosecond;
                    }
                    // add counter, and go to next
                    targetCounter.value += (*normalCursor)->savedLength;
                    ++normalCursor;
                }

                // push
                if (fromSmallToBig.value)
                    targetEventLog.push_back(fromSmallToBig);
                if (fromBigToSmall.value)
                    targetEventLog.push_back(fromBigToSmall);
            }
        }

    // sort event logs once again
    for (auto &pair : auditLogs)
        std::sort(pair.second.second.begin(), pair.second.second.end(), [](const SessionEvent &a, const SessionEvent &b) -> bool { return SuperCodex::isPast(a.second, a.nanosecond, b.second, b.nanosecond); });

    // return result, sorted by timestamp of startup of the time
    auto result = auditLogs.values();
    std::sort(result.begin(), result.end(), [](const std::pair<uint64_t, std::pair<SessionIndex, std::vector<SessionEvent>>> &a, const std::pair<uint64_t, std::pair<SessionIndex, std::vector<SessionEvent>>> &b) -> bool { return SuperCodex::isPast(a.second.first.second, a.second.first.nanosecond, b.second.first.second, b.second.first.nanosecond); });
    return result;
}

void FeedRefinerSessionAudit::pushAuditLog(const std::vector<std::pair<uint64_t, std::pair<SessionIndex, std::vector<SessionEvent>>>> &logs)
{
    // write down main event data
    for (const auto &pair : logs) {
        std::ofstream events(messyRoomPrefix + '/' + std::to_string(pair.first), std::ios::binary | std::ios::app);
        events.write((const char *) pair.second.second.data(), pair.second.second.size() * sessionEventSize);
        events.close();
    }

    // append new session indices
    indicesMutex.lock();
    const size_t newCapacity = indices.size() + logs.size();
    indices.reserve(newCapacity);
    savedSessionIds.reserve(newCapacity);
    for (const auto &pair : logs)
        if (!savedSessionIds.contains(pair.first)) { // check duplicate
            savedSessionIds.insert(pair.first);
            indices.push_back(pair.second.first);
        }
    indicesMutex.unlock();
}
