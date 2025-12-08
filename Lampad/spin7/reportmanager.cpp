#include "reportmanager.h"
#include "civet7.hpp"
#include "user.h"
#include "../featherlite.h"
#include "../fnvhash.h"
#include "datafeed.h"
#include "codexindex.h"

#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <future>

using namespace std::string_literals;
// extern variables
std::shared_mutex ReportManager::reportMutex;
Logger ReportManager::logger("Report"s);

void ReportManager::start()
{
    logger.log("Starting up Report Manager");

    // create report database file if not exist
    if (!std::filesystem::exists("diagnostic.reports"s)) {
        logger.log("Initialize database for diagnostic reports"s);
        FeatherLite feather("diagnostic.reports");
        feather.useWal();
        feather.exec("CREATE TABLE reports(requestedat BIGINT, id BIGINT, user TEXT, ip TEXT, filename TEXT, options TEXT, status INTEGER, file BLOB);" // user: LAMPAD ID. IP: IP address of the user when requesting the report
                     "CREATE INDEX idxreports1 ON reports(requestedat);"
                     "CREATE INDEX idxreports2 ON reports(status);"
                     "CREATE UNIQUE INDEX idxreports3 ON reports(id);"
                     "CREATE TABLE recurring(id BIGINT, user TEXT, ip TEXT, mode INTEGER, options TEXT);" // mode: daily, weekly, monthly.  user: LAMPAD ID. IP: IP address of the user when requesting the report
                     "CREATE UNIQUE INDEX idxrecurring1 ON recurring(id);"
                     "CREATE INDEX idxrecurring2 ON recurring(mode);"s);
    }

    // if a report is tagged as WORKING, mark it as OOPS, since the job could cause Spin7 to crash
    FeatherLite feather("diagnostic.reports");
    feather.exec("UPDATE reports SET status=3 WHERE status=1;");

    // start dedicated thread for reports
    std::thread([&]() { generateReports(); }).detach();
}

void ReportManager::postReport(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check availability of required parameters
    unsigned int mode;
    uint32_t from = 0, to = UINT32_MAX;
    try {
        // check existence of data feed
        if (!parameters.contains("feed"s) || !parameters.contains("slideKeys"))
            throw "parameter feed not found";
        const std::string &feedName = parameters.at("feed"s);
        for (const auto &description : DataFeed::describeFeeds())
            if (description.name == feedName) {
                from = description.from;
                to = description.to;
                break;
            }
        if (from == 0)
            throw "unknown feed name";

        // get mode
        mode = std::stoi(parameters.at("mode"s));
        if (mode > 3)
            throw "unexpected mode value";

        // set default time offset if it's recurring job
        switch (mode) {
        case 1:
            from = -86400; // one full day
            to = 0;
            break;
        case 2:
            from = -604800; // seven full days
            to = 0;
            break;
        case 3:
            // for monthly report, the duration is first day to last day, which can be 28, 29, 30, or 31 days based on month and leap year condition
            break;
        }

        // if user set 'from' and 'to', default values are overwritten
        if (parameters.contains("from"s))
            from = std::stoul(parameters.at("from"s));
        if (parameters.contains("to"s))
            to = std::stoul(parameters.at("to"s));
    } catch (...) {
        mg_send_http_error(connection, 400, "required parameters are not found or invalid. Check 'mode', 'feed', 'from', 'to', 'slideKeys'");
        return;
    }

    // extract parameters and build report ID
    auto parametersVector = parameters.values();
    std::string civet7Tag; // dummy :P
    parametersVector.push_back(std::make_pair("Civet7Token"s, User::sessionIdFromConnection(connection, civet7Tag))); // add Civet7Token for this user so that report generator can use in authentication
    std::sort(parametersVector.begin(), parametersVector.end(), [](const std::pair<std::string, std::string> &a, const std::pair<std::string, std::string> &b) -> bool { return a.first < b.first; });
    uint32_t id = 0;
    for (const auto &pair : parametersVector)
        if (pair.first != "prefix"s) { // we ignore "prefix" parameter when we generate report ID, since the prefix doesn't change content of the report
            id = fnv32a(pair.first.data(), pair.first.size(), id);
            id = fnv32a('\t', id);
            id = fnv32a(pair.second.data(), pair.second.size(), id);
        }

    // check duplicate request
    FeatherLite feather("diagnostic.reports"s, SQLITE_OPEN_READONLY);
    if (mode == 0) {
        feather.prepare("SELECT id, user, ip, options, status, requestedat FROM reports WHERE id=?;");
        feather.bindInt64(1, id);
    } else {
        feather.prepare("SELECT id, user, ip, options FROM recurring WHERE id=?;");
        feather.bindInt64(1, id);
    }
    if (feather.next() == SQLITE_ROW) { // found already registered request
        // build response body
        nlohmann::json responseBody = nlohmann::json::parse(feather.getText(3));
        responseBody["id"s] = feather.getInt64(0);
        responseBody["username"] = feather.getText(1);
        responseBody["userip"] = feather.getText(2);
        if (mode == 0) {
            responseBody["status"s] = feather.getInt(4);
            responseBody["requestedat"s] = feather.getInt64(5);
        }
        std::string responseBodyString = responseBody.dump();

        // respond with 409 Conflict
        mg_send_http_error(connection, 409, responseBodyString.data());
        return;
    }

    // get other jobs: user ID, peer IP, and options
    User::usersMutex.lock_shared();
    const std::string username = User::usernameFromConnection(connection);
    User::usersMutex.unlock_shared();
    const std::string userIp = mg_get_request_info(connection)->remote_addr;
    std::string prefix;
    if (parameters.contains("prefix"s))
        prefix = parameters.at("prefix"s);
    nlohmann::json options;
    for (const auto &pair : parametersVector)
        options[pair.first] = pair.second;
    // 'from' and 'to' shall be saved as numbers
    options["from"s] = from;
    options["to"s] = to;
    options["mode"s] = mode;

    // register job
    if (mode == 0) { // start immediately
        try {
            std::string lastError = registerNewJob(id, mode, username, userIp, prefix, options.dump());
            if (lastError.empty())
                mg_send_http_error(connection, 204, "\r\n\r\n");
            else
                mg_send_http_error(connection, 500, "Failed to register new job. Details: %s", feather.lastError().data());
        } catch (...) {
            mg_send_http_error(connection, 500, "Failed to register new job. There may be some errors on string-to-number conversion");
            return;
        }
    } else { // register as recurring jobs
        std::lock_guard lock(reportMutex);
        FeatherLite feather("diagnostic.reports"s);
        feather.prepare("INSERT INTO recurring(id,user,ip,mode,options) VALUES(?,?,?,?,?);"s);
        feather.bindInt64(1, id);
        feather.bindText(2, username);
        feather.bindText(3, userIp);
        feather.bindInt(4, mode);
        std::string optionsString = options.dump();
        feather.bindText(5, optionsString);
        if (feather.next() == SQLITE_DONE)
            mg_send_http_error(connection, 204, "\r\n\r\n");
        else
            mg_send_http_error(connection, 500, "Failed to register new schedule. Details: %s", feather.lastError().data());
    }
}

std::string ReportManager::registerNewJob(const uint32_t id, const int mode, const std::string &username, const std::string &ip, const std::string &filenamePrefix, const std::string &options)
{
    // prepare for some stuff
    time_t now = time(nullptr);
    std::string filename = filenamePrefix;
    if (!filename.empty())
        filename.push_back('_');
    filename.append(FeedRefinerAbstract::epochToIsoDate(now, "%Y%m%d-%H%M%S"));
    switch (mode) {
    case 1:
        filename.append("_daily"s);
        break;
    case 2:
        filename.append("_weekly"s);
        break;
    case 3:
        filename.append("_monthly"s);
        break;
    }

    // push to database
    {
        std::lock_guard lock(reportMutex);
        FeatherLite feather("diagnostic.reports"s);
        if (!feather.prepare("INSERT INTO reports(requestedat,id,user,ip,filename,options,status) VALUES(?,?,?,?,?,?,0);"s))
            return feather.lastError();
        feather.bindInt64(1, now);
        feather.bindInt64(2, id);
        feather.bindText(3, username);
        feather.bindText(4, ip);
        feather.bindText(5, filename);
        feather.bindText(6, options);
        feather.bindInt(7, PENDING);

        // check whether there was an error
        if (feather.next() != SQLITE_DONE)
            return feather.lastError();
    }

    return ""s;
}

void ReportManager::registerRepeated()
{
    // get some date-time related variables
    struct tm midnight;
    const time_t now = time(nullptr);
#ifdef __linux__
    localtime_r(&now, &midnight); // Linux
#else
    localtime_s(&midnight, &now); // Windows
#endif
    midnight.tm_hour = 0;
    midnight.tm_min = 0;
    midnight.tm_sec = 0;
    time_t midnightEpoch = mktime(&midnight); // epoch time for 00:00:00 today
    size_t weekday = midnight.tm_wday; // day of week

    // enumerate reports to generate this time
    struct Pack
    {
        uint32_t id;
        std::string username, ip;
        int32_t mode;
        nlohmann::json options;
    };
    std::vector<Pack> packs;
    {
        FeatherLite feather("diagnostic.reports"s, SQLITE_OPEN_READONLY);
        feather.prepare("SELECT id,user,ip,mode,options FROM recurring;");
        while (feather.next() == SQLITE_ROW) {
            // determine whether to push this schedule to the job queue
            bool pushThis = false;
            nlohmann::json options = nlohmann::json::parse(feather.getText(4));
            switch (feather.getInt(3)) {
            // daily and weekly: check weekday
            case 1:
            case 2:
                if (options["weekdays"s].get<std::string>()[weekday] == '1') {
                    options["from"s] = midnightEpoch + options["from"s].get<int64_t>();
                    options["to"s] = midnightEpoch + options["to"s].get<int64_t>();
                    pushThis = true;
                }
                break;

            // monthly: check whether this is the first day of month
            case 3:
                if (midnight.tm_mday == 1) {
                    // "to" shall be 11:59:59 yesterday(last day of last month)
                    options["to"s] = midnightEpoch - 1;
                    pushThis = true;

                    // get epoch timestamp for 12:00:00 of 1st day of last month
                    struct tm lastMonth = midnight;
                    if (lastMonth.tm_mon == 0) { // this is January; last month shall be December of last year
                        lastMonth.tm_year -= 1;
                        lastMonth.tm_mon = 11;
                    } else
                        lastMonth.tm_mon -= 1;
                    options["from"s] = mktime(&lastMonth);
                }
                break;
            }

            // push this job to the queue as needed
            if (pushThis)
                packs.push_back(Pack{static_cast<uint32_t>(feather.getInt64(0)), std::string(feather.getText(1)), std::string(feather.getText(2)), feather.getInt(3), std::move(options)});
        }
    }

    // register new job to the queue
    for (const auto &pack : packs) {
        // prepare to build the job
        uint32_t from = pack.options["from"s].get<uint32_t>(), to = pack.options["to"s].get<uint32_t>();
        // get prefix
        std::string prefix;
        if (pack.options.contains("prefix"s))
            prefix = pack.options["prefix"s].get<std::string>();
        std::string lastError = registerNewJob(fnv32a(&to, 4, fnv32a(&from, 4, pack.id)), pack.mode, pack.username, pack.ip, prefix, pack.options.dump());
        if (!lastError.empty())
            logger.oops("Failed to register the job. Details: "s + lastError);
    }
}

void ReportManager::generateReports()
{
    while (true) {
        uint32_t id;
        std::string options, filename;
        // pop one pending job
        {
            FeatherLite feather("diagnostic.reports"s, SQLITE_OPEN_READONLY);
            feather.prepare("SELECT id,options,filename FROM reports WHERE status=0 ORDER BY requestedat LIMIT 1;"s);
            if (feather.next() == SQLITE_ROW) {
                id = feather.getInt64(0);
                options = feather.getText(1);
                filename = feather.getText(2);
                logger.log("Generate next diagnostic report: "s + std::to_string(id) + ", "s + filename);
            } else { // no job seems to be left
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
        }

        // declare start
        {
            std::lock_guard lock(reportMutex);
            FeatherLite feather("diagnostic.reports"s);
            feather.prepare("UPDATE reports SET status=1 WHERE id=?;");
            feather.bindInt64(1, id);
            feather.next();
        }

        // run application
        std::string exceptionString;
        try {
            // generate report
            logger.log("Generate report: "s + filename + ". Options are: "s + options);
            generateRawData(options, "report_raw_data.json"s);
            if (system("node static/report-generator.cjs report_raw_data.json report_result.pptx 2> node.log") != 0)
                throw "Failed to generate report file"s;
        } catch (std::exception &e) {
            exceptionString = std::string(e.what()) + '\n' + std::string(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream("node.log", std::ifstream::binary).rdbuf()).str());
            ;
        } catch (std::string &message) {
            exceptionString = message + '\n' + std::string(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream("node.log", std::ifstream::binary).rdbuf()).str());
        } catch (...) {
            exceptionString = "Details unknown";
        }

        // save report generation result
        if (exceptionString.empty()) {
            // save result to database
            std::lock_guard lock(reportMutex);
            FeatherLite feather("diagnostic.reports"s);
            feather.prepare("UPDATE reports SET status=2, file=? WHERE id=?;");
            std::string file(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream("report_result.pptx", std::ifstream::binary).rdbuf()).str());
            feather.bindBlob(1, file);
            feather.bindInt64(2, id);
            feather.next();
        } else {
            logger.oops("Failed to find generated report file. Details: "s + exceptionString + " on "s + std::to_string(id) + " <- "s + options);
            std::lock_guard lock(reportMutex);
            FeatherLite feather("diagnostic.reports"s);
            feather.prepare("UPDATE reports SET status=3, file=? WHERE id=?;");
            feather.bindText(1, exceptionString);
            feather.bindInt64(2, id);
            feather.next();
        }
    }
}

void ReportManager::getReport(mg_connection *connection, const std::string &id, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    if (id.empty()) { // enumerate saved files
        // initialize variables
        nlohmann::json responsBody;
        FeatherLite feather("diagnostic.reports"s, SQLITE_OPEN_READONLY);

        // enumerate generation queue
        auto &queue = responsBody["queue"s];
        queue = nlohmann::json::array();
        feather.prepare("SELECT requestedat, id, status, filename, options FROM reports ORDER BY requestedat DESC"s);
        while (feather.next() == SQLITE_ROW) {
            // build object to push
            nlohmann::json object;
            object["requested_at"s] = feather.getInt64(0);
            object["id"s] = feather.getInt64(1);
            switch (static_cast<Status>(feather.getInt(2))) {
            case PENDING:
                object["status"s] = "pending"s;
                break;
            case ONGOING:
                object["status"s] = "working"s;
                break;
            case REPORTGENERATED:
                object["status"s] = "done"s;
                break;
            case OOPS:
                object["status"s] = "error"s;
                break;
            }
            object["filename"s] = feather.getText(3);
            object["options"s] = nlohmann::json::parse(feather.getText(4));

            // push object
            queue.push_back(object);
        }
        feather.reset();

        // enumerate recurring jobs
        auto &recurring = responsBody["recurring"s];
        recurring = nlohmann::json::array();
        feather.prepare("SELECT id,mode,options FROM recurring ORDER BY mode DESC"s);
        while (feather.next() == SQLITE_ROW) {
            // build object to push
            nlohmann::json object;
            object["id"s] = feather.getInt64(0);
            object["mode"s] = feather.getInt(1);
            object["options"s] = nlohmann::json::parse(feather.getText(2));

            // push object
            recurring.push_back(object);
        }
        feather.reset();

        Civet7::respond200(connection, responsBody);
    } else { // download file
        FeatherLite feather("diagnostic.reports"s, SQLITE_OPEN_READONLY);
        uint32_t realId;
        try {
            realId = std::stoul(id.substr(1));
        } catch (...) {
            mg_send_http_error(connection, 400, "Failed to convert report ID. Check whether they're all numbers");
            return;
        }
        feather.prepare("SELECT status, file, filename FROM reports WHERE id=?;"s);
        feather.bindInt64(1, realId);
        if (feather.next() == SQLITE_ROW) {
            // has record: start download session
            const auto stream = feather.getBlob(1);
            std::string additionalHeader = "application/octet-stream"s;
            additionalHeader.append("\r\nContent-Disposition: attachment; filename=\""s + std::string(feather.getText(2)) + ".pptx\""s);
            Civet7::respond200(connection, stream.data(), stream.size(), additionalHeader);
        } else {
            // no record: return "file not found"
            mg_send_http_error(connection, 404, "nonexistent ID: %ul", realId);
            return;
        }
    }
}

void ReportManager::deleteReport(mg_connection *connection, const std::string &id)
{
    // initialize some stuff
    uint32_t realId;
    try {
        realId = std::stoul(id.substr(1));
    } catch (...) {
        mg_send_http_error(connection, 400, "invalid report ID");
        return;
    }

    int deletedRows = 0;
    FeatherLite feather("diagnostic.reports"s);
    // remove from reports
    feather.prepare("DELETE FROM reports WHERE id=?;");
    feather.bindInt64(1, realId);
    feather.next();
    feather.reset();
    deletedRows += feather.rowsChanged();

    // remove from recurring
    feather.prepare("DELETE FROM recurring WHERE id=?;");
    feather.bindInt64(1, realId);
    feather.next();
    feather.reset();
    deletedRows += feather.rowsChanged();

    if (deletedRows)
        mg_send_http_error(connection, 204, "\r\n\r\n");
    else
        mg_send_http_error(connection, 404, "ID found neither from queue nor schedule");
}

void ReportManager::generateRawData(const std::string &optionsString, const std::string &rawDataFileName)
{
    // prepare for stuff
    logger.log("Prepare for stuff"s);
    nlohmann::json options = nlohmann::json::parse(optionsString);
    options["slideKeys"s] = nlohmann::json::parse(options["slideKeys"].get<std::string>());
    ankerl::unordered_dense::map<std::string, std::string> parameters;
    for (const auto &pair : options.items()) {
        const auto &value = pair.value();
        if (value.is_string())
            parameters[pair.key()] = value.get<std::string>();
        else if (value.is_number())
            parameters[pair.key()] = std::to_string(value.get<uint32_t>());
        // arrays and objects are ignored(e.g. list of pages to generate)
    }
    const std::string &feedName = parameters.at("feed"s);
    SuperCodex::Conditions conditions;
    conditions.dataFeed = feedName;
    DataFeed::feeds.at(feedName)->buildSuperCodexConditions(parameters, conditions);

    // build jobs per page
    logger.log("Build jobs"s);
    // general
    std::vector<std::pair<std::string, std::future<nlohmann::json>>> synchronizer; // page name(bps, uage, pps, ......) + future
    // top N bytes
    bool buildUsage = false, buildBpsPeak = false;
    std::future<nlohmann::json> generateTopNBytesFuture;
    // TCP events
    bool buildTcpRankingsAll = false;
    std::future<nlohmann::json> synchronizerTcpTopNAll[5];
    std::array<nlohmann::json, 5> tcpTopNAll;
    std::pair<std::string, bool> tcpPagesToBuild[5] = {{"zero-windows"s, false}, {"retransmissions"s, false}, {"dup-acks"s, false}, {"resets"s, false}, {"out-of-orders"s, false}}; // page name + whether to build specific page
    for (const auto &element : options["slideKeys"]) {
        // initialize some variables
        const std::string pageType = element.get<std::string>();

        // organize what to do for given page type
        if (pageType == "bps"s)
            synchronizer.push_back(std::make_pair(pageType, std::async([&]() { return generateBps(conditions); })));
        else if (pageType == "pps"s)
            synchronizer.push_back(std::make_pair(pageType, std::async([&]() { return generatePps(conditions); })));
        else if (pageType == "icmp"s)
            synchronizer.push_back(std::make_pair(pageType, std::async([&]() { return generateIcmp(conditions); })));
        else if (pageType == "port"s)
            synchronizer.push_back(std::make_pair(pageType, std::async([&]() { return generatePort(conditions); })));
        else if (pageType == "dns"s)
            synchronizer.push_back(std::make_pair(pageType, std::async([&]() { return generateDns(conditions); })));
        else if (pageType == "http-error"s)
            synchronizer.push_back(std::make_pair(pageType, std::async([&]() { return generateHttpErrors(conditions); })));
        else if (pageType == "peak"s)
            synchronizer.push_back(std::make_pair(pageType, std::async([&]() { return generatePeak(conditions); })));

        // these two rely on Top N Bytes for base data
        else if (pageType == "usage"s) {
            buildUsage = true;
        } else if (pageType == "bps-peak"s) {
            // an exception: combination of independent page data and subset of TCP rankings
            buildTcpRankingsAll = true; // bps-peak page needs TCP rankings
            buildBpsPeak = true;
        }

        // for TCP event pages, just raise some flags(actual processing is done after the loop)
        else if (pageType == "zero-windows"s) {
            tcpPagesToBuild[0].second = true;
            buildTcpRankingsAll = true;
        } else if (pageType == "retransmissions"s) {
            tcpPagesToBuild[1].second = true;
            buildTcpRankingsAll = true;
        } else if (pageType == "dup-acks"s) {
            tcpPagesToBuild[2].second = true;
            buildTcpRankingsAll = true;
        } else if (pageType == "resets"s) {
            tcpPagesToBuild[3].second = true;
            buildTcpRankingsAll = true;
        } else if (pageType == "out-of-orders"s) {
            tcpPagesToBuild[4].second = true;
            buildTcpRankingsAll = true;
        } else
            throw "Unknown page type: "s + pageType;
    }

    // start generating Top N Bytes data as needed
    if (buildUsage || buildBpsPeak)
        generateTopNBytesFuture = std::async([&]() { return generateTopNBytes(conditions); });

    // do we need to build TCP data?
    if (buildTcpRankingsAll) {
        synchronizerTcpTopNAll[0] = std::async([&]() { return generateTcpZeroWindows(conditions); });
        synchronizerTcpTopNAll[1] = std::async([&]() { return generateTcpRetransmissions(conditions); });
        synchronizerTcpTopNAll[2] = std::async([&]() { return generateTcpDupAcks(conditions); });
        synchronizerTcpTopNAll[3] = std::async([&]() { return generateTcpResets(conditions); });
        synchronizerTcpTopNAll[4] = std::async([&]() { return generateTcpOutOfOrders(conditions); });
    }

    // generate JSON - phase 1: general
    logger.log("Generate data: phase 1"s);
    nlohmann::json result;
    for (auto &pair : synchronizer)
        result[pair.first] = pair.second.get();

    // generate JSON - phase 2: Top N Bytes
    if (buildTcpRankingsAll) { // before generating actual JSON, we need to make sure all the TCP ranking data is ready. they may be used from phase 1
        logger.log("Preprocess TCP Top N"s);
        for (size_t i = 0; i < 5; ++i)
            if (synchronizerTcpTopNAll[i].valid())
                tcpTopNAll[i] = synchronizerTcpTopNAll[i].get(); // order: TCP zero window, TCP retransmissions, TCP DUP ACKs, TCP resets, TCP out of orders
    }
    logger.log("Generate data: phase 2"s);
    if (buildUsage || buildBpsPeak) {
        // get Top N bytes ranking
        nlohmann::json topNBytes = generateTopNBytesFuture.get();

        // build pages
        if (buildUsage) {
            auto &pageRoot = result["usage"];
            // enumerate ranks up to top 100
            auto &topn = pageRoot["topn"s];
            topn = extractOnlyN(topNBytes, 100);
            topn["base"s] = "bytes"s; // do we need this? not sure
        }
        if (buildBpsPeak) {
            auto &pageRoot = result["bps-peak"s];
            // enumerate ranks up to top 5
            auto &topn = pageRoot["topn"s];
            topn = extractOnlyN(topNBytes, 5);
            topn["base"s] = "bytes"s; // do we need this? not sure

            // count number of events
            std::string ip = topn["periptoservice"s].front()["ip"s]["ip"s].get<std::string>(), ip2 = topn["periptoservice"s].front()["ip2"s]["ip"s].get<std::string>();
            pageRoot["zero-windows"s] = extractCount(ip, ip2, tcpTopNAll[0]);
            pageRoot["retransmissions"s] = extractCount(ip, ip2, tcpTopNAll[1]);
            pageRoot["dup-acks"s] = extractCount(ip, ip2, tcpTopNAll[2]);
            pageRoot["resets"s] = extractCount(ip, ip2, tcpTopNAll[3]);
            pageRoot["out-of-orders"s] = extractCount(ip, ip2, tcpTopNAll[4]);
        }
    }

    // generate JSON - phase 3: TCP specifics
    logger.log("Generate data: phase 3"s);
    for (size_t i = 0; i < 5; ++i)
        if (tcpPagesToBuild[i].second)
            result[tcpPagesToBuild[i].first] = buildTcpPage(tcpTopNAll, conditions, i);

    // write to file
    std::ofstream(rawDataFileName, std::ios::trunc) << result;
    logger.log("Generated raw data");
}

nlohmann::json ReportManager::generateBps(SuperCodex::Conditions conditions)
{
    nlohmann::json result;

    // initialize refiner
    conditions.parameters["type"s] = "bps"s;
    FeedRefinerAbstract *refiner = refine(conditions);

    // build result
    auto bindValue = (conditions.to - conditions.from) / 1000;
    if (bindValue < 1)
        bindValue = 1;
    refiner->resultsInteractive(nullptr, conditions.from, conditions.to, bindValue, {});
    result["bps"s] = fromYyjson(refiner->lastInterativeResult);
    refiner->resultsInteractive(nullptr, conditions.from, conditions.to, -1, {});
    result["minmax"s] = fromYyjson(refiner->lastInterativeResult);
    refiner->resultsInteractive(nullptr, conditions.from, conditions.to, conditions.to - conditions.from + 1, {});
    result["average"s] = fromYyjson(refiner->lastInterativeResult);

    // finalize
    delete refiner;
    return result;
}

nlohmann::json ReportManager::generatePeak(SuperCodex::Conditions conditions)
{
    nlohmann::json result;

    // pending: the final layout is not yet determined
    ////

    return result;
}

nlohmann::json ReportManager::generatePps(SuperCodex::Conditions conditions)
{
    nlohmann::json result;

    // initialize refiner
    conditions.parameters["type"s] = "pps"s;
    FeedRefinerAbstract *refiner = refine(conditions);

    // build result
    auto bindValue = (conditions.to - conditions.from) / 1000;
    if (bindValue < 1)
        bindValue = 1;
    refiner->resultsInteractive(nullptr, conditions.from, conditions.to, bindValue, {});
    result["pps"s] = fromYyjson(refiner->lastInterativeResult);
    refiner->resultsInteractive(nullptr, conditions.from, conditions.to, -1, {});
    result["minmax"s] = fromYyjson(refiner->lastInterativeResult);
    refiner->resultsInteractive(nullptr, conditions.from, conditions.to, conditions.to - conditions.from + 1, {});
    result["average"s] = fromYyjson(refiner->lastInterativeResult);

    delete refiner;
    return result;
}

nlohmann::json ReportManager::generateTopNBytes(SuperCodex::Conditions conditions)
{
    nlohmann::json result;

    // initialize refiner
    conditions.parameters["type"s] = "topn"s;
    conditions.parameters["base"s] = "bytes"s;
    FeedRefinerAbstract *refiner = refine(conditions);

    // build result
    refiner->resultsInteractive(nullptr, 0, 0, 100, {});
    result = fromYyjson(refiner->lastInterativeResult);

    delete refiner;
    return result;
}

nlohmann::json ReportManager::extractOnlyN(const nlohmann::json &source, const int maxRanking)
{
    nlohmann::json result;

    // per source
    if (source.contains("persource"s)) {
        int counter = 0;
        auto &target = result["persource"s];
        for (const auto &element : source["persource"s]) {
            target.push_back(element);
            ++counter;
            if (counter >= maxRanking)
                break;
        }
    }
    // per destination
    if (source.contains("perdestination"s)) {
        int counter = 0;
        auto &target = result["perdestination"s];
        for (const auto &element : source["perdestination"s]) {
            target.push_back(element);
            ++counter;
            if (counter >= maxRanking)
                break;
        }
    }
    // per IP-to-service
    if (source.contains("periptoservice"s)) {
        int counter = 0;
        auto &target = result["periptoservice"s];
        for (const auto &element : source["periptoservice"s]) {
            target.push_back(element);
            ++counter;
            if (counter >= maxRanking)
                break;
        }
    }

    return result;
}

nlohmann::json ReportManager::generateTcpZeroWindows(const SuperCodex::Conditions &conditions)
{
    nlohmann::json result;

    // initialize refiner
    auto conditionsAll = conditionsForAll(conditions);
    conditionsAll.parameters["type"s] = "topn"s;
    conditionsAll.parameters["base"s] = "tcpzerowindows"s;
    FeedRefinerAbstract *refiner = refine(conditionsAll);

    // build result
    refiner->resultsInteractive(nullptr, 0, 0, INT32_MAX, {});
    result = fromYyjson(refiner->lastInterativeResult);

    delete refiner;
    return result;
}

nlohmann::json ReportManager::generateTcpRetransmissions(const SuperCodex::Conditions &conditions)
{
    nlohmann::json result;

    // initialize refiner
    auto conditionsAll = conditionsForAll(conditions);
    conditionsAll.parameters["type"s] = "topn"s;
    conditionsAll.parameters["base"s] = "tcpretransmissions"s;
    FeedRefinerAbstract *refiner = refine(conditionsAll);

    // build result
    refiner->resultsInteractive(nullptr, 0, 0, INT32_MAX, {});
    result = fromYyjson(refiner->lastInterativeResult);

    delete refiner;
    return result;
}

nlohmann::json ReportManager::generateTcpDupAcks(const SuperCodex::Conditions &conditions)
{
    nlohmann::json result;

    // initialize refiner
    auto conditionsAll = conditionsForAll(conditions);
    conditionsAll.parameters["type"s] = "topn"s;
    conditionsAll.parameters["base"s] = "tcpdupacks"s;
    FeedRefinerAbstract *refiner = refine(conditionsAll);

    // build result
    refiner->resultsInteractive(nullptr, 0, 0, INT32_MAX, {});
    result = fromYyjson(refiner->lastInterativeResult);

    delete refiner;
    return result;
}

nlohmann::json ReportManager::generateTcpResets(const SuperCodex::Conditions &conditions)
{
    nlohmann::json result;

    // initialize refiner
    auto conditionsAll = conditionsForAll(conditions);
    conditionsAll.parameters["type"s] = "topn"s;
    conditionsAll.parameters["base"s] = "tcprsts"s;
    FeedRefinerAbstract *refiner = refine(conditionsAll);

    // build result
    refiner->resultsInteractive(nullptr, 0, 0, INT32_MAX, {});
    result = fromYyjson(refiner->lastInterativeResult);

    delete refiner;
    return result;
}

nlohmann::json ReportManager::generateTcpOutOfOrders(const SuperCodex::Conditions &conditions)
{
    nlohmann::json result;

    // initialize refiner
    auto conditionsAll = conditionsForAll(conditions);
    conditionsAll.parameters["type"s] = "topn"s;
    conditionsAll.parameters["base"s] = "tcpoutoforders"s;
    FeedRefinerAbstract *refiner = refine(conditionsAll);

    // build result
    refiner->resultsInteractive(nullptr, 0, 0, INT32_MAX, {});
    result = fromYyjson(refiner->lastInterativeResult);

    delete refiner;
    return result;
}

nlohmann::json ReportManager::generateIcmp(SuperCodex::Conditions conditions)
{
    nlohmann::json result;

    // initialize refiner
    conditions.parameters["type"s] = "icmpwalk"s;
    conditions.payloadProtocol = 0x01; // ICMPv4
    FeedRefinerAbstract *refiner = refine(conditions);

    // build result
    refiner->resultsInteractive(nullptr, 0, 0, INT32_MAX, {});
    result = nlohmann::json::parse(std::string_view((char *) refiner->lastInterativeResult)); // for this, lastInteractiveResult stores pointer for indexJson[0], which is a std::string

    delete refiner;
    return result;
}

nlohmann::json ReportManager::generatePort(SuperCodex::Conditions conditions)
{
    nlohmann::json result;

    // initialize refiner
    conditions.parameters["type"s] = "overview"s;
    conditions.parameters["gatherby"s] = "destination"s;
    FeedRefinerAbstract *refiner = refine(conditions);

    // build result
    refiner->resultsInteractive(nullptr, 0, 0, INT32_MAX, {});
    result = fromYyjson(refiner->lastInterativeResult);

    delete refiner;
    return result;
}

nlohmann::json ReportManager::generateDns(SuperCodex::Conditions conditions)
{
    nlohmann::json result;

    // initialize refiner
    conditions.parameters["type"s] = "dnstracker"s;
    conditions.l7Protocol = SuperCodex::Session::DNS;
    FeedRefinerAbstract *refiner = refine(conditions);

    // get DNS server IP list
    refiner->resultsInteractive(nullptr, 0, 0, INT32_MAX, {});
    auto servers = fromYyjson(refiner->lastInterativeResult);

    // request status for top 1 and 2 DNS servers
    for (size_t i = 0, iEnd = (servers.size() >= 2 ? 2 : servers.size()); i < iEnd; ++i) {
        // generate description
        std::string serverIp = servers[i].get<std::string>();
        ankerl::unordered_dense::map<std::string, std::string> parameters = {{"status"s, "resolved"s}, {"querylimit"s, "1"s}, {"server"s, serverIp}};
        refiner->resultsInteractive(nullptr, 0, 0, INT32_MAX, parameters);

        // organize data
        auto &target = result["top"s + std::to_string(i + 1)];
        target = fromYyjson(refiner->lastInterativeResult);
        target["ip"s] = serverIp;
    }

    delete refiner;
    return result;
}

nlohmann::json ReportManager::generateHttpErrors(SuperCodex::Conditions conditions)
{
    nlohmann::json result;

    // initialize refiner
    conditions.parameters["type"s] = "topn"s;
    conditions.parameters["base"s] = "httperrors"s;
    conditions.l7Protocol = SuperCodex::Session::HTTP;
    FeedRefinerAbstract *refiner = refine(conditions);

    // build result
    refiner->resultsInteractive(nullptr, 0, 0, 100, {});
    result = fromYyjson(refiner->lastInterativeResult);

    return result;
}

FeedRefinerAbstract *ReportManager::refine(SuperCodex::Conditions &conditions)
{
    // get feed refiner from conditions
    SuperCodex::ChapterType chaptersToLoad = SuperCodex::SESSIONS;
    std::string messyRoomPrefix = "diagnostic_report_"s + conditions.parameters.at("type"s);
    if (conditions.parameters.contains("base"s))
        messyRoomPrefix.append('_' + conditions.parameters.at("base"s));
    FeedRefinerAbstract *refiner = FeedConsumer::constructWorker(conditions, chaptersToLoad, messyRoomPrefix);

    // determine which SuperCodex files to read
    conditions.codicesToGo = refiner->codicesToLoad(conditions);
    refiner->conditions.codicesToGo = conditions.codicesToGo;

    // refine data
    FeedConsumer::consumeByChunk(conditions, chaptersToLoad, std::thread::hardware_concurrency() * 2, [&](std::vector<SuperCodex::Loader *> &codicesLoaded, const bool isFinal) -> bool {
        refiner->consumeCodices(codicesLoaded, isFinal);
        return true;
    });

    return refiner;
}

SuperCodex::Conditions ReportManager::conditionsForAll(const SuperCodex::Conditions &originalCondition)
{
    SuperCodex::Conditions result = originalCondition;

    // remove IP addresses, ports, and payload / layer 7 protocols only, which can be obtained from IP-to-service keys. by doing this we can ensure MPLS and VLAN filters are applied
    result.allowedIps = SuperCodex::IpFilter();
    result.ports.clear();
    result.payloadProtocol = 0;
    result.l7Protocol = SuperCodex::Session::NOL7DETECTED;

    return result;
}

nlohmann::json ReportManager::buildTcpPage(const std::array<nlohmann::json, 5> &topNForAll, const SuperCodex::Conditions &conditions, const size_t mainData)
{
    nlohmann::json result;

    // IP-to-service ranking
    result["topn"s] = extractOnlyN(generateFilteredTopN(topNForAll[mainData], conditions), 5);
    const auto &ipToService = result["topn"s]["periptoservice"s];

    // count events for top 5
    auto &otherEvents = result["other-events"s];
    otherEvents = nlohmann::json::array();
    for (const auto &object : ipToService) { // for each rank......
        // extract IPs
        const std::string ip = object["ip"s]["ip"s].get<std::string>(), ip2 = object["ip2"s]["ip"s].get<std::string>();

        // count events
        nlohmann::json objectToPush;
        if (mainData != 0)
            objectToPush["zero-windows"s] = extractCount(ip, ip2, topNForAll[0]);
        if (mainData != 1)
            objectToPush["retransmissions"s] = extractCount(ip, ip2, topNForAll[1]);
        if (mainData != 2)
            objectToPush["dup-acks"s] = extractCount(ip, ip2, topNForAll[2]);
        if (mainData != 3)
            objectToPush["resets"s] = extractCount(ip, ip2, topNForAll[3]);
        if (mainData != 4)
            objectToPush["out-or-orders"s] = extractCount(ip, ip2, topNForAll[4]);
        otherEvents.push_back(objectToPush);
    }

    // dump up to 5 individual events for up to top 3
    // detemrine which files and chapters to open
    SuperCodex::ChapterType chapterToOpen;
    uint64_t miscAnomalyTail = 0;
    switch (mainData) {
    case 0:
        chapterToOpen = SuperCodex::TCPMISCANOMALIES;
        miscAnomalyTail = MA_TCPZEROWINDOW;
        break;
    case 1:
        chapterToOpen = SuperCodex::TCPRETRANSMISSIONS;
        break;
    case 2:
        chapterToOpen = SuperCodex::TCPDUPACKS;
        break;
    case 3:
        chapterToOpen = SuperCodex::TCPRSTS;
        break;
    case 4:
        chapterToOpen = SuperCodex::TCPMISCANOMALIES;
        miscAnomalyTail = MA_TCPOUTOFORDER;
        break;
    }
    SuperCodex::Conditions conditionsForReadingEvents(conditions);
    conditionsForReadingEvents.includeExternalTransfer = false;
    conditionsForReadingEvents.codicesToGo = DataFeed::codexIndex->codices(conditionsForReadingEvents);
    // read SuperCodex
    auto &eventDumpRoot = result["event-dump"s];
    for (size_t i = 0, iEnd = (ipToService.size() < 3 ? ipToService.size() : 3); i < iEnd; ++i) {
        // extract IP addresses
        const auto &object = ipToService[i];
        SuperCodex::IpFilter ipPairToInclude;
        ipPairToInclude.registerNetwork(object["ip"s]["ip"s].get<std::string>());
        ipPairToInclude.registerNetwork(object["ip2"s]["ip"s].get<std::string>());
        conditionsForReadingEvents.allowedIps = ipPairToInclude;

        // extract and enumerate
        std::function<void(SuperCodex::Loader &)> pushData;
        size_t records = 0, maxRecords = 5; // "max records" is currently hardcoded
        auto &dumpToGo = eventDumpRoot["top"s + std::to_string(i + 1)];
        switch (chapterToOpen) {
        case SuperCodex::TCPRSTS:
            pushData = [&](SuperCodex::Loader &loader) {
                for (auto rst = loader.firstTcpRst(); rst; rst = loader.nextTcpRst(rst)) {
                    // add new object
                    nlohmann::json objectToPush;
                    objectToPush["second"s] = rst->second;
                    objectToPush["nanosecond"s] = rst->nanosecond;
                    objectToPush["fromclienttoserver"s] = rst->fromSmallToBig == loader.sessions.at(rst->sessionId)->sourceIsSmall;
                    dumpToGo.push_back(objectToPush);

                    // check counter
                    if (++records >= maxRecords)
                        return;
                }
            };
            break;
        case SuperCodex::TCPMISCANOMALIES:
            pushData = [&](SuperCodex::Loader &loader) {
                for (auto tcpMiscAnomaly = loader.firstTcpMiscAnomaly(); tcpMiscAnomaly; tcpMiscAnomaly = loader.nextTcpMiscAnomaly(tcpMiscAnomaly))
                    if (tcpMiscAnomaly->tail == miscAnomalyTail) {
                        // add new object
                        nlohmann::json objectToPush;
                        objectToPush["second"s] = tcpMiscAnomaly->second;
                        objectToPush["nanosecond"s] = tcpMiscAnomaly->nanosecond;
                        objectToPush["fromclienttoserver"s] = tcpMiscAnomaly->fromSmallToBig == loader.sessions.at(tcpMiscAnomaly->sessionId)->sourceIsSmall;
                        dumpToGo.push_back(objectToPush);

                        // check counter
                        if (++records >= maxRecords)
                            return;
                    }
            };
            break;
        case SuperCodex::TCPDUPACKS:
            pushData = [&](SuperCodex::Loader &loader) {
                for (auto tcpDupAck = loader.firstTcpDupAck(); tcpDupAck; tcpDupAck = loader.nextTcpDupAck(tcpDupAck)) {
                    // add new object
                    nlohmann::json objectToPush;
                    objectToPush["second"s] = tcpDupAck->second;
                    objectToPush["nanosecond"s] = tcpDupAck->nanosecond;
                    objectToPush["fromclienttoserver"s] = tcpDupAck->fromSmallToBig == loader.sessions.at(tcpDupAck->sessionId)->sourceIsSmall;
                    dumpToGo.push_back(objectToPush);

                    // check counter
                    if (++records >= maxRecords)
                        return;
                }
            };
            break;
        case SuperCodex::TCPRETRANSMISSIONS:
            pushData = [&](SuperCodex::Loader &loader) {
                for (auto tcpRetransmission = loader.firstTcpRetransmission(); tcpRetransmission; tcpRetransmission = loader.nextTcpRetransmission(tcpRetransmission)) {
                    // add new object
                    nlohmann::json objectToPush;
                    objectToPush["second"s] = tcpRetransmission->second;
                    objectToPush["nanosecond"s] = tcpRetransmission->nanosecond;
                    objectToPush["fromclienttoserver"s] = tcpRetransmission->fromSmallToBig == loader.sessions.at(tcpRetransmission->sessionId)->sourceIsSmall;
                    dumpToGo.push_back(objectToPush);

                    // check counter
                    if (++records >= maxRecords)
                        return;
                }
            };
            break;
        default:
            pushData = [&](SuperCodex::Loader &loader) {
                records = UINT64_MAX;
                logger.oops("No instruction for given chapter: "s + std::to_string(chapterToOpen));
            };
            break;
        }

        // build result
        auto conditions2 = conditions;
        for (const auto &file : DataFeed::codexIndex->codices(conditions2)) {
            SuperCodex::Loader loader(file, chapterToOpen, conditions2);
            pushData(loader);
            if (records >= maxRecords)
                break;
        }
    }

    return result;
}

nlohmann::json ReportManager::generateFilteredTopN(const nlohmann::json &topNForAll, const SuperCodex::Conditions &conditions)
{
    // exception handling: nothing to filter
    if (conditions.allowedIps.isEmpty && conditions.ports.empty() && conditions.payloadProtocol == 0 && conditions.l7Protocol == SuperCodex::Session::NOL7DETECTED)
        return topNForAll;

    // start main job
    nlohmann::json result;

    // filter IP-to-service
    const auto &allowedIps = conditions.allowedIps;
    const bool includeExternalTransfer = conditions.includeExternalTransfer;
    nlohmann::json &perIpToService = result["periptoservice"s];
    for (const auto &object : topNForAll["periptoservice"s]) {
        // some shortcuts for object
        const auto &ip = object["ip"s], &ip2 = object["ip2"s];

        // IP
        if (!allowedIps.isEmpty && // if there's no IP filter, wo don't have to concern this
            ((!includeExternalTransfer && !allowedIps.contains(ip2["ip"s].get<std::string>()) && !allowedIps.contains(ip["ip"s].get<std::string>())) || // neither IP address is in the filter list
             (includeExternalTransfer && (!allowedIps.contains(ip2["ip"s].get<std::string>()) || !allowedIps.contains(ip["ip"s].get<std::string>()))) // either one of two is not in the list
             ))
            continue;

        // port
        const auto &ports = conditions.ports;
        if (!ports.empty()) {
            uint16_t port = 0, port2 = 0;
            if (ip.contains("port"s))
                port = ip["port"s].get<uint16_t>();
            if (ip2.contains("port"s))
                port2 = ip2["port"s].get<uint16_t>();
            if (port2 && ports.contains(port2))
                goto PayloadProtocol;
            if (port && ports.contains(port))
                goto PayloadProtocol;
            continue;
        }

    PayloadProtocol:
        // payload protocol
        if (conditions.payloadProtocol != 0) {
            const std::string payloadProtocol = object["payloadprotocol"s].get<std::string>();
            if (payloadProtocol == "tcp"s && conditions.payloadProtocol != 6)
                continue;
            else if (payloadProtocol == "udp"s && conditions.payloadProtocol != 17)
                continue;
        }

        // L7 protocol
        if (conditions.l7Protocol != SuperCodex::Session::NOL7DETECTED) {
            const std::string l7Protocol = object["l7protocol"].get<std::string>();
            if (l7Protocol == "TLS"s && conditions.l7Protocol != SuperCodex::Session::TLS)
                continue;
            else if (l7Protocol == "DNS"s && conditions.l7Protocol != SuperCodex::Session::DNS)
                continue;
            else if (l7Protocol == "HTTP"s && conditions.l7Protocol != SuperCodex::Session::HTTP)
                continue;
            else if (l7Protocol == "FTP"s && conditions.l7Protocol != SuperCodex::Session::FTP)
                continue;
            else if (l7Protocol == "SMTP"s && conditions.l7Protocol != SuperCodex::Session::SMTP)
                continue;
            else if (l7Protocol == "IMAP"s && conditions.l7Protocol != SuperCodex::Session::IMAP)
                continue;
            else if (l7Protocol == "POP3"s && conditions.l7Protocol != SuperCodex::Session::POP3)
                continue;
            else if (l7Protocol == "RTP"s && conditions.l7Protocol != SuperCodex::Session::RTP)
                continue;
            else if (l7Protocol == "RTCP"s && conditions.l7Protocol != SuperCodex::Session::RTCP)
                continue;
            else if (l7Protocol == "RTSP"s && conditions.l7Protocol != SuperCodex::Session::RTSP)
                continue;
            else if (l7Protocol == "SIP"s && conditions.l7Protocol != SuperCodex::Session::SIP)
                continue;
        }

        // register chosen object
        perIpToService.push_back(object);
    }

    // per-source and per-desitnation is not implemented, since they're not used in the report
    ////

    return result;
}

uint64_t ReportManager::extractCount(const std::string &ip, const std::string &ip2, const nlohmann::json &tcpTopNAll)
{
    uint64_t result = 0;
    if (!tcpTopNAll.is_null())
        for (const auto &object : tcpTopNAll["periptoservice"s])
            if ((object["ip"s]["ip"] == ip && object["ip2"s]["ip"] == ip2) || (object["ip2"s]["ip"] == ip && object["ip"s]["ip"] == ip2))
                result += object["value"s].get<uint64_t>();

    return result;
}

nlohmann::json ReportManager::fromYyjson(yyjson_mut_doc *document)
{
    nlohmann::json result;

    size_t size;
    yyjson_write_err parserError;
    char *resultRaw = yyjson_mut_write_opts(document, YYJSON_WRITE_ALLOW_INVALID_UNICODE, nullptr, &size, &parserError);
    if (size == 0)
        logger.log("Zero(0) size result. JSON parser error: "s + parserError.msg);
    else
        result = nlohmann::json::parse(std::string_view(resultRaw, size));
    free(resultRaw);
    yyjson_mut_doc_free(document);

    return result;
}
