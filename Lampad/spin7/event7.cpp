#include "event7.h"
#include "supercache.h"
#include "supercache0.h"
#include "codexindex.h"
#include "../featherlite.h"
#include "../supercodex.h"

using namespace std::string_literals;

std::string Event7::feedPath;
std::vector<std::string> Event7::dbs = {
    "/events.tags"s,
};
std::vector<std::string> Event7::ddls = {"CREATE TABLE rows(occurredat INTEGER, severity INTEGER, datasource INTEGER, lookbackwindow INTEGER, type INTEGER, value BIGINT, threshold BIGINT, tag TEXT, description TEXT);"
                                         "CREATE INDEX idx1 ON rows(occurredat);"
                                         "CREATE INDEX idx2 ON rows(severity);"
                                         "CREATE INDEX idx3 ON rows(tag);"
                                         "CREATE TABLE bookmarks(signature BIGINT NOT NULL UNIQUE, datadump BLOB);" // for "everything", signature shall be 0
                                         "CREATE INDEX idxb1 ON bookmarks(signature);"s};
ankerl::unordered_dense::map<std::string, Event7::Description> Event7::triggers; // feed name + events parsed from JSON
Logger Event7::logger("Event7"s);

void Event7::start()
{
    logger.log("Starting Event7"s);
    auto nextCheckpoint = std::chrono::steady_clock::now() + std::chrono::hours(1);
    while (true) {
        // calculate time until next minute
        std::chrono::steady_clock::time_point nextStart = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        feedPath.clear();

        // for each data feed
        for (const auto &feed : DataFeed::describeFeeds()) {
            // initialize event generator
            feedPath = CodexIndex::feedRoot + feed.name;
            SuperCache::initializeDatabase(feedPath, dbs, ddls);
            updateTriggers(feed.name);

            // generate events and update bookmarks
            generate(feed);
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

void Event7::updateTriggers(const std::string &feedName)
{
    // prepare for variables
    auto &details = triggers[feedName];
    std::filesystem::path tagsJsonPath(feedPath + "/tags.json"s);

    if (std::filesystem::exists(tagsJsonPath) && (std::filesystem::last_write_time(tagsJsonPath) != details.lastTagsJsonUpdate)) {
        logger.log("Update triggers at "s + feedPath);
        if(std::filesystem::file_size(tagsJsonPath)==0) {
            logger.oops("Tags file size zero"s);
            return;
        }

        // update timestamp and clear previous triggers
        details.lastTagsJsonUpdate = std::filesystem::last_write_time(tagsJsonPath);
        details.triggers.clear();

        // read file
        yyjson_doc *document = yyjson_read_file(tagsJsonPath.string().data(), YYJSON_READ_NOFLAG, nullptr, nullptr);
        yyjson_val *rootObject = yyjson_doc_get_root(document);
        yyjson_val *tagName, *tagDescription;
        yyjson_obj_iter iterator = yyjson_obj_iter_with(rootObject);
        while ((tagName = yyjson_obj_iter_next(&iterator))) { // for each tag......
            tagDescription = yyjson_obj_iter_get_val(tagName);

            // check whether this tag has some event
            yyjson_val *triggers = yyjson_obj_get(tagDescription, "triggers");
            if (triggers != nullptr) { // process only tags with event triggers
                const std::string tagNameString(yyjson_get_str(tagName));

                // extract registered IPs
                std::vector<std::string> ipsBytes;
                yyjson_val *ips = yyjson_obj_get(tagDescription, "ips"), *ip;
                yyjson_arr_iter ipsIterator = yyjson_arr_iter_with(ips);

                // read(and optionally unfold) IP addresses
                SuperCodex::IpFilter filter;
                while ((ip = yyjson_arr_iter_next(&ipsIterator))) 
                    filter.registerNetwork(yyjson_get_str(ip));

                // read triggers and set the data
                yyjson_val *key, *value;
                yyjson_obj_iter iter = yyjson_obj_iter_with(triggers);
                while ((key = yyjson_obj_iter_next(&iter))) {
                    value = yyjson_obj_iter_get_val(key);
                    Description::Trigger trigger;
                    // members which can read with simple processing
                    trigger.description = yyjson_get_str(key);
                    trigger.signature = filter.signature();
                    trigger.tag = tagNameString;
                    trigger.lookbackWindow = yyjson_get_uint(yyjson_obj_getn(value, "lookbackwindowsize", 18));
                    trigger.threshold = yyjson_get_uint(yyjson_obj_getn(value, "threshold", 9));
                    // severity
                    switch (*yyjson_get_str(yyjson_obj_getn(value, "severity", 8))) {
                    case 'i': // info
                        trigger.severity = Description::Trigger::INFO;
                        break;
                    case 'w': // warning
                        trigger.severity = Description::Trigger::WARNING;
                        break;
                    case 'c': // critical
                        trigger.severity = Description::Trigger::CRITICAL;
                        break;
                    }
                    // type
                    switch (*yyjson_get_str(yyjson_obj_getn(value, "type", 4))) {
                    case 'o': // overthreshold
                        trigger.type = Description::Trigger::OVERTHRESHOLD;
                        break;
                    case 'u': // underthreshold
                        trigger.type = Description::Trigger::UNDERTHRESHOLD;
                        break;
                    case 'd': // delta
                        trigger.type = Description::Trigger::DELTA;
                        break;
                    }
                    // delta with sanity check
                    auto delta = yyjson_obj_getn(value, "delta", 5);
                    if (delta)
                        trigger.delta = yyjson_get_sint(delta);
                    if (trigger.type == Description::Trigger::DELTA && trigger.delta < 1) {
                        logger.oops("skip unaccpetable delta("s + std::to_string(trigger.delta) + ") for trigger "s + trigger.description);
                        continue;
                    }

                    // register new trigger if data source is known type
                    trigger.dataSource = determineDataSource(yyjson_get_str(yyjson_obj_getn(value, "datasource", 10)));
                    if (trigger.dataSource != SuperCodex::EVENTS)
                        details.triggers.push_back(std::move(trigger));
                    else
                        logger.oops("Unknown data source: "s + trigger.description);
                }
            }
        }
        yyjson_doc_free(document);
    }
}

void Event7::generate(const DataFeed::Description &feed)
{
    // initialize some stuff
    auto &description = triggers[feed.name];

    // prepare for database connectors
    FeatherLite featherBookmark(feedPath + dbs[0], SQLITE_OPEN_READONLY), featherReader(feedPath + SuperCache::dbs[0], SQLITE_OPEN_READONLY), featherReader0(feedPath + SuperCacheZero::dbs[0], SQLITE_OPEN_READONLY), featherWriter(feedPath + dbs[0]), bookmarkWriter(feedPath + dbs[0]);
    featherBookmark.prepare("SELECT datadump FROM bookmarks WHERE signature=?;"s);
    featherReader.prepare("SELECT value, timestamp FROM rows WHERE timestamp>? AND chapter=? ORDER BY timestamp;"s);
    featherReader0.prepare("SELECT value, timestamp FROM rows WHERE timestamp>? AND chapter=? AND signature=? ORDER BY timestamp;"s);
    bookmarkWriter.prepare("INSERT OR REPLACE INTO bookmarks(signature, datadump) VALUES(?1, ?2);"s);
    featherWriter.prepare("INSERT INTO rows(occurredat, severity, datasource, lookbackwindow, type, value, threshold, tag, description) VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ?);"s);
    std::function<void(const uint32_t, const int, const int, const int, const int, const int64_t, const int64_t, const std::string &, const std::string &)> writeRecord = [&](const uint32_t occurredAt, const int severity, const int dataSource, const int lookbackWindow, const int type, const int64_t value, const int64_t threshold, const std::string &tag, const std::string &description) {
        if (!featherWriter.bindInt(1, occurredAt))
            logger.oops("Failed to bind occurredat. Details: "s + featherWriter.lastError());
        if (!featherWriter.bindInt(2, severity))
            logger.oops("Failed to bind severity. Details: "s + featherWriter.lastError());
        if (!featherWriter.bindInt(3, dataSource))
            logger.oops("Failed to bind datasource. Details: "s + featherWriter.lastError());
        if (!featherWriter.bindInt(4, lookbackWindow))
            logger.oops("Failed to bind lookbackwindow. Details: "s + featherWriter.lastError());
        if (!featherWriter.bindInt(5, type))
            logger.oops("Failed to bind type. Details: "s + featherWriter.lastError());
        if (!featherWriter.bindInt64(6, value))
            logger.oops("Failed to bind value. Details: "s + featherWriter.lastError());
        if (!featherWriter.bindInt64(7, threshold))
            logger.oops("Failed to bind threshold. Details: "s + featherWriter.lastError());
        if (!featherWriter.bindText(8, tag))
            logger.oops("Failed to bind tag. Details: "s + featherWriter.lastError());
        if (!featherWriter.bindText(9, description))
            logger.oops("Failed to bind description. Details: "s + featherWriter.lastError());
        if (!featherWriter.next())
            logger.oops("Failed to step. Details: "s + featherWriter.lastError());
        if (!featherWriter.reset())
            logger.oops("Failed to reset. Details: "s + featherWriter.lastError());
    };

    // for each trigger......
    for (const auto &trigger : description.triggers) {
        // read bookmark
        Bookmark bookmark{};
        featherBookmark.bindInt64(1, (int64_t) trigger.signature);
        if (featherBookmark.next() == SQLITE_ROW)
            bookmark = *(const Bookmark *) featherBookmark.getBlob(0).data();
        featherBookmark.reset();
        logger.log("Trigger "s + trigger.description + " from "s + trigger.tag + '(' + std::to_string(trigger.signature) + ") after "s + std::to_string(bookmark.lastRead));

        // select database and query
        FeatherLite *feather;
        if (trigger.signature == 0) {
            feather = &featherReader;
            feather->bindInt(1, bookmark.lastRead);
            feather->bindInt(2, trigger.dataSource);
        } else {
            feather = &featherReader0;
            feather->bindInt(1, bookmark.lastRead);
            feather->bindInt(2, trigger.dataSource);
            feather->bindInt64(3, (int64_t) trigger.signature);
        }

        while (feather->next() == SQLITE_ROW) {
            logger.log("Apply "s + std::to_string(feather->getInt(1)));
            // prepare for pointers to read individual record
            const uint64_t *cursorStart = (const uint64_t *) feather->getBlob(0).data(), *cursor = cursorStart, *cursorEnd = cursorStart + 60;

            while (cursor < cursorEnd) {
                // calculate remaining number of items to accumulate
                auto stepsRemaining = trigger.lookbackWindow - bookmark.countPresent;

                // update counter
                if (cursor + stepsRemaining >= cursorEnd) { // we need more records beyond remaining ones
                    // update count
                    bookmark.countPresent += cursorEnd - cursor;

                    // add values
                    auto &sumPresent = bookmark.sumPresent;
                    while (cursor < cursorEnd) {
                        sumPresent += *cursor;
                        ++cursor;
                    }
                } else { // there are (more than) enough records to process
                    // update count
                    auto &countPresent = bookmark.countPresent;
                    countPresent += stepsRemaining;

                    // add values
                    const auto nextStop = cursor + stepsRemaining;
                    auto &sumPresent = bookmark.sumPresent;
                    while (cursor < nextStop) {
                        sumPresent += *cursor;
                        ++cursor;
                    }

                    // evaluate and generate event record as needed
                    const auto average = countPresent > 0 ? sumPresent / countPresent : 0;
                    bool push = false;
                    switch (trigger.type) {
                    case Description::Trigger::OVERTHRESHOLD:
                        push = average > trigger.threshold;
                        break;
                    case Description::Trigger::UNDERTHRESHOLD:
                        push = average < trigger.threshold;
                        break;
                    case Description::Trigger::DELTA:
                        push = bookmark.countPrevious > 0 && bookmark.countPresent > 0 && bookmark.sumPrevious / bookmark.countPrevious > trigger.threshold && sumPresent * (100 + trigger.delta) / 100 > bookmark.sumPrevious;
                        break;
                    }
                    if (push)
                        writeRecord(feather->getInt(1) + (nextStop - cursorStart), trigger.severity, trigger.dataSource, trigger.lookbackWindow, trigger.type, average, trigger.threshold, trigger.tag, trigger.description);

                    // reset counter
                    bookmark.sumPrevious = bookmark.sumPresent;
                    bookmark.countPrevious = bookmark.countPresent;
                    bookmark.sumPresent = 0;
                    bookmark.countPresent = 0;
                }
            }

            // processed all the values in the database record. update bookmark timestamp
            bookmark.lastRead = feather->getInt(1);
        }

        // save bookmark
        bookmarkWriter.bindInt64(1, (int64_t) trigger.signature);
        bookmarkWriter.bindBlob(2, &bookmark, bookmarkSize);
        bookmarkWriter.next();
        bookmarkWriter.reset();
    }
}

SuperCodex::ChapterType Event7::determineDataSource(const char *dataSource)
{
    switch (*dataSource) {
    case 'b': // bps
        return SuperCodex::ChapterType::BPSPERSESSION;
        break;
    case 'p': // pps
        return SuperCodex::ChapterType::PPSPERSESSION;
        break;
    case 'r': // rtt
        return SuperCodex::ChapterType::RTTS;
        break;
    case 't': // TCP series
        switch (dataSource[3]) {
        case 't': // tcptimeouts
            return SuperCodex::ChapterType::TIMEOUTS;
            break;
        case 'r': // tcpr......
            switch (dataSource[6]) {
            case 's': // tcprsts
                return SuperCodex::ChapterType::TCPRSTS;
                break;
            case 'r': // tcpretransmissions
                return SuperCodex::ChapterType::TCPRETRANSMISSIONS;
                break;
            }
            break;
        case 'z': // tcpzerowindows
            return static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPZEROWINDOW);
            break;
        case 'p': // tcpportreused
            return static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPPORTSREUSED);
            break;
        case 'o': // tcpoutoforders
            return static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPOUTOFORDER);
            break;
        case 'd': // tcpdupacks
            return SuperCodex::ChapterType::TCPDUPACKS;
            break;
        }
        break;
    }

    // nothing in the list
    return SuperCodex::EVENTS;
}
