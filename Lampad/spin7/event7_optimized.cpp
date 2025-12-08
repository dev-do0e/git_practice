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
                                         "CREATE TABLE bookmarks(signature BIGINT NOT NULL UNIQUE, datadump BLOB);" // "everything"을 위한 것, signature는 0이어야 함
                                         "CREATE INDEX idxb1 ON bookmarks(signature);"s};
ankerl::unordered_dense::map<std::string, Event7::Description> Event7::triggers; // 피드 이름 + JSON에서 파싱된 이벤트들
Logger Event7::logger("Event7"s);

// 최적화: 파일 읽기 헬퍼 함수
inline std::string readFileToString(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return "";
    }
    
    const auto fileSize = file.tellg();
    if (fileSize <= 0) {
        return "";
    }
    
    std::string buffer;
    buffer.resize(static_cast<size_t>(fileSize));
    
    file.seekg(0);
    file.read(&buffer[0], fileSize);
    return buffer;
}

// 최적화: 문자열 비교 최적화
inline bool startsWith(const std::string& str, const char* prefix) {
    return str.compare(0, strlen(prefix), prefix) == 0;
}

void Event7::start()
{
    logger.log("Starting Event7"s);
    auto nextCheckpoint = std::chrono::steady_clock::now() + std::chrono::hours(1);
    
    // 최적화: 피드 목록을 미리 캐시
    std::vector<DataFeed::Description> cachedFeeds;
    
    while (true) {
        // 다음 분까지의 시간 계산
        std::chrono::steady_clock::time_point nextStart = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        feedPath.clear();

        // 최적화: 피드 목록을 한 번만 가져오기
        if (cachedFeeds.empty()) {
            cachedFeeds = DataFeed::describeFeeds();
        }

        // 각 데이터 피드에 대해
        for (const auto &feed : cachedFeeds) {
            // 이벤트 생성기 초기화
            feedPath = CodexIndex::feedRoot + feed.name;
            SuperCache::initializeDatabase(feedPath, dbs, ddls);
            updateTriggers(feed.name);

            // 이벤트 생성 및 북마크 업데이트
            generate(feed);
        }

        // 정리 및 마무리
        if (std::chrono::steady_clock::now() >= nextCheckpoint) { // 다음 기간(현재 1시간마다)
            // 데이터베이스 체크포인트 및 너무 오래된 레코드 제거
            SuperCache::checkpointDatabase(dbs);
            nextCheckpoint = std::chrono::steady_clock::now() + std::chrono::hours(1);
            
            // 최적화: 피드 목록 캐시 갱신
            cachedFeeds.clear();
        }
        std::this_thread::sleep_until(nextStart);
    }
}

void Event7::updateTriggers(const std::string &feedName)
{
    // 변수 준비
    auto &details = triggers[feedName];
    std::filesystem::path tagsJsonPath(feedPath + "/tags.json"s);

    if (std::filesystem::exists(tagsJsonPath) && (std::filesystem::last_write_time(tagsJsonPath) != details.lastTagsJsonUpdate)) {
        logger.log("Update triggers at "s + feedPath);
        
        const auto fileSize = std::filesystem::file_size(tagsJsonPath);
        if(fileSize == 0) {
            logger.oops("Tags file size zero"s);
            return;
        }

        // 타임스탬프 업데이트 및 이전 트리거들 정리
        details.lastTagsJsonUpdate = std::filesystem::last_write_time(tagsJsonPath);
        details.triggers.clear();
        details.triggers.reserve(100); // 최적화: 예상 크기로 미리 할당

        // 최적화: 효율적인 파일 읽기
        std::string fileContent = readFileToString(tagsJsonPath.string());
        if (fileContent.empty()) {
            logger.oops("Failed to read tags file"s);
            return;
        }

        // 파일 읽기
        yyjson_doc *document = yyjson_read(fileContent.data(), fileContent.size(), YYJSON_READ_NOFLAG);
        if (!document) {
            logger.oops("Failed to parse JSON"s);
            return;
        }
        
        yyjson_val *rootObject = yyjson_doc_get_root(document);
        if (!yyjson_is_obj(rootObject)) {
            yyjson_doc_free(document);
            return;
        }
        
        yyjson_val *tagName, *tagDescription;
        yyjson_obj_iter iterator = yyjson_obj_iter_with(rootObject);
        
        // 최적화: 상수 문자열 미리 정의
        const char* severityKey = "severity";
        const char* typeKey = "type";
        const char* datasourceKey = "datasource";
        const char* lookbackwindowsizeKey = "lookbackwindowsize";
        const char* thresholdKey = "threshold";
        const char* deltaKey = "delta";
        const char* triggersKey = "triggers";
        const char* ipsKey = "ips";
        
        while ((tagName = yyjson_obj_iter_next(&iterator))) { // 각 태그에 대해......
            tagDescription = yyjson_obj_iter_get_val(tagName);

            // 이 태그가 이벤트를 가지고 있는지 확인
            yyjson_val *triggers = yyjson_obj_get(tagDescription, triggersKey);
            if (triggers != nullptr) { // 이벤트 트리거가 있는 태그만 처리
                const std::string tagNameString(yyjson_get_str(tagName));

                // 등록된 IP들 추출
                yyjson_val *ips = yyjson_obj_get(tagDescription, ipsKey);
                if (!ips || !yyjson_is_arr(ips)) {
                    continue;
                }

                // IP 주소들 읽기(선택적으로 펼치기)
                SuperCodex::IpFilter filter;
                yyjson_val *ip;
                yyjson_arr_iter ipsIterator = yyjson_arr_iter_with(ips);
                while ((ip = yyjson_arr_iter_next(&ipsIterator))) {
                    filter.registerNetwork(yyjson_get_str(ip));
                }

                // 트리거들 읽기 및 데이터 설정
                yyjson_val *key, *value;
                yyjson_obj_iter iter = yyjson_obj_iter_with(triggers);
                while ((key = yyjson_obj_iter_next(&iter))) {
                    value = yyjson_obj_iter_get_val(key);
                    Description::Trigger trigger;
                    
                    // 간단한 처리로 읽을 수 있는 멤버들
                    trigger.description = yyjson_get_str(key);
                    trigger.signature = filter.signature();
                    trigger.tag = tagNameString;
                    trigger.lookbackWindow = yyjson_get_uint(yyjson_obj_getn(value, lookbackwindowsizeKey, 18));
                    trigger.threshold = yyjson_get_uint(yyjson_obj_getn(value, thresholdKey, 9));
                    
                    // 최적화: severity 파싱 최적화
                    yyjson_val* severityVal = yyjson_obj_getn(value, severityKey, 8);
                    if (severityVal) {
                        const char* severityStr = yyjson_get_str(severityVal);
                        if (severityStr) {
                            switch (severityStr[0]) {
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
                        }
                    }
                    
                    // 최적화: type 파싱 최적화
                    yyjson_val* typeVal = yyjson_obj_getn(value, typeKey, 4);
                    if (typeVal) {
                        const char* typeStr = yyjson_get_str(typeVal);
                        if (typeStr) {
                            switch (typeStr[0]) {
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
                        }
                    }
                    
                    // delta 유효성 검사
                    auto delta = yyjson_obj_getn(value, deltaKey, 5);
                    if (delta)
                        trigger.delta = yyjson_get_sint(delta);
                    if (trigger.type == Description::Trigger::DELTA && trigger.delta < 1) {
                        logger.oops("skip unaccpetable delta("s + std::to_string(trigger.delta) + ") for trigger "s + trigger.description);
                        continue;
                    }

                    // 데이터 소스가 알려진 타입인 경우 새 트리거 등록
                    yyjson_val* datasourceVal = yyjson_obj_getn(value, datasourceKey, 10);
                    if (datasourceVal) {
                        trigger.dataSource = determineDataSource(yyjson_get_str(datasourceVal));
                        if (trigger.dataSource != SuperCodex::EVENTS)
                            details.triggers.push_back(std::move(trigger));
                        else
                            logger.oops("Unknown data source: "s + trigger.description);
                    }
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
    FeatherLite featherBookmark(feedPath + dbs[0], SQLITE_OPEN_READONLY), 
                featherReader(feedPath + SuperCache::dbs[0], SQLITE_OPEN_READONLY), 
                featherReader0(feedPath + SuperCacheZero::dbs[0], SQLITE_OPEN_READONLY), 
                featherWriter(feedPath + dbs[0]), 
                bookmarkWriter(feedPath + dbs[0]);
    
    // 최적화: prepared statement 미리 준비
    featherBookmark.prepare("SELECT datadump FROM bookmarks WHERE signature=?;"s);
    featherReader.prepare("SELECT value, timestamp FROM rows WHERE timestamp>? AND chapter=? ORDER BY timestamp;"s);
    featherReader0.prepare("SELECT value, timestamp FROM rows WHERE timestamp>? AND chapter=? AND signature=? ORDER BY timestamp;"s);
    bookmarkWriter.prepare("INSERT OR REPLACE INTO bookmarks(signature, datadump) VALUES(?1, ?2);"s);
    featherWriter.prepare("INSERT INTO rows(occurredat, severity, datasource, lookbackwindow, type, value, threshold, tag, description) VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ?);"s);
    
    // 최적화: 람다 함수를 일반 함수로 변경하여 오버헤드 감소
    auto writeRecord = [&](const uint32_t occurredAt, const int severity, const int dataSource, 
                          const int lookbackWindow, const int type, const int64_t value, 
                          const int64_t threshold, const std::string &tag, const std::string &description) {
        // 최적화: 에러 체크를 한 번에 처리
        if (!featherWriter.bindInt(1, occurredAt) ||
            !featherWriter.bindInt(2, severity) ||
            !featherWriter.bindInt(3, dataSource) ||
            !featherWriter.bindInt(4, lookbackWindow) ||
            !featherWriter.bindInt(5, type) ||
            !featherWriter.bindInt64(6, value) ||
            !featherWriter.bindInt64(7, threshold) ||
            !featherWriter.bindText(8, tag) ||
            !featherWriter.bindText(9, description) ||
            !featherWriter.next() ||
            !featherWriter.reset()) {
            logger.oops("Failed to write record. Details: "s + featherWriter.lastError());
        }
    };

    // for each trigger......
    for (const auto &trigger : description.triggers) {
        // read bookmark
        Bookmark bookmark{};
        featherBookmark.bindInt64(1, static_cast<int64_t>(trigger.signature));
        if (featherBookmark.next() == SQLITE_ROW) {
            const auto blob = featherBookmark.getBlob(0);
            if (blob.size() >= sizeof(Bookmark)) {
                bookmark = *reinterpret_cast<const Bookmark*>(blob.data());
            }
        }
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
            feather->bindInt64(3, static_cast<int64_t>(trigger.signature));
        }

        // 최적화: 루프 내부 최적화
        while (feather->next() == SQLITE_ROW) {
            logger.log("Apply "s + std::to_string(feather->getInt(1)));
            
            // prepare for pointers to read individual record
            const auto blob = feather->getBlob(0);
            if (blob.size() < sizeof(uint64_t)) continue;
            
            const uint64_t *cursorStart = reinterpret_cast<const uint64_t*>(blob.data());
            const uint64_t *cursor = cursorStart;
            const uint64_t *cursorEnd = cursorStart + std::min(60ULL, blob.size() / sizeof(uint64_t));

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
                    
                    // 최적화: switch 문 최적화
                    switch (trigger.type) {
                    case Description::Trigger::OVERTHRESHOLD:
                        push = average > trigger.threshold;
                        break;
                    case Description::Trigger::UNDERTHRESHOLD:
                        push = average < trigger.threshold;
                        break;
                    case Description::Trigger::DELTA:
                        push = bookmark.countPrevious > 0 && bookmark.countPresent > 0 && 
                               bookmark.sumPrevious / bookmark.countPrevious > trigger.threshold && 
                               sumPresent * (100 + trigger.delta) / 100 > bookmark.sumPrevious;
                        break;
                    }
                    
                    if (push) {
                        writeRecord(feather->getInt(1) + (nextStop - cursorStart), 
                                  trigger.severity, trigger.dataSource, trigger.lookbackWindow, 
                                  trigger.type, average, trigger.threshold, trigger.tag, trigger.description);
                    }

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
        bookmarkWriter.bindInt64(1, static_cast<int64_t>(trigger.signature));
        bookmarkWriter.bindBlob(2, &bookmark, bookmarkSize);
        bookmarkWriter.next();
        bookmarkWriter.reset();
    }
}

// 최적화: 데이터소스 결정 함수 최적화 - 룩업 테이블 사용
SuperCodex::ChapterType Event7::determineDataSource(const char *dataSource)
{
    if (!dataSource) return SuperCodex::EVENTS;
    
    // 최적화: 첫 번째 문자로 빠른 분기
    switch (dataSource[0]) {
    case 'b': // bps
        return SuperCodex::ChapterType::BPSPERSESSION;
    case 'p': // pps
        return SuperCodex::ChapterType::PPSPERSESSION;
    case 'r': // rtt
        return SuperCodex::ChapterType::RTTS;
    case 't': // TCP series
        if (dataSource[3] == 't') { // tcptimeouts
            return SuperCodex::ChapterType::TIMEOUTS;
        } else if (dataSource[3] == 'r') { // tcpr......
            if (dataSource[6] == 's') { // tcprsts
                return SuperCodex::ChapterType::TCPRSTS;
            } else if (dataSource[6] == 'r') { // tcpretransmissions
                return SuperCodex::ChapterType::TCPRETRANSMISSIONS;
            }
        } else if (dataSource[3] == 'z') { // tcpzerowindows
            return static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPZEROWINDOW);
        } else if (dataSource[3] == 'p') { // tcpportreused
            return static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPPORTSREUSED);
        } else if (dataSource[3] == 'o') { // tcpoutoforders
            return static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPOUTOFORDER);
        } else if (dataSource[3] == 'd') { // tcpdupacks
            return SuperCodex::ChapterType::TCPDUPACKS;
        }
        break;
    }

    // nothing in the list
    return SuperCodex::EVENTS;
}
