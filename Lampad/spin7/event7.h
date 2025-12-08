#ifndef EVENT7_H
#define EVENT7_H

#include "../loghandler.h"
#include "../supercodex.h"
#include "datafeed.h"

#include <ankerl/unordered_dense.h>

#include <string>
#include <filesystem>
#include <vector>

namespace Event7 {
// environmental variable(s)
extern std::string feedPath;

// main functions
void start();
void generate(const DataFeed::Description &feed);

// database management
extern std::vector<std::string> dbs, ddls; // there can be more than one database tables. For example. AI3 events may need different database table schema
struct Bookmark
{
    uint64_t sumPrevious, countPrevious, sumPresent, countPresent;
    int32_t lastRead;
};
constexpr size_t bookmarkSize = sizeof(Bookmark);

// parse event triggers
struct Description
{
    std::filesystem::file_time_type lastTagsJsonUpdate; // timestamp for last write of tags.json
    struct Trigger
    {
        uint32_t lookbackWindow;
        int32_t delta = -1;
        enum Severity : uint8_t { INFO, WARNING, CRITICAL, SEVERITYALL = UINT8_MAX } severity;
        enum Type : uint8_t { OVERTHRESHOLD, UNDERTHRESHOLD, DELTA } type;
        SuperCodex::ChapterType dataSource = SuperCodex::ChapterType::EVENTS;
        int64_t threshold;
        uint64_t signature; // 0: from SuperCache(=all)
        std::string description, tag;
    };
    std::vector<Trigger> triggers;
};
extern ankerl::unordered_dense::map<std::string, Description> triggers; // feed name + events parsed from JSON
void updateTriggers(const std::string &feedName);
SuperCodex::ChapterType determineDataSource(const char *dataSource);

// logger
extern Logger logger;

} // namespace Event7

#endif // EVENT7_H
