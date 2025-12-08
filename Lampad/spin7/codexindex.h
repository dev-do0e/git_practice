#ifndef CODEXINDEX_H
#define CODEXINDEX_H

#include "miscellany.h"
#include "../loghandler.h"
#include "../supercodex.h"

#include <ankerl/unordered_dense.h>
#include <shared_mutex>

class CodexIndex
{
public:
    CodexIndex();
    struct IndexRecord
    {
        uint32_t from, to; // timestamp
        std::string file; // filename with path after feed
    };
    std::vector<std::string> codices(SuperCodex::Conditions &conditions);
    void availableTimeframe(const std::string feed, uint32_t &start, uint32_t &end);

    // build codices: add, remove, and build index
    void addCodices(const std::string feedName, const std::string list);
    void cleanUpFeed();
    long long codexSize(const std::string feedName);

    // environmental variables
    static void setFeedRoot(const std::string &path);
    static std::string feedRoot, logRoot;
    static int feedCleanUpInterval, feedFreeSpaceRatio;
    static int logsToMaintain;
    static std::string spin7Command;
    static ankerl::unordered_dense::map<std::string, uint32_t> individualFeedDuration; // feed name + save duration in seconds
    static ankerl::unordered_dense::set<std::string> feedsToIgnoreOnCleanup; // feed name

    // utility functions
    static std::vector<std::string> enumerateSuperCodexFiles(const std::string hourDirectory);
    static CodexIndex::IndexRecord generateIndexRecord(const std::string &fileName);
    static void saveCodexCache(const std::string hourDirectory, std::vector<IndexRecord> indexRecords);

private:
    // check codex filesystem update
    TimerThread feedCleanUpTimer, logRotationTimer;

    // list of codices per feed
    ankerl::unordered_dense::map<std::string, std::vector<IndexRecord>> codexList;
    std::shared_mutex codexListLock;

    Logger logger;
    void cleanUpLogs();
};

#endif // CODEXINDEX_H
