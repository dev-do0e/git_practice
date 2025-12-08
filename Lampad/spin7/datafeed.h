#ifndef DATAFEED_H
#define DATAFEED_H

#include <shared_mutex>
#include <mutex>

#include <string>
#include <ankerl/unordered_dense.h>
#include <nlohmann/json.hpp>

#include "datafeedrefinery.h"
#include "../loghandler.h"

// forward declarations
class CodexIndex;
struct mg_connection;

using namespace std::string_literals;

class DataFeed
{
    friend class DataFeedRefinery;

public:
    DataFeed(const std::string &feedName);
    ~DataFeed();

    // feed management
    static ankerl::unordered_dense::map<std::string, DataFeed *> feeds; // feed name(not full path)+object

    // data feed enumeration
    struct Description
    {
        std::string name;
        uint32_t from = 0, to = 0;
    };
    static std::vector<Description> describeFeeds();
    static std::string enumerateFeeds();

    // environmental variables
    static CodexIndex *codexIndex;

    /* backend for REST APIs */
    // tags
    void getTag(mg_connection *connection);
    void putTag(mg_connection *connection, const std::string &path, ankerl::unordered_dense::map<std::string, std::string> &parameters);
    void deleteTag(mg_connection *connection, const std::string &path);
    void getIp(mg_connection *connection, const std::string &ip);
    void saveTags();
    // refinery
    void postRefinery(mg_connection *connection, const std::string &username, ankerl::unordered_dense::map<std::string, std::string> &parameters);
    void getProgress(mg_connection *connection, const std::string &username);
    void getRefinery(mg_connection *connection, const std::string &username, const std::string &path, ankerl::unordered_dense::map<std::string, std::string> &parameters);
    void deleteRefinery(mg_connection *connection, const std::string &username, const std::string &path);
    std::mutex deleteRefineryMutex;
    void putRefinery(mg_connection *connection, const std::string &username, const std::string &path, ankerl::unordered_dense::map<std::string, std::string> &parameters);
    // miscellany
    void getPcap(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
    void getBpms(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
    void getEvents(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
    void getSchrodinger(mg_connection *connection, ankerl::unordered_dense::map<std::string, std::string> &parameters);
    void initializeDnsCache();

    // utility function(s)
    std::string buildSuperCodexConditions(const ankerl::unordered_dense::map<std::string, std::string> &parameters, SuperCodex::Conditions &conditions);

private:
    // metadata for the feed
    std::string feedPath, feedName;
    Logger logger;
    DataFeedRefinery refinery;

    // tag management
    nlohmann::json tags;
    std::string tagsPath;
    std::shared_mutex tagsLock;

    // utility functions
    enum JobStatus { INQUEUE, INPROGRESS, COMPLETE, NOTFOUND };
    JobStatus jobStatus(const std::string username, const uint64_t jobId);
};

#endif // DATAFEED_H
