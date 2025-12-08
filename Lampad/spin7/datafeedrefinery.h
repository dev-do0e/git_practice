#ifndef DATAFEEDREFINERY_H
#define DATAFEEDREFINERY_H

#include <atomic>
#include <memory>
#include <ankerl/unordered_dense.h>
#include <shared_mutex>
#include <vector>

#include "../loghandler.h"
#include "../supercodex.h"
#include "feedrefinerabstract.h"
#include "miscellany.h"

// forward declaration
class DataFeedRefinery;

class FeedConsumer
{
public:
    FeedConsumer(DataFeedRefinery *refinery);
    ankerl::unordered_dense::map<std::string, std::string> originalParameters();
    std::atomic<bool> stopCurrentProcess = false; // set this to "true" to safely stop process

    // progress and information
    unsigned int jobId;
    std::string username;
    void targetTime(uint32_t &from, uint32_t &to);

    // utility functions
    static FeedRefinerAbstract *constructWorker(const SuperCodex::Conditions &conditions, SuperCodex::ChapterType &chaptersToLoad, const std::string messyRoomPrefix = "refined"s);
    static void consumeByChunk(const SuperCodex::Conditions &conditions, const SuperCodex::ChapterType &chaptersToLoad, const int chunkSize, std::function<bool(std::vector<SuperCodex::Loader *> &, const bool)> feedProcess); // false: stop the process

private:
    void run();
    std::thread thread;
    FeedRefinerAbstract *worker = nullptr;
    SuperCodex::ChapterType chaptersToLoad;
    DataFeedRefinery *refinery;
    Logger logger;
};

class DataFeedRefinery
{
public:
    DataFeedRefinery();

    // environmental variables
    static int timeToClearRefineryResult;

    // jobs: finished, ongoing, queue
    void cancelCurrentJob(const std::string &username);
    FeedConsumer *feedConsumer;
    struct JobQueueItem
    {
        std::string username;
        SuperCodex::Conditions conditions;
        std::atomic<int> progress = 0;
        FeedRefinerAbstract *refiner = nullptr;
    };
    std::vector<std::shared_ptr<JobQueueItem>> jobsQueue;
    std::shared_mutex jobsQueueMutex;

    // append a new job to the queue
    void queueAJob(const std::string &username, const SuperCodex::Conditions conditions);
    static unsigned int jobId(const std::string username, const std::string &feedname, SuperCodex::Conditions &conditions); // exposed to public so that it can be used by DataFeed
    std::shared_ptr<JobQueueItem> job(const std::string &username, const unsigned int jobId);

private:
    // removing unused results
    TimerThread finishedJobCleanupTimer;
    void cleanFinishedJobs();
    Logger logger;
};

#endif // DATAFEEDREFINERY_H
