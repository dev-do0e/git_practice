#include "datafeedrefinery.h"
#include "tcpservicemanager.h"
#include "../fnvhash.h"
#include "feedrefinerbasic.h"
#include "feedrefinermain.h"
#include "feedrefinerspecialized.h"
#include "feedrefinertopn.h"
#include "feedrefinertrackers.h"

#include <string>
#include <ankerl/unordered_dense.h>

using namespace std::string_literals;

// environmental variables
int DataFeedRefinery::timeToClearRefineryResult = 300;

DataFeedRefinery::DataFeedRefinery()
    : finishedJobCleanupTimer(timeToClearRefineryResult, [&]() { cleanFinishedJobs(); })
    , logger("DataFeedRefinery")
{
    // initialize jobConsumer
    feedConsumer = new FeedConsumer(this);

    // start cleanup timer
    finishedJobCleanupTimer.start();
}

void DataFeedRefinery::cancelCurrentJob(const std::string &username)
{
    if (feedConsumer->username == username) {
        logger.log("Announcing job consumer to stop current job.");
        feedConsumer->stopCurrentProcess = true;
    } else
        logger.log("Username is different. Current job is not cancelled.");
}

void DataFeedRefinery::queueAJob(const std::string &username, const SuperCodex::Conditions conditions)
{
    // job ID duplication check shall be done beforhand
    jobsQueueMutex.lock();
    jobsQueue.push_back(std::shared_ptr<DataFeedRefinery::JobQueueItem>(new JobQueueItem{username, conditions, 0, nullptr}));
    jobsQueueMutex.unlock();

    logger.log("Queued job "s + std::to_string(conditions.jobId));
}

void DataFeedRefinery::cleanFinishedJobs()
{
    time_t cleanBase = time(nullptr) - timeToClearRefineryResult;
    logger.log("Cleaning up finished jobs. Base time: "s + FeedRefinerAbstract::epochToIsoDate(cleanBase));
    jobsQueueMutex.lock();
    for (auto i = jobsQueue.begin(); i != jobsQueue.end();)
        if ((*i)->refiner->lastAccess < cleanBase) {
            logger.log("Remove job: user "s + (*i)->username + " / Job ID "s + std::to_string((*i)->conditions.jobId) + " / Last Access: "s + FeedRefinerAbstract::epochToIsoDate((*i)->refiner->lastAccess));
            i = jobsQueue.erase(i);
        } else if ((*i)->progress == -1)
            ++i;
        else
            break;
    jobsQueueMutex.unlock();
}

unsigned int DataFeedRefinery::jobId(const std::string username, const std::string &feedname, SuperCodex::Conditions &conditions)
{
    // get session filter ID
    unsigned int hash = SuperCodex::conditionsId(conditions);

    // username and feedname
    hash = fnv32a(username.data(), username.size(), fnv32a(feedname.data(), feedname.size(), hash));

    // remove parameters used to create session filter ID(=already applied)
    auto parametersCopy = conditions.parameters;
    if (parametersCopy.contains("tags"s))
        parametersCopy.erase("tags"s);
    if (parametersCopy.contains("ips"s))
        parametersCopy.erase("ips"s);
    if (parametersCopy.contains("ports"s))
        parametersCopy.erase("ports"s);
    if (parametersCopy.contains("payloadprotocol"s))
        parametersCopy.erase("payloadprotocol"s);
    if (parametersCopy.contains("detectedl7"s))
        parametersCopy.erase("detectedl7"s);
    if (parametersCopy.contains("includeexternal"s))
        parametersCopy.erase("includeexternal"s);
    if (parametersCopy.contains("from"s))
        parametersCopy.erase("from"s);
    if (parametersCopy.contains("to"s))
        parametersCopy.erase("to"s);
    if (parametersCopy.contains("vlanq"s))
        parametersCopy.erase("vlanq"s);
    if (parametersCopy.contains("mpls"s))
        parametersCopy.erase("mpls"s);

    // sign with parameters
    for (const auto &parameter : parametersCopy)
        hash = fnv32a(parameter.second.data(), parameter.second.size(), hash);

    return hash;
}

std::shared_ptr<DataFeedRefinery::JobQueueItem> DataFeedRefinery::job(const std::string &username, const unsigned int jobId)
{
    for (const auto &job : jobsQueue)
        if (job->conditions.jobId == jobId && job->username == username)
            return std::shared_ptr(job);
    return nullptr;
}

FeedConsumer::FeedConsumer(DataFeedRefinery *refinery)
    : refinery{refinery}
    , logger("FeedConsumer")
{
    thread = std::thread([&]() { this->run(); });
}

void FeedConsumer::run()
{
    while (true) {
        // initialize stop flag
        stopCurrentProcess = false;

        // get next job to do
        std::shared_ptr<DataFeedRefinery::JobQueueItem> jobToGo(nullptr);
        refinery->jobsQueueMutex.lock();
        for (auto i = refinery->jobsQueue.begin(); i != refinery->jobsQueue.end();) {
            if ((*i)->progress == 0) {
                // create new worker
                (*i)->refiner = constructWorker((*i)->conditions, chaptersToLoad);
                if (!(*i)->refiner) { // exception handling: unsupported job type
                    logger.log("Unsupported job type("s + (*i)->conditions.parameters["type"s] + ") for job ID "s + std::to_string((*i)->conditions.jobId));
                    i = refinery->jobsQueue.erase(i);
                    continue;
                }
                (*i)->conditions.codicesToGo = (*i)->refiner->codicesToLoad((*i)->conditions);

                // show log for this job
                std::string originalOptions("/ Options are "s);
                for (const auto &pair : (*i)->conditions.parameters)
                    originalOptions.append(pair.first).append("="s).append(pair.second).push_back('&');
                originalOptions.pop_back();
                logger.log("Next job by " + (*i)->username + ": "s + (*i)->conditions.parameters["type"s] + '/' + std::to_string((*i)->conditions.jobId) + originalOptions);

                // get the (shared) pointer for job description
                jobToGo = *i;
                worker = jobToGo->refiner;
                break;
            } else
                ++i;
        }
        refinery->jobsQueueMutex.unlock();
        if (!jobToGo) { // if there's no job to go, sleep for 1 second
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        // register current job to this object
        LogStopwatch elapsed(&logger, "Time consumed:"s);
        refinery->jobsQueueMutex.lock_shared();
        jobId = jobToGo->conditions.jobId;
        username = jobToGo->username;
        refinery->jobsQueueMutex.unlock_shared();

        // feed codices to worker
        jobToGo->refiner->conditions.codicesToGo = jobToGo->conditions.codicesToGo; // target SuperCodex file list is set to jobToGo->conditions after refiner object is constructed, so conditions inside refiner doesn't have SuperCodex file list
        int codicesTotal = jobToGo->conditions.codicesToGo.size();
        int codicesProcessed = 0;
        logger.log("Feed "s + std::to_string(codicesTotal) + " codices to job ID "s + std::to_string(jobId));

        if (jobToGo->refiner->isStreaming) { // streaming: go directly to finalize
            logger.log("Streaming: finalize immediately"s);
            std::vector<SuperCodex::Loader *> temp;
            worker->consumeCodices(temp, true);
            jobToGo->progress = -1; // atomic
        } else
            consumeByChunk(jobToGo->conditions, chaptersToLoad, std::thread::hardware_concurrency() * 2, [&](std::vector<SuperCodex::Loader *> &codicesLoaded, const bool isFinal) -> bool {
                if (stopCurrentProcess)
                    return false;

                // do the job
                worker->consumeCodices(codicesLoaded, isFinal);

                // update progress
                codicesProcessed += codicesLoaded.size(); // update progress
                jobToGo->progress = codicesProcessed * 100 / codicesTotal; // atmoic

                return true;
            });

        // register results and finalize
        if (stopCurrentProcess) {
            logger.log("Stop current job: "s + std::to_string(jobId) + " from "s + username);
            std::lock_guard lock(refinery->jobsQueueMutex);
            // remove the job from queue
            for (auto i = refinery->jobsQueue.begin(); i != refinery->jobsQueue.end();)
                if (i->get()->conditions.jobId == jobId && username == i->get()->username) {
                    i = refinery->jobsQueue.erase(i);
                    break;
                } else
                    ++i;

            // remove from current
            jobToGo.reset();
        } else {
            // mark the job as complete
            jobToGo->progress = -1; // atomic
        }

        // set worker to null pointer to indicate that there's no active refinery job
        worker = nullptr;
    }

    logger.log("Queue empty. Exiting thread."s);
}

FeedRefinerAbstract *FeedConsumer::constructWorker(const SuperCodex::Conditions &conditions, SuperCodex::ChapterType &chaptersToLoad, const std::string messyRoomPrefix)
{
    // initialization
    if (conditions.parameters.contains("type"s) == 0)
        return nullptr;
    FeedRefinerAbstract *worker = nullptr;
    const std::string messyRoomPath = messyRoomPrefix + std::to_string(conditions.jobId), &type = conditions.parameters.at("type"s);
    chaptersToLoad = static_cast<SuperCodex::ChapterType>(SuperCodex::SESSIONS | SuperCodex::REMARKS);

    if (type == "bps"s) {
        worker = new FeedRefinerPerSecondStatistics(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::BPSPERSESSION);
    } else if (type == "pps"s) {
        worker = new FeedRefinerPps(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::PPSPERSESSION);
        if (conditions.parameters.contains("ignoremac"s) && !conditions.parameters.at("ignoremac"s).empty())
            chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::PACKETS);
    } else if (type == "averagelatency"s) {
        worker = new FeedRefinerLatency(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::RTTS);
    } else if (type == "timeoutcounts"s) {
        worker = new FeedRefinerPerSecondStatistics(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TIMEOUTS);
    } else if (type == "tcprsts"s) {
        worker = new FeedRefinerPerSecondStatistics(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TCPRSTS);
    } else if (type == "tcpzerowindows"s) {
        worker = new FeedRefinerPerSecondStatistics(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TCPMISCANOMALIES);
    } else if (type == "tcpdupacks"s) {
        worker = new FeedRefinerPerSecondStatistics(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TCPDUPACKS);
    } else if (type == "tcpretransmissions"s) {
        worker = new FeedRefinerPerSecondStatistics(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TCPRETRANSMISSIONS);
    } else if (type == "tcpportsreused"s) {
        worker = new FeedRefinerPerSecondStatistics(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TCPMISCANOMALIES);
    } else if (type == "tcpoutoforders"s) {
        worker = new FeedRefinerPerSecondStatistics(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TCPMISCANOMALIES);
    } else if (type == "datastreams"s) {
        worker = new FeedRefinerDataStreams(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::BPSPERSESSION | SuperCodex::RTTS | SuperCodex::TIMEOUTS);
        if (conditions.parameters.contains("regex"s))
            chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::PACKETS);
    } else if (type == "services"s)
        worker = new FeedRefinerServices(messyRoomPath, conditions);
    else if (type == "topn"s) {
        const std::string &base = conditions.parameters.at("base"s);
        if (base == "httperrors"s) {
            worker = new FeedRefinerTopNHttpErrors(messyRoomPath, conditions);
            chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::REMARKS);
        } else if (base == "latencies"s) {
            worker = new FeedRefinerTopNLatencies(messyRoomPath, conditions);
            chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::RTTS | SuperCodex::BPSPERSESSION);
        } else {
            worker = new FeedRefinerTopN(messyRoomPath, conditions);
            if (base == "bytes"s)
                chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::BPSPERSESSION);
            else if (base == "packets"s)
                chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::PPSPERSESSION);
            else if (base == "timeouts"s)
                chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TIMEOUTS);
            else if (base == "tcprsts"s)
                chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TCPRSTS | SuperCodex::PPSPERSESSION);
            else if (base == "tcpzerowindows"s)
                chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TCPMISCANOMALIES | SuperCodex::PPSPERSESSION);
            else if (base == "tcpdupacks"s)
                chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TCPDUPACKS | SuperCodex::PPSPERSESSION);
            else if (base == "tcpretransmissions"s)
                chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TCPRETRANSMISSIONS | SuperCodex::PPSPERSESSION);
            else if (base == "tcpoutoforders"s)
                chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TCPMISCANOMALIES | SuperCodex::PPSPERSESSION);
            else if (base == "tcpportsreused"s)
                chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::TCPMISCANOMALIES);
        }
    } else if (type == "macsperip"s) {
        worker = new FeedRefinerMacsPerIp(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::PACKETS);
    } else if (type == "overview"s) {
        worker = new FeedRefinerOverview(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::BPSPERSESSION | SuperCodex::PPSPERSESSION);
    } else if (type == "lowhoplimits"s) {
        worker = new FeedRefinerLowHopLimits(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::PACKETS);
    } else if (type == "dnstracker"s) {
        worker = new FeedRefinerDnsTracker(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::REMARKS | SuperCodex::RTTS | SuperCodex::TIMEOUTS);
    } else if (type == "pop3tracker"s) {
        worker = new FeedRefinerPop3Tracker(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::REMARKS | SuperCodex::BPSPERSESSION);
    } else if (type == "imaptracker"s) {
        worker = new FeedRefinerImapTracker(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::REMARKS | SuperCodex::BPSPERSESSION);
    } else if (type == "httptracker"s) {
        worker = new FeedRefinerHttpTracker(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::REMARKS);
    } else if (type == "smtptracker"s) {
        worker = new FeedRefinerSmtpTracker(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::REMARKS | SuperCodex::BPSPERSESSION);
    } else if (type == "ftptracker"s) {
        worker = new FeedRefinerFtpTracker(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::REMARKS | SuperCodex::BPSPERSESSION);
    } else if (type == "httt"s) {
        worker = new FeedRefinerHttt(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::REMARKS);
    } else if (type == "jitter"s) {
        worker = new FeedRefinerJitter(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::RTTS | SuperCodex::PACKETS | SuperCodex::PPSPERSESSION);
    } else if (type == "icmpwalk"s) {
        worker = new FeedRefinerIcmpWalk(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::PACKETS | SuperCodex::REMARKS);
    } else if (type == "icmp6walk"s) {
        worker = new FeedRefinerIcmpWalk(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::PACKETS | SuperCodex::REMARKS);
    } else if (type == "tlstracker"s) {
        worker = new FeedRefinerTlsTracker(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::BPSPERSESSION | SuperCodex::RTTS | SuperCodex::TIMEOUTS | SuperCodex::REMARKS);
    } else if (type == "tlsdump"s) {
        worker = new FeedRefinerTlsDump(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad);
    } else if (type == "microburst"s) {
        worker = new FeedRefinerMicroBurst(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::PACKETS);
    } else if (type == "voipmonitor") {
        worker = new FeedRefinerVoip(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::REMARKS | SuperCodex::PACKETS);
    } else if (type == "raw"s) {
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::PACKETS);
        worker = new FeedRefinerRaw(messyRoomPath, conditions);
    } else if (type == "sessionaudit"s) {
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad);
        worker = new FeedRefinerSessionAudit(messyRoomPath, conditions);
    } else if (type == "bps2"s) {
        worker = new FeedRefinerBps2(messyRoomPath, conditions);
        chaptersToLoad = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::BPSPERSESSION);
    } else if (type == "flowcounts"s) {
        worker = new FeedRefinerFlowCounts(messyRoomPath, conditions);
        // we use SuperCodex::SESSIONS only
    }

    return worker;
}

void FeedConsumer::consumeByChunk(const SuperCodex::Conditions &conditions, const SuperCodex::ChapterType &chaptersToLoad, const int chunkSize, std::function<bool(std::vector<SuperCodex::Loader *> &, const bool)> feedProcess)
{
    // get a copy of TCP services
    TcpServiceManager::servicesMutex.lock_shared();
    auto services = TcpServiceManager::services;
    TcpServiceManager::servicesMutex.unlock_shared();

    // internal function to load SuperCodex
    std::function<SuperCodex::Loader *(const std::string &)> loadCodex = [&](const std::string &fileName) -> SuperCodex::Loader * {
        auto loader = new SuperCodex::Loader(fileName, chaptersToLoad, conditions);
        if (loader->isSane)
            return loader;
        else {
            delete loader;
            return nullptr;
        }
    };

    // build codices to load
    std::vector<std::string> codices = conditions.codicesToGo;
    while (!codices.empty()) {
        // determine how many SuperCodex files are loaded
        int codicesToLoadSize = std::min(chunkSize, static_cast<int>(codices.size()));
        auto i = codices.begin(), iEnd = codices.begin();
        std::advance(iEnd, codicesToLoadSize);
        std::vector<std::string> codicesToLoad(i, iEnd);
        codices.erase(i, iEnd);

        // load SuperCodex files
        std::vector<SuperCodex::Loader *> codicesLoaded = SuperCodex::parallel_convert(codicesToLoad, loadCodex);
        for (auto i = codicesLoaded.begin(); i != codicesLoaded.end();)
            if ((*i) == nullptr)
                i = codicesLoaded.erase(i);
            else
                ++i;

        // do the job
        const bool go_on = feedProcess(codicesLoaded, codices.empty());
        // destroy used loaders
        for (auto &loader : codicesLoaded)
            delete loader;
        // check whether to stop
        if (!go_on)
            return;
    }
}

ankerl::unordered_dense::map<std::string, std::string> FeedConsumer::originalParameters()
{
    if (!worker)
        return ankerl::unordered_dense::map<std::string, std::string>();
    else
        return worker->conditions.parameters;
}

void FeedConsumer::targetTime(uint32_t &from, uint32_t &to)
{
    if (!worker) {
        from = -1;
        to = -1;
    } else
        worker->resultTimeFrame(from, to);
}

