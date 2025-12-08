#include "codexindex.h"

#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <iterator>
#include <tbb/parallel_for.h>

#include "datafeed.h"

using namespace std::string_literals;

std::string CodexIndex::feedRoot, CodexIndex::logRoot;
int CodexIndex::feedCleanUpInterval = 300; // clean up feeds every 5 minutes
int CodexIndex::feedFreeSpaceRatio = 10; // at least 10% of free space will be secured on feed cleanup process
int CodexIndex::logsToMaintain = 90; // past 90 days
std::string CodexIndex::spin7Command;
ankerl::unordered_dense::map<std::string, uint32_t> CodexIndex::individualFeedDuration;
ankerl::unordered_dense::set<std::string> CodexIndex::feedsToIgnoreOnCleanup;

void CodexIndex::setFeedRoot(const std::string &path)
{
    feedRoot = path;
    for (size_t i = 0, iEnd = CodexIndex::feedRoot.size(); i < iEnd; i++)
        if (CodexIndex::feedRoot[i] == '\\')
            CodexIndex::feedRoot[i] = '/';
    if (feedRoot.back() != '/')
        feedRoot.push_back('/');
}

CodexIndex::CodexIndex()
    : feedCleanUpTimer(feedCleanUpInterval, [&]() { cleanUpFeed(); })
    , logRotationTimer(86400, [&]() { cleanUpLogs(); })
    , logger("CodexIndex")
{
    // read filesystem to enumerate existing codices
    logger.log("Build indices from feed root "s + CodexIndex::feedRoot);
    std::vector<std::pair<std::string, std::string>> hoursWithoutCodexCombined; // feed name + full path for hours directory
    for (const auto &feedDirectory : std::filesystem::directory_iterator(CodexIndex::feedRoot))
        if (std::filesystem::is_directory(feedDirectory)) {
            // determine whether to skip reading feeds
            std::string path = feedDirectory.path().string(), feedName(feedDirectory.path().filename().string());
            if (feedName == "lost+found"s || feedName.at(0) == '.') {
                logger.log("Skip "s + path);
                continue;
            } else
                logger.log("Enumerate codex index from "s + path);

            // enumerate all hour directories
            std::vector<std::string> hourDirectories;
            for (const auto &codexDirectory : std::filesystem::directory_iterator(feedDirectory))
                if (std::filesystem::is_directory(codexDirectory))
                    hourDirectories.push_back(codexDirectory.path().string());
            if (hourDirectories.empty()) {
                logger.log("Skipping empty directory: "s + feedDirectory.path().string());
                continue;
            }
            std::sort(hourDirectories.begin(), hourDirectories.end());

            // either read SuperCodex from cache or individual SuperCodex files
            std::function<std::vector<IndexRecord>(const std::string)> buildIndex = [&](const std::string hourDirectory) -> std::vector<IndexRecord> {
                std::vector<IndexRecord> results;

                if (std::filesystem::exists(hourDirectory + "/codex.cache"s)) {
                    results.reserve(7200);

                    // "read all" from cache file
                    std::string cache(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream(hourDirectory + "/codex.cache"s, std::ifstream::binary).rdbuf()).str());

                    // build result
                    const char *cursor = cache.data(), *cursorEnd = cursor + cache.size();
                    while (cursor < cursorEnd) {
                        // register new index record
                        uint32_t from = *(uint32_t *) cursor, to = *(uint32_t *) (cursor + 4);
                        std::string superCodexFile = std::string(cursor + 8);
                        results.push_back(IndexRecord{from, to, superCodexFile});

                        // move cursor to next record
                        cursor += 8;
                        while (*cursor != '\0')
                            ++cursor;
                        ++cursor;
                    }

                    results.shrink_to_fit();
                } else {
                    // enumerate SuperCodex files and build index
                    results = SuperCodex::parallel_convert<std::string, IndexRecord>(enumerateSuperCodexFiles(hourDirectory), generateIndexRecord);

                    // remove broken indices
                    for (auto i = results.begin(); i != results.end();)
                        if (i->from == 0)
                            i = results.erase(i);
                        else
                            ++i;

                    // save cache for given hour directory
                    if (hourDirectory != hourDirectories.back())
                        saveCodexCache(hourDirectory, results);
                }

                return results;
            };
            std::vector<std::vector<IndexRecord>> indices = SuperCodex::parallel_convert<std::string, std::vector<IndexRecord>>(hourDirectories, buildIndex);

            // consolidate codex index
            size_t indexSize = 0;
            for (const auto &index : indices)
                indexSize += index.size();
            auto &targetIndex = codexList[feedName];
            targetIndex.reserve(indexSize);
            for (const auto &index : indices)
                for (const auto &item : index)
                    targetIndex.push_back(std::move(item));

            // remove last directory(which doesn't fill the full hour)
            hourDirectories.pop_back();
        }

    // background: start disk clean up
    std::thread([&]() {
        logger.log("Initial cleanup in the background"s);
        cleanUpFeed();
        cleanUpLogs();

        logger.log("Start cleanup timers"s);
        feedCleanUpTimer.start();
        logRotationTimer.start();
    }).detach();
}

void CodexIndex::availableTimeframe(const std::string feed, uint32_t &start, uint32_t &end)
{
    codexListLock.lock_shared();
    if (!codexList.contains(feed) || codexList.at(feed).empty()) {
        start = 0;
        end = 0;
    } else {
        start = codexList.at(feed).front().from;
        end = codexList.at(feed).back().to - 1; // by doing this, we can ensure that last second is fully filled(i.e. from 0.000 to 1.000), not partially(e.g. filled only from 0.000 to 0.287)
    }
    codexListLock.unlock_shared();
}

void CodexIndex::cleanUpFeed()
{
    logger.log("Clean up spaces"s);
    LogStopwatch stopwatch(&logger, "Spaces cleaned up"s);

    // pre-cleanup: remove "too old" raw packet data
    codexListLock.lock_shared();
    for (const auto &pair : codexList)
        if (individualFeedDuration.contains(pair.first)) {
            const auto &list = pair.second;
            uint32_t removeBaseTimestamp = list.back().to - individualFeedDuration.at(pair.first);

            // determine starting point
            auto reverseIterator = list.rbegin();
            while (reverseIterator->from > removeBaseTimestamp)
                ++reverseIterator;

            // delete raw packet data as needed
            std::vector<std::string> suffixList = {".appendix"s, ".slice64"s, ".slice128"s, ".slice192"s};
            while (reverseIterator != list.rend()) {
                // prepare for some variables
                bool rawPacketFound = false;
                std::string pathPrefix = reverseIterator->file;
                pathPrefix.erase(pathPrefix.size() - 11); // remove ".supercodex"

                // find and delete raw socket data
                for (const auto &suffix : suffixList) {
                    std::filesystem::path path(pathPrefix + suffix);
                    if (std::filesystem::exists(path)) {
                        std::filesystem::remove(path);
                        rawPacketFound = true;
                        break;
                    }
                }

                // if raw packet data is not found, treat they're already deleted
                if (!rawPacketFound)
                    break;
                else
                    ++reverseIterator;
            }
        }
    codexListLock.unlock_shared();

    // secure free space
    codexListLock.lock();
    std::filesystem::space_info spaceInfo = std::filesystem::space(feedRoot);
    auto targetSpace = spaceInfo.capacity * feedFreeSpaceRatio / 100;
    while (spaceInfo.free < targetSpace) {
        logger.log(feedRoot + "| free space and target: "s + std::to_string(spaceInfo.free) + ' ' + std::to_string(targetSpace) + ". Needs "s + std::to_string(targetSpace - spaceInfo.free) + " more");

        // determine which data feed has the oldest data
        std::vector<std::pair<std::string, uint32_t>> fronts;
        fronts.reserve(codexList.size());
        for (const auto &pair : codexList)
            if (!feedsToIgnoreOnCleanup.contains(pair.first) && !pair.second.empty())
                fronts.push_back(std::make_pair(pair.first, pair.second.front().from));
        if (fronts.empty()) {
            logger.oops("There's no data feed to delete. Consider removing frozen data feeds at Spin7->DoNotDelete."s);
            return;
        }
        std::sort(fronts.begin(), fronts.end(), [](const std::pair<std::string, uint32_t> &a, const std::pair<std::string, uint32_t> &b) -> bool { return a.second < b.second; });

        // remove the oldest hour directory acress entire data feeds
        auto &codices = codexList[fronts.front().first];
        std::filesystem::path parent = std::filesystem::absolute(codices.front().file).parent_path();
        logger.log("Remove hour directory: "s + parent.string());
        std::filesystem::remove_all(parent);

        // remove records of nonexistent SuperCodex files from codex index
        while (!codices.empty() && !std::filesystem::exists(codices.front().file))
            codices.erase(codices.begin());

        // update space info
        spaceInfo = std::filesystem::space(feedRoot);
    }
    codexListLock.unlock();

    // enumerate nonexistent SuperCodex files
    ankerl::unordered_dense::map<std::string, std::vector<size_t>> deletedFiles; // feed name + index in the vector
    // enumerate nonexistent files
    codexListLock.lock_shared();
    for (auto &list : codexList) {
        auto &target = deletedFiles[list.first];
        target.reserve(list.second.size() / 2);
        for (size_t i = 0, iEnd = list.second.size(); i < iEnd; ++i)
            if (!std::filesystem::exists(list.second[i].file))
                target.push_back(i);
    }
    codexListLock.unlock_shared();

    codexListLock.lock();
    // remove nonexistent SuperCodex files from the list
    for (auto &pair : deletedFiles) {
        // sort indices in descending order
        std::sort(pair.second.rbegin(), pair.second.rend());

        // remove file entries
        auto &target = codexList[pair.first];
        for (const auto &index : pair.second)
            target.erase(std::next(target.begin(), index));
    }

    // is there anything remaining in each data feed?
    for (auto i = DataFeed::feeds.begin(); i != DataFeed::feeds.end();) {
        // if there's no SuperCodex file in data feed directory, physically remove entire directory
        if (std::filesystem::exists(feedRoot + i->first) && codexList[i->first].empty())
            std::filesystem::remove_all(feedRoot + i->first);

        // remove any nonexistent data feed from codex list
        if (!std::filesystem::exists(feedRoot + i->first)) {
            logger.log("Removing deleted feed: "s + i->first);
            codexList.erase(i->first);
            delete i->second;
            i = DataFeed::feeds.erase(i);
        } else
            ++i;
    }
    codexListLock.unlock();
}

long long CodexIndex::codexSize(const std::string feedName)
{
    long long result = 0;
    for (auto &path : std::filesystem::recursive_directory_iterator((feedRoot + '/' + feedName)))
        if (path.is_regular_file())
            result += path.file_size();

    return result;
}

CodexIndex::IndexRecord CodexIndex::generateIndexRecord(const std::string &fileName)
{
    auto duration = SuperCodex::durationContained(fileName);
    return IndexRecord{duration.first, duration.second, fileName};
}

std::vector<std::string> CodexIndex::enumerateSuperCodexFiles(const std::string hourDirectory)
{
    std::vector<std::string> result;

    result.reserve(7200); // more than maximum number of files that may present in "hour directory"
    for (const auto &file : std::filesystem::directory_iterator(hourDirectory)) {
        std::string codexPath = file.path().string();
        if (codexPath.find(".supercodex"s) == codexPath.size() - 11)
            result.push_back(codexPath);
    }
    result.shrink_to_fit();
    std::sort(result.begin(), result.end());

    return result;
}

void CodexIndex::saveCodexCache(const std::string hourDirectory, std::vector<IndexRecord> indexRecords)
{
    // remove anything other than SuperCodex file from the list (e.g. codex.combined)
    for (auto i = indexRecords.begin(); i != indexRecords.end();)
        if (i->file.find(".supercodex"s) == std::string::npos)
            i = indexRecords.erase(i);
        else
            ++i;

    // prepare to save cache file
    std::ofstream cacheFile(hourDirectory + "/codex.cache"s, std::ios::binary | std::ios::trunc);
    std::unique_ptr<char[]> cacheFileBuffer(new char[536870912]); // 512MB
    cacheFile.rdbuf()->pubsetbuf(cacheFileBuffer.get(), 536870912);

    // save file
    for (const auto &record : indexRecords) {
        cacheFile.write((const char *) &record.from, 4);
        cacheFile.write((const char *) &record.to, 4);
        cacheFile.write(record.file.data(), record.file.size());
        cacheFile.write("\0", 1);
    }

    cacheFile.close();
}

void CodexIndex::cleanUpLogs()
{
    logger.log("Clean up logs"s);
    LogStopwatch stopwatch(&logger, "Logs cleaned up");

    // prepare for baseline to remove the directory
    std::filesystem::file_time_type removalBase = std::filesystem::file_time_type::clock::now() - std::chrono::hours(logsToMaintain * 24);

    // check last modified time of the directory to determine whether to remove the directory
    for (const auto &logDirectory : std::filesystem::directory_iterator(CodexIndex::logRoot))
        if (std::filesystem::is_directory(logDirectory) && (std::filesystem::last_write_time(logDirectory) < removalBase))
            std::filesystem::remove_all(logDirectory);
}

std::vector<std::string> CodexIndex::codices(SuperCodex::Conditions &conditions)
{
    std::vector<std::string> result;

    // crash guard
    if (codexList.empty())
        return result;

    // sanity check
    if (conditions.from > conditions.to) { // logic(from<=to)
        logger.log("Against sanity check: from<=to. from="s + std::to_string(conditions.from) + ", to="s + std::to_string(conditions.to));
        return result;
    }

    try {
        std::shared_lock locker(codexListLock);

        // select target data feed
        const std::vector<IndexRecord> &targetList = codexList.at(conditions.dataFeed);

        // boundary check
        if (targetList.front().from > conditions.to) { // request is for future of the available duration
            logger.log("Request is future of available duration: "s + std::to_string(conditions.from) + "(from) / "s + std::to_string(targetList.back().to) + "(right end)"s);
            return result;
        } else if (targetList.back().to < conditions.from) { // request is for past of the available duration
            logger.log("Request is past of available duration: "s + std::to_string(conditions.to) + "(to) / "s + std::to_string(targetList.back().from) + "(left end)"s);
            return result;
        }

        // fine-tune requested time duration
        if (targetList.front().from > conditions.from)
            conditions.from = targetList.front().from;
        if (targetList.back().to < conditions.to)
            conditions.to = targetList.back().to;

        // prepare for search
        result.reserve(targetList.size());
        // determine target SuperCodex files
        int codexCount = targetList.size(), left, right;
        // binary search to nearest "from"
        std::function<int(int, int, int)> binarySearch = [&](int left, int right, int target) -> int {
            while (right - left > 1) {
                int middle = (left + right) / 2, fileFrom = targetList[middle].from, fileTo = targetList[middle].to;
                if (target >= fileFrom && target < fileTo)
                    return middle;
                else if (target < fileFrom)
                    right = middle;
                else
                    left = middle;
            }

            return left;
        };

        // enumerate raw SuperCodex files
        if (conditions.cacheFrom) {
            // head
            left = binarySearch(0, codexCount, conditions.from);
            right = binarySearch(0, codexCount, conditions.cacheFrom);
            for (int i = std::max(left, 0); i <= right; ++i)
                result.push_back(targetList.at(i).file);
            // tail
            left = binarySearch(0, codexCount, conditions.cacheTo);
            right = binarySearch(0, codexCount, conditions.to);
            for (int i = std::max(left, 0); i <= right; ++i)
                result.push_back(targetList.at(i).file);
        } else {
            left = binarySearch(0, codexCount, conditions.from);
            right = binarySearch(0, codexCount, conditions.to);
            for (int i = std::max(left, 0); i <= right; ++i)
                result.push_back(targetList.at(i).file);
        }

        if (result.empty())
            logger.log("No codices for "s + std::to_string(conditions.from) + "->" + std::to_string(conditions.to));

        result.shrink_to_fit();
    } catch (std::exception &e) {
        logger.oops("(MAYBE) unexpected exception. Details: "s + e.what());
    } catch (...) {
        logger.oops("(MAYBE) unexpected exception. Details unknown"s);
    }

    return result;
}

void CodexIndex::addCodices(const std::string feedName, const std::string list)
{
    // determine current status of the feed
    uint32_t lastTo = 0;
    if (codexList.contains(feedName) && !codexList[feedName].empty())
        lastTo = codexList[feedName].back().to;

    // register new SuperCodex files
    const char *cursor = list.data(), *cursorEnd = cursor + list.size();
    std::lock_guard lockGuard(codexListLock);
    auto &targetFeed = codexList[feedName];
    while (cursor < cursorEnd) {
        // get timestamp
        uint32_t from = *(uint32_t *) cursor, to = *(uint32_t *) (cursor + 4);

        // get filename
        std::string fileName(cursor + 8);
        if (from >= lastTo) { // apply "New SuperCodex" information only when the file directs present or future of last timestamp
            targetFeed.push_back(IndexRecord{std::move(from), std::move(to), feedRoot + feedName + '/' + fileName + ".supercodex"s});
            const CodexIndex::IndexRecord &newRecord = codexList[feedName].back();
            logger.log("New SuperCodex: "s + newRecord.file + " / "s + std::to_string(newRecord.from) + " -> "s + std::to_string(newRecord.to));
        }
        // move cursor to next record
        while (*cursor != '\0')
            ++cursor;
        ++cursor;
    }
}
