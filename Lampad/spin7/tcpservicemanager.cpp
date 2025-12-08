#include "tcpservicemanager.h"

#include <filesystem>
#include <fstream>

#include <ankerl/unordered_dense.h>
#include <tbb/parallel_for.h>
#include <tbb/parallel_for_each.h>

#include "codexindex.h"

using namespace std::string_literals;

int TcpServiceManager::servicesCacheLimit = 1000000; // 1 million
ankerl::unordered_dense::map<std::pair<std::string, uint16_t>, uint64_t> TcpServiceManager::services;
std::shared_mutex TcpServiceManager::servicesMutex;
Logger TcpServiceManager::logger("TcpServiceManager"s);

void TcpServiceManager::initialize()
{
    // check whether TCP service manager is enabled
    if (servicesCacheLimit == 0) {
        logger.log("TCP service cache is disabled. To enable, set Spin7->ServicesCacheLimit to positive number.");
        return;
    }

    logger.log("Initialize TcpServiceManager"s);
    // load known TCP services
    if (std::filesystem::exists("services.tcp4"s))
        loadFromCacheFile("services.tcp4"s, 4);
    if (std::filesystem::exists("services.tcp6"s))
        loadFromCacheFile("services.tcp6"s, 16);

    // if existing services are not found, try to read from SuperCodex files
    if (services.empty()) {
        // if there's no registered services, try to build new list from existing SuperCodex files
        logger.log("Loading TCP services from SuperCodex files of each data feed");
        std::vector<std::filesystem::path> feeds;
        for (const auto &feedDirectory : std::filesystem::directory_iterator(CodexIndex::feedRoot))
            if (feedDirectory.is_directory())
                feeds.push_back(feedDirectory.path());
        for (const auto &feed : feeds) {
            for (const auto &hourDirectory : std::filesystem::directory_iterator(feed))
                if (hourDirectory.is_directory()) {
                    logger.log("Rebuild TCP service cache from "s + hourDirectory.path().string());
                    // enumerate SuperCodex files
                    std::vector<std::string> codices;
                    for (const auto &file : std::filesystem::directory_iterator(hourDirectory)) {
                        std::string path = file.path().string();
                        if (path.find(".supercodex"s) == path.size() - 11)
                            codices.push_back(path);
                    }
                    std::sort(codices.begin(), codices.end());

                    // load files and register services
                    auto loaders = loadCodices(codices, SuperCodex::ChapterType::SESSIONS);
                    tbb::parallel_for_each(loaders, [&](const SuperCodex::Loader *loader) { updateServices(*loader); });
                    for (auto &loader : loaders)
                        delete loader;
                }
        }
        saveServices();
        logger.log("Recognized "s + std::to_string(services.size()) + " services from SuperCodex");
    }
}

void TcpServiceManager::loadFromCacheFile(const std::string &filename, const size_t ipLength)
{
    // determine buffer size
    size_t keyLength = ipLength + 2, bufferSize = keyLength + 8; // ip length + port length(2 byte) + count(8 byte)

    // read cache file
    std::ifstream source(filename, std::ios::binary);
    std::unique_ptr<char[]> tcpBuffer(new char[33554432]); // 32MB should be enough
    source.rdbuf()->pubsetbuf(tcpBuffer.get(), 33554432);
    char buffer[26]; // IPv6 address size + port length + count
    source.read(buffer, bufferSize);
    servicesMutex.lock();
    while (source.gcount() == bufferSize) {
        services[std::make_pair(std::string(buffer, ipLength), *(const uint16_t *) (buffer + ipLength))] = *(uint64_t *) (buffer + keyLength);
        source.read(buffer, 14);
        if (services.size() % 10000 == 0) { // unlock for a while so that others can access the service list
            servicesMutex.unlock();
            servicesMutex.lock();
        }
    }
    servicesMutex.unlock();
    servicesMutex.lock_shared();
    logger.log("Loaded services from "s + filename + ". Accumulated: "s + std::to_string(services.size()));
    servicesMutex.unlock_shared();
}

void TcpServiceManager::updateServices(const SuperCodex::Loader &loader)
{
    if (servicesCacheLimit) {
        ankerl::unordered_dense::map<std::pair<std::string, uint16_t>, uint64_t> toAppend;

        // extract TCP services
        for (const auto &pair : loader.sessions)
            if (pair.second->status & SuperCodex::Session::HASTCPSYN)
                ++toAppend[std::make_pair(SuperCodex::destinationIp(*pair.second), pair.second->destinationPort)];

        // remove any known services
        servicesMutex.lock_shared();
        for (auto i = toAppend.begin(); i != toAppend.end();)
            if (services.contains(i->first))
                i = toAppend.erase(i);
            else
                ++i;

        // enumerate services with quite low use
        std::vector<std::pair<std::string, uint16_t>> keysToDelete;
        if (services.size() > servicesCacheLimit * 3 / 2) { // we accept some overflow, since new TCP services should have very low hit count when they're first introduced
            // enumerate records to delete
            std::vector<const std::pair<std::pair<std::string, uint16_t>, uint64_t> *> pairs;
            pairs.reserve(services.size());
            for (const auto &pair : services)
                pairs.push_back(&pair);
            std::sort(pairs.begin(), pairs.end(), [](const std::pair<std::pair<std::string, uint16_t>, uint64_t> *a, const std::pair<std::pair<std::string, uint16_t>, uint64_t> *b) { return a->second < b->second; }); // ascending sort to remain enumerate keys to remove from service
            pairs.resize(services.size() - servicesCacheLimit);

            keysToDelete.reserve(pairs.size());
            for (const auto &pair : pairs)
                keysToDelete.push_back(pair->first);
        }
        servicesMutex.unlock_shared();

        // merge new services and remain only designate number of services as needed
        if (!toAppend.empty()) {
            servicesMutex.lock();

            // remove redundant services so that we don't have to reserve new room for new key(instead, use existing spaces which was used by deleted items)
            for (const auto &key : keysToDelete)
                services.erase(key);

            // merge new services
            for (const auto &pair : toAppend)
                services.insert(pair);

            servicesMutex.unlock();
        }
    }
}

std::vector<SuperCodex::Loader *> TcpServiceManager::loadCodices(const std::vector<std::string> &codices, const SuperCodex::ChapterType chapterType)
{
    return SuperCodex::parallel_convert<std::string, SuperCodex::Loader *>(codices, [&](const std::string file) -> SuperCodex::Loader * { return new SuperCodex::Loader(file, chapterType, SuperCodex::Conditions()); });
}

void TcpServiceManager::saveServices()
{
    // prepare for file stream
    std::ofstream tcp4("services.tcp4"s, std::ios::out | std::ios::binary | std::ios::trunc);
    std::unique_ptr<char[]> tcp4Buffer(new char[33554432]); // 32MB should be enough
    tcp4.rdbuf()->pubsetbuf(tcp4Buffer.get(), 33554432);
    std::ofstream tcp6("services.tcp6"s, std::ios::out | std::ios::binary | std::ios::trunc);
    std::unique_ptr<char[]> tcp6Buffer(new char[33554432]); // 32MB should be enough
    tcp6.rdbuf()->pubsetbuf(tcp6Buffer.get(), 33554432);

    // write files
    servicesMutex.lock_shared();
    for (const auto &pair : services)
        if (pair.first.first.size() == 4) { // IPv4
            tcp4.write(pair.first.first.data(), 4);
            tcp4.write((const char *) &pair.first.second, 2);
            tcp4.write((const char *) &pair.second, 8);
        } else if (pair.first.first.size() == 16) { // IPv6
            tcp4.write(pair.first.first.data(), 16);
            tcp4.write((const char *) &pair.first.second, 2);
            tcp4.write((const char *) &pair.second, 8);
        }

    // finalize
    tcp4.close();
    tcp6.close();
    servicesMutex.unlock_shared();
}
