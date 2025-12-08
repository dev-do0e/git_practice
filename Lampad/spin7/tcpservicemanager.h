#ifndef TCPSERVICEMANAGER_H
#define TCPSERVICEMANAGER_H

#include <string>
#include <shared_mutex>
#include <utility>
#include <ankerl/unordered_dense.h>
#include <tbb/concurrent_unordered_set.h>

#include "../loghandler.h"
#include "../supercodex.h"

namespace TcpServiceManager {
// public interface
void initialize();
void loadFromCacheFile(const std::string &filename, const size_t ipLength);

// configuration
extern int servicesCacheLimit;

// service list container
extern ankerl::unordered_dense::map<std::pair<std::string, uint16_t>, uint64_t> services; // <IP + port> + counts
extern std::shared_mutex servicesMutex;

// backend
void updateServices(const SuperCodex::Loader &loader);
std::vector<SuperCodex::Loader *> loadCodices(const std::vector<std::string> &codices, const SuperCodex::ChapterType chapterType);
void saveServices();

// logger
extern Logger logger;
}; // namespace TcpServiceManager

#endif // TCPSERVICEMANAGER_H
