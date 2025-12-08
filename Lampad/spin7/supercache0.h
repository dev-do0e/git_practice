#ifndef SUPERCACHE0_H
#define SUPERCACHE0_H

#include "supercache.h"
#include "feedrefinerbasic.h"
#include "../loghandler.h"

#include <ankerl/unordered_dense.h>
#include <vector>
#include <string>

namespace SuperCacheZero {
// environmental variable(s)
extern std::string feedPath;

// startup
void start();

// actual cache builder
struct SignaturePack
{
    std::string name;
    SuperCodex::IpFilter filter; // IP addresses
    uint32_t signature;
    bool buildNow = false; // this flag is used to whether to build for this signature this time. i.e. distinguishing tags to build for phase 1 only(start to last stored in database) or both 1 and 2(after database store to most recent)
};
extern std::vector<SignaturePack> signatures;
struct Intermediate
{
    // helper struct
    struct Pack
    {
        // per second statistics
        std::vector<int64_t> bps, timeouts, rsts, dupAcks, retransmissions, zeroWindows, portReused, outOfOrders, flowCounts;
        std::vector<FeedRefinerPps::Description> pps;
        std::vector<FeedRefinerAbstract::ValuesRtt> rtts;
        // flow count special
        std::vector<uint64_t> sessionsInTail;
        ankerl::unordered_dense::set<uint64_t> sessionsFromHead;
    };

    // main members
    uint32_t from, to;
    std::vector<Pack> packs;
};
struct Final
{
    Final(const uint32_t from, const size_t size)
        : from(from)
    {
        packs = new SuperCache::Final::PerSecondPack[size]{};
    }
    ~Final() { delete[] packs; }
    uint32_t from;
    SuperCache::Final::PerSecondPack *packs;
};
std::string buildCache(const std::string &feedName, const uint32_t from);

// database
extern std::vector<std::string> dbs, ddls;

// miscellany
extern Logger logger;

} // namespace SuperCacheZero

#endif // SUPERCACHE0_H
