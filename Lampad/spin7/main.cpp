#include <filesystem>
#include <fstream>
#include <chrono>
#include <nlohmann/json.hpp>
#include <tbb/parallel_for_each.h>

#include "../license.h"
#include "../loghandler.h"
#include "civet7.hpp"
#include "codexindex.h"
#include "datafeed.h"
#include "paradox.h"
#include "paranoia.h"
#include "subsystems.h"
#include "user.h"
#include "feedrefinertopn.h"
#include "tcpservicemanager.h"
#include "supercache.h"
#include "supercache0.h"
#include "event7.h"
#include "svcd.h"
#include "reportmanager.h"
#include "miscellany.h"

// Linux only: for stack size adjustment
#ifdef __linux__
#include <sys/resource.h>
#endif

using namespace std::string_literals;

inline std::string newSessionSeed()
{
    return SuperCodex::stringToHex(buildDigest(std::to_string(rand()) + std::to_string(rand()), EVP_sha3_256()));
}

int main(int argc, char *argv[])
{
    // Linux only: for stack size adjustment
#ifdef __linux__
    const rlim_t kStackSize = 20 * 1024 * 1024;
    struct rlimit rl;
    int result = getrlimit(RLIMIT_STACK, &rl);
    if (result == 0) {
        if (rl.rlim_cur < kStackSize) {
            rl.rlim_cur = kStackSize;
            result = setrlimit(RLIMIT_STACK, &rl);
            if (result != 0)
                fprintf(stderr, "setrlimit returned %d\n", result);
        }
    }
#endif

    // set application directory as working directory
    std::filesystem::current_path(std::filesystem::absolute(argv[0]).parent_path());

    // initialization
    Logger logger("Spin7");
    srand(time(nullptr));
    nlohmann::json settings = nlohmann::json::parse(std::ifstream("pandorasbox.json"s)), &spin7 = settings["Spin7"s];

    // check license
    auto &core = settings.at("Core");
    std::string licenseRaw = core["License"s].get<std::string>();
    if (!isValidCoreLicense(licenseRaw)) {
        logger.log("License key invalid"s);
        return -666;
    }
    std::vector<std::string> licenseSplit = splitPipes(licenseRaw);
    if (core.contains("ActiveMonitors"s)) {
        const std::string monitorLicense = core.at("ActiveMonitors"s).get<std::string>();
        unsigned int allowedUnits = std::stoi(monitorLicense.substr(monitorLicense.find('|') + 1));
        if (activeMonitorsLicenseKey(licenseSplit.back(), allowedUnits) == monitorLicense) {
            logger.log("Allowed active monitor units: "s + std::to_string(allowedUnits));
            Paradox::allowedUnits = allowedUnits;
        }
    }
    if (core.contains("Kurabit"s)) {
        if (core.at("Kurabit"s).get<std::string>() == kurabitLicenseKey(licenseSplit.back())) {
            logger.log("Kurabit subsystem activated"s);
        }
    }

    try {
        // feed root
        CodexIndex::setFeedRoot(settings["Core"s]["Feed"s].get<std::string>());

        // global IP exclusion
        if (spin7.contains("GlobalExclusion"s)) {
            logger.log("Set global IP exclusion filter");
            for (const auto &element : spin7["GlobalExclusion"s]) {
                if (element.is_string())
                    SuperCodex::Loader::addToExclusion(SuperCodex::stringFromHex(element.get<std::string>()));
                else if (element.is_array())
                    SuperCodex::Loader::addToExclusion(SuperCodex::stringFromHex(element[0].get<std::string>() + element[1].get<std::string>()));
            }
        }

        // messy room location
        FeedRefinerAbstract::messyRoom = spin7["MessyRoom"s].get<std::string>();
        SubSystems::importPcapPath = FeedRefinerAbstract::messyRoom + "/refined_importpcap";

        // start logging
        CodexIndex::logRoot = settings["Core"s]["Log"s].get<std::string>();
        if (!settings["Spin7"s]["EchoLog"s].get<bool>())
            Logger::initializeFileWrite(CodexIndex::logRoot, "Spin7"s);
        logger.logAndEcho("========================================Starting up Spin7 "s + SubSystems::spin7Version);

        // initialize TCP service manager in the background
        if (spin7.contains("ServicesCacheLimit"s))
            TcpServiceManager::servicesCacheLimit = spin7["ServicesCacheLimit"s].get<int>();
        std::thread([]() { TcpServiceManager::initialize(); }).detach();

        // update session seed as needed
        if (!spin7.contains("SessionSeed"s)) {
            logger.log("Session seed not found. Generate new one."s);
            spin7["SessionSeed"s] = newSessionSeed();
            std::ofstream file("pandorasbox.json"s, std::ios::trunc);
            const std::string dump = settings.dump();
            file.write(dump.data(), dump.size());
        }
        User::initialize(spin7["SessionSeed"s].get<std::string>(), spin7["LoginExpiration"s].get<int>());

        // configure refinery
        logger.log("Configure refinery"s);
        DataFeedRefinery::timeToClearRefineryResult = spin7["TimeToClearRefineryResult"s].get<int>();
        if (spin7.contains("MaxPayloadSizeForRegex"s))
            FeedRefinerAbstract::maxPayloadSizeForRegex = spin7["MaxPayloadSizeForRegex"s].get<long long>();
        if (spin7.contains("TopNGreedFactor"s))
            FeedRefinerTopN::greedFactorProto = spin7["TopNGreedFactor"s].get<long long>(); 

        // clean up messy room in the background to prevent from blocking startup
        logger.log("Clean up messy room"s);
        if (std::filesystem::exists(FeedRefinerAbstract::messyRoom)) {
            std::string toDelete = FeedRefinerAbstract::messyRoom;
            while (toDelete.back() == '/' || toDelete.back() == '\\')
                toDelete.pop_back();
            toDelete.append('-' + std::to_string(rand()));
            std::filesystem::rename(FeedRefinerAbstract::messyRoom, toDelete);
            std::thread([&]() {
                // get name of the messy room directory
                std::filesystem::path prefixPath = FeedRefinerAbstract::messyRoom;
                std::string prefix = std::filesystem::path(FeedRefinerAbstract::messyRoom).filename().string() + '-';
                size_t prefixSize = prefix.size();
                for (auto &entry : std::filesystem::directory_iterator(prefixPath.parent_path())) {
                    if (entry.is_directory()) {
                        const auto path = entry.path();
                        if (path.filename().string().substr(0, prefixSize) == prefix) {
                            logger.log("Clean up "s + path.string());
                            std::filesystem::remove_all(path);
                        }
                    }
                }
            }).detach();
        }
        // in this timing, messy room doesn't exist anyway - we need to create new messy room directory
        std::filesystem::create_directories(FeedRefinerAbstract::messyRoom);

        // get threshold value
        logger.log("Get threshold"s);
        FeedRefinerAbstract::trafficThrottle = std::stoull(licenseSplit[3]);

        // initialize subsystems
        SubSystems::initialize();

        // initialize codex index
        logger.log("Initialize Codex Index"s);
        if (spin7.contains("FullRescanInterval"s))
            CodexIndex::feedCleanUpInterval = spin7["FullRescanInterval"s].get<int>();
        if (spin7.contains("FeedFreeSpaceRatio"s))
            CodexIndex::feedFreeSpaceRatio = spin7["FeedFreeSpaceRatio"s].get<int>();
        if (settings["Core"s].contains("LogsToMaintain"s))
            CodexIndex::logsToMaintain = settings["Core"s]["LogsToMaintain"].get<int>();
        CodexIndex::spin7Command = argv[0];
        CodexIndex::spin7Command.append(" combinecodices "s);
        if (settings.contains("SavePcap"s))
            for (const auto &pair : settings.at("SavePcap"s).items()) {
                int duration = pair.value()["duration"].get<int>();
                if (duration > 0)
                    CodexIndex::individualFeedDuration[pair.key()] = duration;
            }
        if (spin7.contains("DoNotDelete"s))
            for (const auto &feedNameRaw : spin7.at("DoNotDelete"))
                CodexIndex::feedsToIgnoreOnCleanup.insert(feedNameRaw.get<std::string>());
        DataFeed::codexIndex = new CodexIndex();

        // initialize Paradox and Paranoia in parallel
        Paranoia::initialize();
        if (spin7.contains("ParadoxDashboardUpdateInterval"s))
            Paradox::latestUpdateIntervalInSeconds = spin7["ParadoxDashboardUpdateInterval"s].get<time_t>();
        std::thread([]() { Paradox::initialize(); }).join();

        // initialize reporting backend
        logger.log("Initialize reporting backend");
        ReportManager::start();

        // configure and start up Civet7
        logger.log("Configure Civet7");
        Civet7::staticFileRoot = spin7["StaticFileRoot"s].get<std::string>();
        Civet7::start(settings);
        logger.log("Civet7 started. Spin7 ready."s);

        // SuperCache must start after Civet7 is started
        if (spin7.contains("TlsDumpDuration"s))
            SuperCache::tlsDumpRetentionPeriod = spin7["TlsDumpDuration"s].get<uint32_t>();
        std::thread([]() { SuperCache::start(); }).detach();
        std::thread([]() { SuperCacheZero::start(); }).detach();
        std::thread([]() { Event7::start(); }).detach();
        std::thread([]() { ServiceDashboard::start(); }).detach();

        // prepare for daily chores and do it once
        DailyChore::initialize(licenseSplit[2], spin7);
        DailyChore::doIt();

        // do some chores at 1:00 AM every day
        while (true) {
            const auto next0100 = std::chrono::steady_clock::now() + std::chrono::seconds(DailyChore::next0100am() - time(nullptr));
            DailyChore::doIt();

            // see you tomorrow. ;)
            std::this_thread::sleep_until(next0100);
        }

        // this won't happen...... :P
        return 0;
    } catch (std::exception &e) {
        logger.oops("Exception occurred. Reason: "s + e.what());
        return -6;
    } catch (...) {
        logger.oops("Exception occurred. Reason unknown."s);
        return -66;
    }
}
