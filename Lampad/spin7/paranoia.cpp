#include "paranoia.h"
#include "civet7.hpp"
#include "../featherlite.h"

#include <fstream>
#include <filesystem>
#include <tbb/parallel_for.h>

using namespace std::string_literals;

// extern variables
nlohmann::json Paranoia::devices = nlohmann::json::object();
std::shared_mutex Paranoia::devicesMutex, Paranoia::latestResultCacheMutex;
std::mutex Paranoia::writerMutex;
ankerl::unordered_dense::map<std::pair<std::string, std::string>, bool> Paranoia::latestResultCache;
Logger Paranoia::logger("Paranoia"s);

void Paranoia::initialize()
{
    logger.log("Initialize subsystem Paranoia");
    LogStopwatch stopwatch(&logger, "Subsystem Paranoia initialized.");

    // create database file if it doesn't exist
    if (!std::filesystem::exists("paranoia.results"s)) {
        FeatherLite feather("paranoia.results"s);
        feather.useWal();
        feather.exec("CREATE TABLE Paranoia(mac TEXT NOT NULL,testedat INTEGER,testname TEXT,testtemplate TEXT,success INT,details TEXT);"
                     "CREATE INDEX ParanoiaIdx1 ON Paranoia(mac);"
                     "CREATE INDEX ParanoiaIdx2 ON Paranoia(testedat);"
                     "CREATE INDEX ParanoiaIdx3 ON Paranoia(testname);"
                     "CREATE INDEX ParanoiaIdx4 ON Paranoia(testtemplate);"
                     "CREATE INDEX ParanoiaIdx5 ON Paranoia(success);"s);
    }

    // load device list to RAM
    try {
        devices = nlohmann::json::parse(std::ifstream("paranoia.json"s));
    } catch (std::exception &e) {
        logger.oops("Device list not found or invalid. Details: "s + e.what());
        if (std::filesystem::exists("paranoia.json")) {
            logger.oops("Removing invalid paranoia.json"s);
            std::filesystem::remove("paranoia.json");
        }
    } catch (...) {
        logger.oops("Device list not found or invalid. Details unknown.");
        if (std::filesystem::exists("paranoia.json")) {
            logger.oops("Removing invalid paranoia.json"s);
            std::filesystem::remove("paranoia.json");
        }
    }

    // enumerate all MAC addresses in the table
    { // limit life span of FeatherLite object
        std::vector<std::string> macsToCheck;
        FeatherLite feather("paranoia.results"s);
        feather.useWal();
        feather.prepare("SELECT DISTINCT mac FROM paranoia;"s);
        while (feather.next() == SQLITE_ROW)
            macsToCheck.push_back(std::string(feather.getText(0)));
        feather.reset();
        feather.finalize();

        // remove any records with invalid MAC addresses
        feather.prepare("DELETE FROM paranoia WHERE mac=?;");
        for (const auto &mac : macsToCheck)
            if (!devices.contains(mac)) {
                logger.log("Remove test results without device information: "s + mac);
                feather.bindText(1, mac);
                feather.next();
                feather.reset();
            }
        feather.finalize();
    }

    // latest result cache is rebuilt every one minute(or later if the update takes too long)
    logger.log("Rebuild latest result cache from the database");
    std::thread([&]() {
        while (true) {
            auto oneMinuteLater = std::chrono::steady_clock::now() + std::chrono::minutes(1);
            // get newest cache
            devicesMutex.lock_shared();
            auto newLatest = newLatestResultCache();
            { // limit life of FeatherLie object
                FeatherLite feather("paranoia.results"s);
                feather.useWal();
                feather.checkpoint();
            }
            devicesMutex.unlock_shared();

            // update result cache
            latestResultCacheMutex.lock();
            latestResultCache = std::move(newLatest);
            latestResultCacheMutex.unlock();

            std::this_thread::sleep_until(oneMinuteLater);
        }
    }).detach();
}

ankerl::unordered_dense::map<std::pair<std::string, std::string>, bool> Paranoia::newLatestResultCache()
{
    LogStopwatch finish(&logger, "Built new latest result cache");
    // prepare for variables
    ankerl::unordered_dense::map<std::pair<std::string, std::string>, bool> result;
    FeatherLite feather("paranoia.results"s, SQLITE_OPEN_READONLY);
    feather.useWal();
    feather.prepare("SELECT success FROM paranoia WHERE mac=? AND testname=? ORDER BY testedat DESC LIMIT 1;"s);

    // enuemrate devices and test scenarios and get latest test result for each
    for (const auto &pair : devices.items()) // for each device
        for (const auto &scenario : pair.value()["Scenarios"s]) { // for each test scenario in that device
            // build key and query the latest test result
            const std::string mac = pair.key(), name = scenario["name"s].get<std::string>();
            feather.bindText(1, mac);
            feather.bindText(2, name);
            auto key = std::make_pair(mac, name);

            // fetch result
            if (feather.next() && !feather.isNull(0))
                result[key] = feather.getInt(0) != 0;
            else { // either there was no result or database failed to fetch the result
                logger.oops("Error on creating lastest result cache. Details: "s + feather.lastError());
                if (latestResultCache.contains(key)) // if we have previous result, use it as the latest result
                    result[key] = latestResultCache[key];
                else
                    result[key] = false;
            }
            feather.reset();
        }
    feather.finalize();

    return result;
}

void Paranoia::saveDeviceList()
{
    // we assume that devicesMutex is already locked
    std::ofstream devicesFile("paranoia.json"s, std::ios::trunc); // overwrite
    devicesFile << devices;
    devicesFile.close();
}

void Paranoia::describeStatus(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    if (path.size() != 18) {
        mg_send_http_error(connection, 400, "Invalid MAC address: %s", path.data());
        return;
    }

    nlohmann::json responseBody;
    std::string mac = path.substr(1);

    // get the latest timestamp for given MAC
    uint32_t latestTestedAt = 0;
    FeatherLite feather("paranoia.results"s, SQLITE_OPEN_READONLY);
    feather.prepare("SELECT MAX(testedat) FROM paranoia WHERE mac=?;"s);
    feather.bindText(1, mac);
    if (feather.next() && !feather.isNull(0))
        latestTestedAt = feather.getInt(0);
    responseBody["StoredUpTo"s] = latestTestedAt;

    // check configuration update
    devicesMutex.lock_shared();
    if (devices.contains(mac)) {
        const auto &target = devices[mac];
        if (target.contains("ToUpdate"s) && target["ToUpdate"].get<bool>() == true) {
            responseBody["Settings"s] = target["Settings"s];
            responseBody["Scenarios"s] = target["Scenarios"s];
        }
    }
    devicesMutex.unlock_shared();

    // respond
    Civet7::respond200(connection, responseBody);

    // prepare for disk usage
    const std::string &disk = parameters.at("disk"s);
    size_t separator = disk.find('_'), volumeFree, volumeCapacity;
    if (separator != std::string::npos) { // actually, npos should NOT happen, but just in case
        volumeFree = std::stoll(disk.substr(0, separator));
        volumeCapacity = std::stoll(disk.substr(separator + 1));
    }

    // update device IP last timestamp, disk volume usage
    devicesMutex.lock();
    // if the device is brand new, set MAC address as its alias
    if (!devices.contains(mac))
        devices[mac]["Settings"s]["Alias"s] = mac;
    // set others
    auto &target = devices[mac];
    target["ip"s] = mg_get_request_info(connection)->remote_addr;
    target["lastping"s] = time(nullptr);
    if (responseBody.contains("Settings"s))
        target["ToUpdate"s] = false;
    target["VolumeFree"] = volumeFree;
    target["VolumeCapacity"] = volumeCapacity;
    saveDeviceList();
    devicesMutex.unlock();
}

void Paranoia::storeNewTestResults(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    logger.log("New test results: "s + path.substr(1));
    if (path.size() != 18) {
        mg_send_http_error(connection, 400, "Invalid MAC address: %s", path.data());
        return;
    }

    try {
        // prepare for a few variables
        time_t now = time(nullptr);
        std::string mac(path.substr(1));
        nlohmann::json requestBody = nlohmann::json::parse(parameters.at("raw"));

        // gather maximum timestamp for each test
        FeatherLite feather("paranoia.results"s);
        feather.useWal();
        feather.prepare("SELECT MAX(testedat) from paranoia WHERE mac=? and testname=?;"s);
        ankerl::unordered_dense::map<std::pair<std::string, std::string>, uint32_t> localTestedAtMax; // <mac + test name> + timestamp
        for (const auto &object : requestBody) {
            std::string testName = object["name"].get<std::string>();
            auto key = std::make_pair(mac, testName);
            if (!localTestedAtMax.contains(key)) {
                feather.bindText(1, mac);
                feather.bindText(2, testName);
                if (feather.next() && !feather.isNull(0))
                    localTestedAtMax[key] = feather.getInt(0);
                feather.next();
            }
            feather.reset();
        }
        feather.finalize();

        // write down results
        std::lock_guard writerLock(writerMutex);
        feather.prepare("INSERT INTO paranoia(mac,testedat,testname,testtemplate,success,details) VALUES(?,?,?,?,?,?)"s);
        for (const auto &object : requestBody) {
            // before going further, check timestamp sanity
            std::string testName = object["name"].get<std::string>();
            uint32_t lastTestAt = localTestedAtMax[std::make_pair(mac, testName)], testedAt = object["timestamp"].get<uint32_t>(); // lastTestAt: if the test is brand new, it'll be set to zero(0)
            if (testedAt <= lastTestAt) {
                logger.oops("Test record already inside the database: "s + testName + ": latest test at "s + std::to_string(lastTestAt) + " while timestamp for the test instance is"s + std::to_string(testedAt));
                continue;
            }
            if (testedAt > now) {
                logger.oops("Test record from the future for "s + testName + ": local time is "s + std::to_string(now) + " while timestamp for the test instance is"s + std::to_string(testedAt));
                continue;
            }

            // looks good, let's extract result elements and save
            std::string testTemplate = object["template"].get<std::string>(), details = object["details"].dump();
            bool isSuccess = object["success"].get<bool>();
            feather.bindText(1, mac);
            feather.bindInt(2, testedAt);
            feather.bindText(3, testName);
            feather.bindText(4, testTemplate);
            feather.bindInt(5, isSuccess ? 1 : 0);
            feather.bindText(6, details);
            feather.next();
            feather.reset();
        }

        // return HTTP 204 No Content
        mg_send_http_error(connection, 204, "\r\n\r\n");
    } catch (std::exception &e) {
        std::string message = "Exception on storing test results: "s + e.what();
        logger.log(message);
        mg_send_http_error(connection, 500, message.data());
    } catch (...) {
        std::string message = "Exception on storing test results: details unknown."s;
        logger.log(message);
        mg_send_http_error(connection, 500, message.data());
    }
}

void Paranoia::enumerateDevices(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // get a copy of device list
    devicesMutex.lock_shared();
    nlohmann::json copy = devices;
    devicesMutex.unlock_shared();

    if (parameters.contains("mac"s)) { // deliver value for given underscored key
        // determine which device to get the underscored key
        const std::string &mac = parameters.at("mac");
        if (!copy.contains(mac)) {
            mg_send_http_error(connection, 404, "No such MAC address");
            return;
        }
        auto &device = copy[mac];

        // find value for given key
        if (parameters.contains("scenario"s) && parameters.contains("parameter"s)) {
            const std::string &scenarioName = parameters.at("scenario"s), &parameter = parameters.at("parameter"s);
            for (const auto &scenario : device["Scenarios"])
                if (scenario["name"s].get<std::string>() == scenarioName) {
                    const auto &parameters = scenario["parameters"s];
                    if (parameters.contains(parameter)) {
                        std::string valueString;
                        const auto &value = parameters[parameter];
                        if (value.is_string())
                            valueString = value.get<std::string>();
                        else
                            valueString = value.dump();
                        Civet7::respond200(connection, valueString.data(), valueString.size(), "text/plain"s);
                        return;
                    }
                }
        }

        // no such key combination to extract value
        mg_send_http_error(connection, 400, "no parameters matching key combinations");
    } else { // enumerate normally
        // add time duration of each test
        FeatherLite feather("paranoia.results"s, SQLITE_OPEN_READONLY);
        feather.prepare("SELECT MIN(testedat),MAX(testedat),CAST(COUNT(testedat) AS INTEGER) FROM paranoia WHERE mac=? AND testname=?"s);
        for (auto &pair : copy.items())
            for (auto &scenario : pair.value()["Scenarios"]) {
                // change values for any underscored keys to null
                auto &parameters = scenario["parameters"s];
                for (auto &[key, value] : parameters.items())
                    if (!key.empty() && key[0] == '_')
                        value = nullptr;

                // bind parameters and query
                std::string mac = pair.key(), name = scenario["name"];
                feather.bindText(1, mac);
                feather.bindText(2, name);
                // merge the result
                if (feather.next() == SQLITE_ROW) {
                    scenario["savedfront"s] = feather.getInt(0);
                    scenario["savedback"s] = feather.getInt(1);
                    scenario["counts"s] = feather.getInt(2);
                }
                feather.reset();
            }

        // send result
        Civet7::respond200(connection, copy);
    }
}

void Paranoia::showLatestResults(mg_connection *connection)
{
    // pull latest test results from cache
    nlohmann::json response = nlohmann::json::array(); // empty array
    devicesMutex.lock_shared();
    for (const auto &items : devices.items()) {
        const auto &value = items.value();

        // recognize MAC address, alias
        const std::string mac = items.key();

        // for each test scenario
        for (const auto &scenario : value["Scenarios"s]) {
            nlohmann::json object;

            // general description
            object["mac"] = mac;
            object["alias"] = value["Settings"s]["Alias"s];
            object["ip"] = value["ip"];
            object["scenario"] = scenario["name"s];
            object["lastping"] = value["lastping"];
            object["VolumeFree"] = value["VolumeFree"];
            object["VolumeCapacity"] = value["VolumeCapacity"];

            // get latest result from cache if it exists
            latestResultCacheMutex.lock_shared();
            const auto key = std::make_pair(mac, scenario["name"s].get<std::string>());
            if (latestResultCache.contains(key))
                object["success"] = latestResultCache[key];
            latestResultCacheMutex.unlock_shared();

            // push object
            response.push_back(object);
        }
    }
    devicesMutex.unlock_shared();

    // sort response data
    Civet7::respond200(connection, response);
}

void Paranoia::deleteDevice(mg_connection *connection, const std::string &path)
{
    std::string mac = path.substr(1);
    std::unique_lock lock(devicesMutex);
    if (devices.contains(mac)) {
        devices.erase(mac);
        saveDeviceList();
        mg_send_http_error(connection, 204, "\r\n\r\n");
    } else
        mg_send_http_error(connection, 404, "No such MAC address registered: %s", path.data());
}

void Paranoia::changeSettings(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // initialize and check type safety
    if (!parameters.contains("raw"s)) {
        mg_send_http_error(connection, 400, "No request body.\nSend stringified JSON as raw request body with Content-Type set as application/octet-stream, or, as value for JSON key \"raw\" if you'd like to use Content-Type as application/json or application/x-www-form-urlencoded");
        return;
    }
    nlohmann::json newSettings = nlohmann::json::parse(parameters.at("raw"s));
    if (!newSettings["StoreDuration"].is_number())
        mg_send_http_error(connection, 400, "StoreDuration is not number");
    if (!newSettings["Alias"].is_string())
        mg_send_http_error(connection, 400, "Alias is not string");

    // manipulate device list
    std::string mac = path.substr(1);
    std::unique_lock lock(devicesMutex);
    if (devices.contains(mac)) {
        // update settings as needed
        auto &target = devices[mac];
        target["Settings"] = newSettings;
        target["ToUpdate"] = true;
        saveDeviceList();
        mg_send_http_error(connection, 204, "\r\n\r\n");
    } else
        mg_send_http_error(connection, 404, "No such MAC address registered: %s", path.data());
}

void Paranoia::updateTestScenarios(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // initialize and check type safety
    if (!parameters.contains("raw"s)) {
        mg_send_http_error(connection, 400, "No request body.\nSend stringified JSON as raw request body with Content-Type set as application/octet-stream, or, as value for JSON key \"raw\" if you'd like to use Content-Type as application/json or application/x-www-form-urlencoded");
        return;
    }
    nlohmann::json newScenarios = nlohmann::json::parse(parameters.at("raw"s));
    if (!newScenarios.is_array()) {
        mg_send_http_error(connection, 400, "Request body is not an array");
        return;
    }
    for (const auto &scenario : newScenarios) {
        if (scenario["name"s].is_string() && scenario["parameters"s].is_object() && scenario["template"s].is_string() && scenario["interval"s].is_number() && // test description + interval
            scenario["from"s].is_string() && scenario["from"s].get<std::string>().size() == 4 && scenario["to"s].is_string() && scenario["to"s].get<std::string>().size() == 4 && scenario["weekday"s].is_array() && scenario["weekday"s].size() == 7) // test schedule
            continue;
        else {
            mg_send_http_error(connection, 400, "Failed to pass data types and length constraints");
            return;
        }
    }

    // update test scenarios
    std::string mac = path.substr(1);
    std::unique_lock lock(devicesMutex);
    if (devices.contains(mac)) {
        // update settings as needed
        nlohmann::json &target = devices[mac], &scenarios = target["Scenarios"s], previousScenarios = target["Scenarios"];
        // overwrite scenarios
        scenarios = newScenarios;
        // "transfer" BLOB fields from previous configuration
        for (auto &scenario : scenarios) { // for each scenario from new scenarios
            // get scenario name
            const std::string &testName = scenario["name"s].get<std::string>(), &testTemplate = scenario["template"s];
            for (const auto &previousScenario : previousScenarios) // compare scenario name of new scenarios from existing scenarios
                if (previousScenario["name"s].get<std::string>() == testName && previousScenario["template"s].get<std::string>() == testTemplate) { // found scenario with same name and template from previous configuration
                    auto &parameters = scenario["parameters"s];
                    for (const auto &[key, value] : previousScenario["parameters"s].items())
                        if (!key.empty() && key[0] == '_') // BLOB fields start with underscore(_)
                            parameters[key] = value;
                }
        }
        // flag up so that the configruation can be updated
        target["ToUpdate"] = true;
        saveDeviceList();
        mg_send_http_error(connection, 204, "\r\n\r\n");
    } else
        mg_send_http_error(connection, 404, "No such MAC address registered: %s", path.data());
}

void Paranoia::postBlob(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // initialize and check type safety
    if (!parameters.contains("scenario"s) || !parameters.contains("parameter"s) || !parameters.contains("value"s)) {
        mg_send_http_error(connection, 400, "One or more required keys(scenario, parameter, value) are not found");
        return;
    }

    // manipulate device list
    std::string mac = path.substr(1);
    const std::string &scenarioName = parameters.at("scenario"s), &parameterName = parameters.at("parameter"s), &parameterValue = parameters.at("value"s);
    std::unique_lock lock(devicesMutex);
    if (devices.contains(mac)) {
        // update settings as needed
        auto &target = devices[mac];
        for (auto &scenario : target["Scenarios"])
            if (scenario["name"s].get<std::string>() == scenarioName) {
                scenario["parameters"][parameterName] = parameterValue;
                mg_send_http_error(connection, 204, "\r\n\r\n");
                saveDeviceList();
                return;
            }

        // scenario not found
        mg_send_http_error(connection, 404, "Scenario not found: %s", scenarioName.data());
    } else
        mg_send_http_error(connection, 404, "No such MAC address registered: %s", path.data());
}

void Paranoia::getTestResults(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check required parameters
    if (parameters.contains("scenario"s) && parameters.contains("from"s) && parameters.contains("to"s)) {
        try {
            // query DB for test results
            FeatherLite feather("paranoia.results"s, SQLITE_OPEN_READONLY);
            feather.prepare("SELECT testedat,testtemplate,success,details FROM paranoia WHERE mac=? AND testname=? AND testedat>=? AND testedat<=? ORDER BY testedat;"s);
            std::string mac = path.substr(1);
            feather.bindText(1, mac);
            feather.bindText(2, parameters.at("scenario"s));
            feather.bindInt(3, std::stoi(parameters.at("from")));
            feather.bindInt(4, std::stoi(parameters.at("to")));

            // build results
            nlohmann::json responseBody;
            while (feather.next() == SQLITE_ROW) {
                nlohmann::json object;
                object["testedat"s] = feather.getInt(0);
                object["template"s] = feather.getText(1);
                object["success"s] = feather.getInt(2) > 0 ? true : false;
                object["details"s] = nlohmann::json::parse(feather.getText(3));
                responseBody.push_back(object);
            }

            Civet7::respond200(connection, responseBody);
        } catch (std::exception &e) {
            logger.log("Unexpected exception. Details: "s + e.what());
            mg_send_http_error(connection, 500, "Unexpected exception. Details: %s", e.what());
        }
    } else
        mg_send_http_error(connection, 400, "One or more of required parameters is not found: scenario, from, to");
}
