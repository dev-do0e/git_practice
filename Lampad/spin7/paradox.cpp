#include "paradox.h"
#include "civet7.hpp"
#include "../sshwrapper.h"

#include <tbb/parallel_for.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <sstream>
#include <fstream>

using namespace std::string_literals;

// backend: listener process management
Logger Paradox::logger("Paradox"s);
std::mutex Paradox::dbMutex;

// backend: client device management
time_t Paradox::latestUpdateIntervalInSeconds = 60;
tbb::concurrent_hash_map<std::string, nlohmann::json> Paradox::devices;
std::shared_mutex Paradox::devicesMutex;
int Paradox::reportTimeout = 90; // default: 90 seconds
unsigned int Paradox::allowedUnits = 0; // no devices will be added
nlohmann::json Paradox::latest, Paradox::topology;
std::mutex Paradox::latestMutex;
ankerl::unordered_dense::map<std::pair<std::string, std::string>, int> Paradox::latestIndex;
std::mutex Paradox::latestIndexMutex;

void Paradox::initialize()
{
    // prepare for logging
    logger.log("Initialize Paradox");
    LogStopwatch stopwatch(&logger, "Subsystem Paradox initialized");

    // create result database as needed
    if (!std::filesystem::exists("paradox.results"s)) {
        logger.log("Create new result database table");
        FeatherLite feather("paradox.results"s);
        feather.useWal();
        feather.exec("CREATE TABLE ParadoxResults("
                     "UploadAt INTEGER,"
                     "Mac TEXT NOT NULL,"
                     "TestedAt INTEGER,"
                     "TestName TEXT,"
                     "SourceIP TEXT,"
                     "Result INTEGER,"
                     "ResultDetail INTEGER,"
                     "Rtt BIGINT,"
                     "Bps BIGINT);"
                     "CREATE INDEX ParadoxResultsIdx1 ON ParadoxResults(Mac);"
                     "CREATE INDEX ParadoxResultsIdx2 ON ParadoxResults(UploadAt);"
                     "CREATE INDEX ParadoxResultsIdx3 ON ParadoxResults(TestName);"
                     "CREATE INDEX ParadoxResultsIdx4 ON ParadoxResults(Result);"
                     "CREATE INDEX ParadoxResultsIdx5 ON ParadoxResults(TestedAt);"s);
    }

    // read device list
    try {
        // build device list
        auto raw = nlohmann::json::parse(std::ifstream("paradoxdevices.json"s));
        for (const auto &element : raw) {
            tbb::concurrent_hash_map<std::string, nlohmann::json>::accessor a;
            devices.insert(a, element["mac"s].get<std::string>());
            a->second = element;
        }

        // build initial data for latest cache
        logger.log("Build initial data for latest cache"s);
        updateLatest();
    } catch (std::exception &e) {
        logger.oops("Device list not found or invalid. Details: "s + e.what());
        if (std::filesystem::exists("paradoxdevices.json")) {
            logger.oops("Removing invalid paradoxdevices.json"s);
            std::filesystem::remove("paradoxdevices.json");
        }
    } catch (...) {
        logger.oops("Device list not found or invalid. Details unknown.");
        if (std::filesystem::exists("paradoxdevices.json")) {
            logger.oops("Removing invalid paradoxdevices.json"s);
            std::filesystem::remove("paradoxdevices.json");
        }
    }

    // populate latest index
    if (std::filesystem::exists("paradoxorders.json"s))
        latestIndex = newLatestIndex(static_cast<std::stringstream const &>(std::stringstream() << std::ifstream("paradoxorders.json"s, std::ifstream::binary).rdbuf()).str());

    // start detached thread to update the status per every given interval
    std::thread([&]() {
        while (true) {
            auto updateInterval = std::chrono::steady_clock::now() + std::chrono::seconds(latestUpdateIntervalInSeconds);
            try {
                updateLatest();
            } catch (std::exception &e) {
                logger.oops("Failed to generate new latest cache. Details: "s + e.what());
            } catch (...) {
                logger.oops("Failed to generate new latest cache. Details unknown."s);
            }
            std::this_thread::sleep_until(updateInterval);
        }
    }).detach();
}

void Paradox::updateTestResults(mg_connection *connection, const std::string &macAddress, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check required parameters
    if (!parameters.contains("profiles"s) || !parameters.contains("results"s)) {
        logger.oops("Missing either 'profiles' or 'results'."s);
        mg_send_http_error(connection, 400, "Critical: missing either 'profiles' or 'results'.");
        return;
    }

    // recognize device
    std::string latestSourceIp = mg_get_request_info(connection)->remote_addr;
    logger.log("Update test results from "s + macAddress + " / "s + latestSourceIp);

    // if this is brand new device, register its description
    if (devices.count(macAddress) == 0) {
        if (devices.size() < allowedUnits)
            updateDeviceDescription2(macAddress, parameters);
        else {
            logger.oops("Exceeding device registration quota. Ignoring update request"s);
            mg_send_http_error(connection, 403, "Warning: exceeding device registration quota. Ignoring update request");
            return;
        }
    }

    // update latest connection information (keep alive timestamp + source IP)
    updateLastConnection(macAddress, mg_get_request_info(connection)->remote_addr);

    // check the time of update
    int lastUpdateAt = lastUpdateTime(macAddress);
    int updateAt = time(nullptr);

    // prepare for database push
    std::lock_guard dbWriterLock(dbMutex);
    FeatherLite feather("paradox.results"s);
    feather.prepare("INSERT INTO ParadoxResults(UploadAt, Mac, TestName, SourceIP, TestedAt, Result, ResultDetail, RTT, BPS) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);"s);

    // push test results
    const std::string &testResultsParameters = parameters.at("results");
    yyjson_doc *document;
    yyjson_val *root;
    document = yyjson_read(testResultsParameters.data(), testResultsParameters.size(), YYJSON_READ_NOFLAG);
    root = yyjson_doc_get_root(document);
    if (yyjson_is_arr(root)) {
        time_t now = time(nullptr), lastNegativeRttAt = 0;
        yyjson_arr_iter iter = yyjson_arr_iter_with(root);
        for (yyjson_val *object = yyjson_arr_iter_next(&iter); object; object = yyjson_arr_iter_next(&iter)) {
            // values for each key
            yyjson_val *testName = yyjson_obj_getn(object, "testname", 8);
            const std::string testNameString(yyjson_get_str(testName), yyjson_get_len(testName));
            auto timestamp = yyjson_get_int(yyjson_obj_getn(object, "timestamp", 9));
            // sanity test against timestamp("tested at")
            if (timestamp <= lastUpdateAt) {
                logger.oops("Timetamp from test record overlaps("s + testNameString + "). Test time is "s + std::to_string(timestamp) + " while we have data until "s + std::to_string(lastUpdateAt));
                continue;
            } else if (timestamp > now) {
                logger.oops("Test from the future("s + testNameString + "). local time "s + std::to_string(now) + " / test time: "s + std::to_string(timestamp));
                continue;
            }

            // check record sanity: if result is 8(success), but RTT or BPS is negative, simply skip it
            int result = yyjson_get_int(yyjson_obj_getn(object, "result", 6));
            long long rtt = yyjson_get_sint(yyjson_obj_getn(object, "rtt", 3)), bps = yyjson_get_sint(yyjson_obj_getn(object, "bps", 3));
            if (result == 8 && (rtt < -1 || bps < -1)) {
                lastNegativeRttAt = timestamp;
                continue;
            }

            // push test result to the database
            feather.bindInt(1, updateAt);
            feather.bindText(2, macAddress);
            feather.bindText(3, testNameString);
            feather.bindText(4, latestSourceIp);
            feather.bindInt(5, timestamp);
            feather.bindInt(6, result);
            feather.bindInt(7, yyjson_get_int(yyjson_obj_getn(object, "resultdetail", 12)));
            feather.bindInt64(8, rtt);
            feather.bindInt64(9, bps);
            if (feather.next() != SQLITE_DONE) {
                logger.oops("Failed to update results"s);
                mg_send_http_error(connection, 500, "Failed to update results. Please report to the administrator");
                yyjson_doc_free(document);
                return;
            }
            feather.reset();
        }

        // if there was negative RTT, just mention it here
        if (lastNegativeRttAt > 0)
            logger.oops("Found negative RTT. Last timestamp: "s + std::to_string(lastNegativeRttAt));
    }
    feather.finalize();
    yyjson_doc_free(document);

    // finally, determine whether to update device configuration
    tbb::concurrent_hash_map<std::string, nlohmann::json>::accessor a;
    devices.insert(a, macAddress);
    auto &description = a->second;
    if (description.contains("configurationChangeApplied"s) && !description["configurationChangeApplied"s].get<bool>()) {
        // build response body
        nlohmann::json body;
        body["alias"s] = description["alias"s];
        body["ethtests"s] = description["ethtests"s];

        // Civet7::respond200() works within Lampad authentication, so we've got to do it manually
        const std::string bodyString = body.dump();
        logger.log("Send configuration update to "s + macAddress);
        mg_send_http_ok(connection, "application/json", bodyString.size());
        mg_printf(connection, bodyString.data());

        // record changes
        description["configurationChangeApplied"s] = true;
        saveDeviceDescription();
    } else
        mg_send_http_error(connection, 204, "\r\n\r\n");
}

void Paradox::deleteDeviceOrResults(mg_connection *connection, const std::string &macAddress, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check existence of the mac address
    if (devices.count(macAddress) == 0) {
        mg_send_http_error(connection, 404, "MAC address not found: %s", macAddress.data());
        return;
    }

    std::lock_guard dbWriterLock(dbMutex);
    // check parameters
    int testedAt = 0;
    if (parameters.contains("from"))
        try {
            testedAt = std::stoi(parameters.at("from"s));
        } catch (std::exception &e) {
            mg_send_http_error(connection, 400, "Failed to convert parameter 'from' to integer. Check your request body. Details: %s", e.what());
            return;
        }
    std::string testName;
    if (parameters.contains("testname"s))
        testName = parameters.at("testname"s);

    // determine whether this is to delete everything or only selected
    if (testedAt == 0 && testName.empty()) { // no parameters: remove the device completely
        devices.erase(macAddress);
        saveDeviceDescription();
        FeatherLite feather("paradox.results"s);
        feather.prepare("DELETE FROM ParadoxResults WHERE mac=?1;"s);
        feather.bindText(1, macAddress);
        if (feather.next() != SQLITE_DONE) {
            mg_send_http_error(connection, 500, "Failed on deleting test results. Please report to the administrator");
            return;
        }
    } else { // delete only given test results
        FeatherLite feather("paradox.results"s);
        feather.prepare("DELETE FROM ParadoxResults WHERE mac=?1 AND testname=?2 AND testedat<=?3;"s);
        feather.bindText(1, macAddress);
        feather.bindText(2, parameters.at("testname"s));
        feather.bindInt(3, testedAt);

        if (feather.next() != SQLITE_DONE) {
            mg_send_http_error(connection, 500, "Failed on deleting test results. Please report to the administrator");
            return;
        }
    }

    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void Paradox::getLastUpdateTime(mg_connection *connection, const std::string &macAddress)
{
    // check existence of the mac address
    if (devices.count(macAddress) == 0) {
        mg_send_http_error(connection, 404, "MAC address not found: %s", macAddress.data());
        return;
    }

    // get latest test time
    std::string timestamp;
    const int lastUpdate = lastUpdateTime(macAddress);
    if (lastUpdate == -1) {
        mg_send_http_error(connection, 500, "Encountered server error. Please report to server administrator.");
        return;
    } else
        timestamp = std::to_string(lastUpdate);

    // update client connection information, which is used as keep alive
    updateLastConnection(macAddress, mg_get_request_info(connection)->remote_addr);

    // Civet7::respond200() works within Lampad authentication, so we rely on manual transmission
    mg_send_http_ok(connection, "text/plain", timestamp.size());
    mg_printf(connection, timestamp.data());
}

void Paradox::updateLastConnection(const std::string &macAddress, const char *remoteAddress)
{
    // update connection information only if we have record
    if (devices.count(macAddress)) {
        tbb::concurrent_hash_map<std::string, nlohmann::json>::accessor a;
        devices.insert(a, macAddress);
        auto &description = a->second;
        description["lastConnection"s] = time(nullptr);
        description["latestSourceIp"s] = remoteAddress;
        a.release();
        saveDeviceDescription();
    }
}

uint32_t Paradox::lastUpdateTime(const std::string &macAddress)
{
    // check latest timestamp stored in the database
    FeatherLite feather("paradox.results"s, SQLITE_OPEN_READONLY);
    feather.prepare("SELECT CAST(MAX(TestedAt) AS INTEGER) FROM ParadoxResults WHERE mac=?1"s);
    feather.bindText(1, macAddress);
    if (feather.next() == SQLITE_ROW)
        return feather.getInt(0);
    else
        return 0;
}

void Paradox::saveDeviceDescription()
{
    nlohmann::json array;
    for (const auto &pair : devices)
        array.push_back(pair.second);
    std::ofstream file("paradoxdevices.json"s, std::ios::trunc);
    file << array;
    file.close();
}

void Paradox::updateLatest()
{
    // get a copy of latest
    latestMutex.lock();
    auto latestCopy = latest;
    auto topologyCopy = topology;
    latestMutex.unlock();
    if (!latestCopy.is_array())
        latestCopy = nlohmann::json::array();
    if (!topologyCopy.is_array())
        topologyCopy = nlohmann::json ::array();

    // prepare for a few stuff
    nlohmann::json newLatest = nlohmann::json::array(), newTopology = nlohmann::json::array();
    FeatherLite featherLatest("paradox.results"s, SQLITE_OPEN_READONLY), featherAverage("paradox.results"s, SQLITE_OPEN_READONLY);
    featherLatest.prepare("SELECT testedat, result, rtt, bps FROM paradoxresults WHERE mac=?1 AND testname=?2 ORDER BY testedat DESC LIMIT 1;"s);
    featherAverage.prepare("SELECT CAST(AVG(rtt) AS BIGINT), CAST(AVG(bps) AS BIGINT) FROM paradoxresults WHERE mac=?1 AND testname=?2 AND testedat>=?3 AND result=8;"s);

    // get description for device and test
    for (const auto &device : devices) {
        // describe device, which is common for the tests inside same device
        const auto &mac = device.first;
        const auto &description = device.second;
        newTopology.push_back(nlohmann::json::object());
        auto &deviceDescriptionCopy = newTopology.back();
        deviceDescriptionCopy["mac"s] = device.first;
        deviceDescriptionCopy["device_name"s] = description["alias"s];
        deviceDescriptionCopy["device_ip"s] = "unknown"s;
        if (description.contains("latestSourceIp"s))
            deviceDescriptionCopy["device_ip"s] = description["latestSourceIp"s];

        // determine responsiveness(or report timeout)
        bool responsive = false;
        if (description.contains("lastConnection"s))
            responsive = (description["lastConnection"s].get<int32_t>() >= time(nullptr) - reportTimeout);
        deviceDescriptionCopy["responsive"s] = responsive;
        if (responsive)
            deviceDescriptionCopy["scenario_status"s] = 0;
        else
            deviceDescriptionCopy["scenario_status"s] = 3;
        auto &deviceStatusCopy = deviceDescriptionCopy["scenario_status"s];

        const auto &ethtests = description["ethtests"s];
        if (ethtests.contains("scenarios"s) && ethtests["scenarios"s].is_array()) { // check edge case: there's no tests registered
            int deviceStatus = 0; // 0: nothing, 1: upper threshold 1, 2: upper threshold 2, 3: timeout
            for (const auto &profile : ethtests["scenarios"s]) {
                // describe each test
                const std::string testName = profile["name"s].get<std::string>();
                auto element = nlohmann::json::object();
                element["name"s] = testName;
                element["scenario"s] = profile["scenario"s];
                element["server"s] = profile["server"s];
                auto &threshold = element["threshold"s];
                if (profile.contains("threshold1")) {
                    element["threshold1"s] = profile["threshold1"s]; // for /paradox/latest
                    threshold["warning"s] = profile["threshold1"s];
                }
                if (profile.contains("threshold2")) {
                    element["threshold2"s] = profile["threshold2"s]; // for /paradox/latest
                    threshold["critical"s] = profile["threshold2"s];
                }

                // set viewhint
                const std::string scenarioString = element["scenario"].get<std::string>();
                if (scenarioString.find("Upload"s) != std::string::npos)
                    element["value_type"s] = "upload"s;
                else if (scenarioString.find("Download"s) != std::string::npos)
                    element["value_type"s] = "download"s;
                else
                    element["value_type"s] = "rtt"s;
                element["viewhint"s] = element["value_type"s]; // TODO: delete when /paradox/latest is removed

                // obtain latest test record
                featherLatest.bindText(1, mac);
                featherLatest.bindText(2, testName);
                if (featherLatest.next() == SQLITE_ROW) {
                    const uint32_t testedAt = featherLatest.getInt64(0);
                    element["tested_at"s] = testedAt;
                    element["testedat"s] = testedAt; // TODO: delete when /paradox/latest is removed
                    element["test_result"s] = featherLatest.getInt(1); // latest test result
                    element["result"s] = featherLatest.getInt(1); // TODO: delete when /paradox/latest is removed
                    std::function<void(const long long, const std::string &)> setTestValue = [&](const long long value, const std::string &key) {
                        if (value == -1)
                            element[key] = nullptr;
                        else
                            element[key] = value;
                    };
                    setTestValue(featherLatest.getInt64(2), "rtt_last"s);
                    setTestValue(featherLatest.getInt64(3), "bps_last"s);

                    // get average test value for last 60 seconds
                    featherAverage.bindText(1, mac);
                    featherAverage.bindText(2, testName);
                    featherAverage.bindInt64(3, testedAt - 60);
                    featherAverage.next();
                    if (featherAverage.isNull(0))
                        element["rtt"s] = nullptr;
                    else
                        setTestValue(featherAverage.getInt64(0), "rtt"s);
                    if (featherAverage.isNull(1))
                        element["bps"s] = nullptr;
                    else
                        setTestValue(featherAverage.getInt64(1), "bps"s);
                } else { // no record. :P
                    logger.oops("No record for "s + mac + ' ' + testName);
                    int lastResult = 0;
                    // get last result
                    for (const auto &element : latestCopy)
                        if (element["mac"s] == mac) {
                            lastResult = element["result"s];
                            logger.oops("Fill last result with previous one"s);
                            break;
                        }

                    // build data
                    element["tested_at"s] = 0;
                    element["testedat"s] = 0; // TODO: delete when /paradox/latest is removed
                    element["result"s] = lastResult;
                    element["rtt"s] = nullptr;
                    element["bps"s] = nullptr;
                    element["rtt_last"s] = nullptr;
                    element["bps_last"s] = nullptr;
                }

                // determine latest device status
                int testStatus = 0;
                if (element["result"s] != 8)
                    testStatus = 3;
                else { // test result code is 8: test complete
                    // determine which value(RTT vs. BPS) to compare against threshold(s)
                    unsigned long long value;
                    if (element["viewhint"s] == "rtt"s)
                        value = element["rtt"s].is_null() ? 0 : element["rtt"s].get<uint64_t>();
                    else
                        value = element["bps"s].is_null() ? 0 : element["bps"s].get<uint64_t>();

                    // compare against threshold(s)
                    if (element.contains("threshold1"s)) { // threshold1 may NOT exist
                        const uint64_t threshold = element["threshold1"s];
                        if (threshold > 0 && threshold < value)
                            testStatus = 1;
                    }
                    if (element.contains("threshold2"s)) {
                        const uint64_t threshold = element["threshold2"s];
                        if (threshold > 0 && threshold < value)
                            testStatus = 2;
                    }
                }
                if (deviceStatus < testStatus)
                    deviceStatus = testStatus;

                // push result
                deviceDescriptionCopy["scenario_list"s].push_back(element);
                // TODO: delete when /paradox/latest is removed - start
                element["mac"s] = deviceDescriptionCopy["mac"s];
                element["alias"s] = deviceDescriptionCopy["device_name"s];
                element["sourceip"s] = deviceDescriptionCopy["device_ip"s];
                element["responsive"s] = deviceDescriptionCopy["responsive"s];
                newLatest.push_back(std::move(element));
                // TODO: delete when /paradox/latest is removed - end

                // reset DB connector
                featherLatest.reset();
                featherAverage.reset();
            }

            // TODO: if `/paradox/latest` is not used anymore(removed), move timeout determinination part to here
            if (deviceStatusCopy.get<int>() < deviceStatus)
                deviceStatusCopy = deviceStatus;
        }
    }

    featherLatest.finalize();
    featherAverage.finalize();

    latestMutex.lock();
    latest = newLatest;
    topology = newTopology;
    latestMutex.unlock();
}

ankerl::unordered_dense::map<std::pair<std::string, std::string>, int> Paradox::newLatestIndex(const std::string &rawJson)
{
    ankerl::unordered_dense::map<std::pair<std::string, std::string>, int> result;

    yyjson_doc *document = yyjson_read(rawJson.data(), rawJson.size(), YYJSON_READ_NOFLAG);
    yyjson_val *root = yyjson_doc_get_root(document);
    yyjson_val *object;
    yyjson_arr_iter iter = yyjson_arr_iter_with(root);
    while ((object = yyjson_arr_iter_next(&iter))) {
        // build key for latest cache
        std::string mac = yyjson_get_str(yyjson_obj_getn(object, "mac", 3)), name = yyjson_get_str(yyjson_obj_getn(object, "name", 4));
        result[std::make_pair(mac, name)] = yyjson_get_int(yyjson_obj_getn(object, "index", 5));
    }

    return result;
}

void Paradox::updateDeviceDescription(mg_connection *connection, const std::string &macAddress, const ankerl::unordered_dense::map<std::string, std::string> &parameters, const std::string &sourceIp)
{
    // update device description
    if (macAddress.find(':') == std::string::npos && macAddress.size() == 12) {
        // add colons between 2 hex digits
        std::string macWithColons;
        for (int i = 0; i < 12; i += 2)
            macWithColons.append(macAddress.substr(i, 2)).push_back(':');
        macWithColons.pop_back(); // remove last colon in the tail
        updateDeviceDescription2(macWithColons, parameters);
    } else
        updateDeviceDescription2(macAddress, parameters);
    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void Paradox::updateDeviceDescription2(const std::string &macAddress, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    logger.log("Update device descriptions for "s + macAddress);

    // open the device: since we have no idea about which data is available for this, we've got to overwrite specific values, rather than replace the whole JSON data itself. For example, if this is called via PUT /paradox public API, only "alias" and "ethtests" will be available, but not "scenarios"
    tbb::concurrent_hash_map<std::string, nlohmann::json>::accessor a;
    devices.insert(a, macAddress);
    nlohmann::json &description = a->second;

    // prepare for variable to store device description element
    description["mac"s] = macAddress;
    description["scenarios"s] = nlohmann::json::parse(parameters.at("scenarios"s));
    description["configurationChangeApplied"s] = false;

    // recognize device name(or, alias)
    auto &alias = description["alias"s];
    if (!parameters.contains("alias"s) || parameters.at("alias"s).empty())
        alias = macAddress;
    else
        alias = parameters.at("alias"s);

    // update tests
    if (parameters.contains("ethtests"s))
        description["ethtests"s] = nlohmann::json::parse(parameters.at("ethtests"s));
    if (!description["ethtests"s].contains("scenarios"s)) // for brand new devices without any test scenarios, add blank array for ethtests scenarios
        description["ethtests"s]["scenarios"s] = nlohmann::json::array();

    // apply changes
    saveDeviceDescription();
}

void Paradox::enumerateDevices(mg_connection *connection)
{
    // count number of records per test
    struct RecordsPerTest
    {
        int64_t numberOfRecords;
        int from, to;
    };
    ankerl::unordered_dense::map<std::pair<std::string, std::string>, RecordsPerTest> recordsPerTests; // <MAC address + test name> + test statistics and descriptions
    FeatherLite feather("paradox.results"s, SQLITE_OPEN_READONLY);
    feather.prepare("SELECT MAC, TestName, COUNT(TestName), MIN(TestedAt), MAX(TestedAt) FROM ParadoxResults GROUP BY MAC, TestName;"s);
    while (feather.next() == SQLITE_ROW)
        recordsPerTests[std::make_pair(std::string(feather.getText(0)), std::string(feather.getText(1)))] = RecordsPerTest{feather.getInt64(2), feather.getInt(3), feather.getInt(4)};

    // build result body
    nlohmann::json body;
    for (const auto &pair : devices) {
        // prepare for variables
        nlohmann::json object;
        auto &description = pair.second;

        // push data
        object["mac"s] = pair.first;
        object["alias"s] = description["alias"s];
        if (description.contains("latestSourceIp"s))
            object["deviceip"s] = description["latestSourceIp"s];
        else
            object["deviceip"s] = "unknown"s;
        object["ethtests"s] = description["ethtests"s];
        object["scenarios"s] = description["scenarios"s];
        auto &records = object["records"s];
        if (description["ethtests"s].contains("scenarios"s)) // there may NOT be any "scenarios" if there's no scenario from the device
            for (const auto &profile : description["ethtests"s]["scenarios"s]) {
                const std::pair<std::string, std::string> key = std::make_pair(pair.first, profile["name"s].get<std::string>());
                auto &target = records[key.second];
                if (recordsPerTests.contains(key)) {
                    const auto &record = recordsPerTests[key];
                    target["savedrecords"s] = record.numberOfRecords;
                    target["from"s] = record.from;
                    target["to"s] = record.to;
                } else {
                    target["savedrecords"s] = 0;
                    target["from"s] = 0;
                    target["to"s] = 0;
                }
            }
        if (description.contains("lastConnection"s))
            object["responsive"s] = (description["lastConnection"s].get<int32_t>() >= time(nullptr) - reportTimeout);
        else
            object["responsive"s] = false;
        body.push_back(object);
    }

    // sort device list per alias
    std::sort(body.begin(), body.end(), [](const nlohmann::json &a, const nlohmann::json &b) -> bool { return a["alias"s].get<std::string>() < b["alias"s].get<std::string>(); });

    // send list
    Civet7::respond200(connection, body);
}

void Paradox::getResults(mg_connection *connection, const std::string &macAddress, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check existence of MAC address
    if (devices.count(macAddress) == 0) {
        mg_send_http_error(connection, 404, "No such MAC address.");
        return;
    }

    // check and set lookback window
    long long from = 0, to = UINT32_MAX, lookback = 0, bindValue = 0;
    std::string name, type;
    try {
        if (parameters.contains("from"s) && !parameters.at("from"s).empty())
            from = std::stoi(parameters.at("from"s));
        if (parameters.contains("to"s) && !parameters.at("to"s).empty())
            to = std::stoi(parameters.at("to"s));
        if (parameters.contains("lookback"s) && !parameters.at("lookback"s).empty())
            lookback = std::stoi(parameters.at("lookback"s));
        if (parameters.contains("name"s) && !parameters.at("name"s).empty())
            name = parameters.at("name"s);
        if (parameters.contains("bind"s) && !parameters.at("bind"s).empty())
            bindValue = std::stoi(parameters.at("bind"s));
        if (parameters.contains("type"s) && !parameters.at("type"s).empty())
            type = parameters.at("type"s);
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to parse numeric parameters to decimal number.");
        return;
    }

    // query data
    FeatherLite feather("paradox.results"s, SQLITE_OPEN_READONLY);

    // prepare query to enumerate results in JSON or tab separated format
    if (lookback) {
        if (name.empty()) {
            feather.prepare("SELECT TestName, TestedAt, SourceIP, Result, ResultDetail, Rtt, Bps FROM ParadoxResults WHERE Mac=?1 ORDER BY TestName, TestedAt DESC OFFSET 0 ROW FETCH FIRST " + std::to_string(lookback) + " ROWS ONLY;"s);
            feather.bindText(1, macAddress);
        } else {
            feather.prepare("SELECT TestName, TestedAt, SourceIP, Result, ResultDetail, Rtt, Bps FROM ParadoxResults WHERE Mac=?1 AND TestName=?2 ORDER BY TestName, TestedAt DESC OFFSET 0 ROW FETCH FIRST " + std::to_string(lookback) + " ROWS ONLY;"s);
            feather.bindText(1, macAddress);
            feather.bindText(2, name);
        }
    } else if (from >= 0) {
        // check whether test name exists
        if (name.empty()) {
            feather.prepare("SELECT TestName, TestedAt, SourceIP, Result, ResultDetail, Rtt, Bps FROM ParadoxResults WHERE Mac=?1 AND TestedAt>=?2 AND TestedAt<=?3 ORDER BY TestName, TestedAt;"s);
            feather.bindText(1, macAddress);
            feather.bindInt(2, from);
            feather.bindInt(3, to);
        } else {
            feather.prepare("SELECT TestName, TestedAt, SourceIP, Result, ResultDetail, Rtt, Bps FROM ParadoxResults WHERE Mac=?1 AND TestName=?4 AND TestedAt>=?2 AND TestedAt<=?3 ORDER BY TestName, TestedAt;"s);
            feather.bindText(1, macAddress);
            feather.bindInt(2, from);
            feather.bindInt(3, to);
            feather.bindText(4, name);
        }
    } else { // from<0, meaning we need step backward
        if (name.empty()) {
            feather.prepare("SELECT TestName, TestedAt, SourceIP, Result, ResultDetail, Rtt, Bps FROM ParadoxResults WHERE Mac=?1 AND TestedAt>=(SELECT max(TestedAt) FROM ParadoxResults WHERE Mac=?1)"s + std::to_string(from) + " ORDER BY TestName, TestedAt;"s);
            feather.bindText(1, macAddress);
        } else {
            feather.prepare("SELECT TestName, TestedAt, SourceIP, Result, ResultDetail, Rtt, Bps FROM ParadoxResults WHERE Mac=?1 AND TestName=?2 AND TestedAt>=(SELECT max(TestedAt) FROM ParadoxResults WHERE Mac=?1 AND TestName=?2)"s + std::to_string(from) + " ORDER BY TestName, TestedAt;"s);
            feather.bindText(1, macAddress);
            feather.bindText(2, name);
        }
    }

    // send result
    if (!type.empty() && type[0] == 's')
        getResultsVersionSsh(connection, type, macAddress, parameters);
    else if (type == "tabseparated")
        getResultsTabSeparated(macAddress, feather, connection);
    else
        getResultsDefault(macAddress, feather, bindValue, connection);
}

void Paradox::getResultsDefault(const std::string &macAddress, FeatherLite &feather, int bindValue, mg_connection *connection)
{
    // prepare for results
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *root = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, root);
    std::string currentTest;

    // variables for "bind" option
    int timestamp = 0, now = 0, timestampNext = 0, timestampRttMax = 0, timestampBpsMax = 0, timestampRttMin = 0, timestampBpsMin = 0;
    long long rttSum = 0, rttCount = 0, rttMax = 0, rttMin = INT64_MAX, bpsSum = 0, bpsCount = 0, bpsMax = 0, bpsMin = INT64_MAX, errors = 0;
    std::function<void()> resetBindingValues = [&]() {
        timestampRttMax = 0;
        timestampBpsMax = 0;
        timestampRttMin = 0;
        timestampBpsMin = 0;
        rttSum = 0;
        rttCount = 0;
        rttMax = 0;
        rttMin = INT64_MAX;
        bpsSum = 0;
        bpsCount = 0;
        bpsMax = 0;
        bpsMin = INT64_MAX;
        errors = 0;
    };

    // write down results
    yyjson_mut_val *object = nullptr, *results = nullptr;
    size_t rowCount = 0;
    while (feather.next() == SQLITE_ROW) {
        ++rowCount;
        // write test result
        std::string_view testName = feather.getText(0);
        if (currentTest != testName) {
            // if binding is enabled, write down final values
            if (!currentTest.empty() && bindValue) {
                yyjson_mut_val *object2 = yyjson_mut_obj(document);
                yyjson_mut_arr_append(results, object2);
                yyjson_mut_obj_add_int(document, object2, "timestamp", timestamp);
                yyjson_mut_obj_add_int(document, object2, "rttsum", rttSum);
                yyjson_mut_obj_add_int(document, object2, "rttcount", rttCount);
                yyjson_mut_obj_add_int(document, object2, "rttmax", rttMax);
                yyjson_mut_obj_add_int(document, object2, "timestamprttmax", timestampRttMax);
                yyjson_mut_obj_add_int(document, object2, "rttmin", rttCount == 0 ? 0 : rttMin);
                yyjson_mut_obj_add_int(document, object2, "timestamprttmin", timestampRttMin);
                yyjson_mut_obj_add_int(document, object2, "bpssum", bpsSum);
                yyjson_mut_obj_add_int(document, object2, "bpscount", bpsCount);
                yyjson_mut_obj_add_int(document, object2, "bpsmax", bpsMax);
                yyjson_mut_obj_add_int(document, object2, "timestampbpsmax", timestampBpsMax);
                yyjson_mut_obj_add_int(document, object2, "bpsmin", bpsCount == 0 ? 0 : bpsMin);
                yyjson_mut_obj_add_int(document, object2, "timestampbpsmin", timestampBpsMin);
                yyjson_mut_obj_add_int(document, object2, "errors", errors);
            }

            // prepare for test description
            currentTest = std::move(testName); // from here, testName is not used anymore
            // describe new test
            tbb::concurrent_hash_map<std::string, nlohmann::json>::const_accessor a;
            if (devices.find(a, macAddress)) {
                bool foundProfile = false;
                // find out whether there's test with given name from the database table
                for (const auto &profile : a->second["ethtests"s]["scenarios"s])
                    if (profile["name"].get<std::string>() == currentTest) {
                        foundProfile = true;
                        // describe test
                        object = yyjson_mut_obj(document);
                        yyjson_mut_arr_append(root, object);
                        std::string temp;
                        temp = profile["name"s];
                        yyjson_mut_obj_add_strncpy(document, object, "testname", temp.data(), temp.size());
                        temp = profile["scenario"s];
                        yyjson_mut_obj_add_strncpy(document, object, "scenario", temp.data(), temp.size());
                        if (temp.find("Upload"s) != std::string::npos)
                            yyjson_mut_obj_add_strn(document, object, "viewhint", "upload", 6);
                        else if (temp.find("Download"s) != std::string::npos)
                            yyjson_mut_obj_add_strn(document, object, "viewhint", "download", 8);
                        else
                            yyjson_mut_obj_add_strn(document, object, "viewhint", "rtt", 3);
                        temp = feather.getText(2);
                        yyjson_mut_obj_add_strncpy(document, object, "sourceip", temp.data(), temp.size());
                        temp = profile["server"s];
                        const size_t separatorIndex = temp.find(':');
                        yyjson_mut_obj_add_int(document, object, "destinationport", std::stoi(temp.substr(separatorIndex + 1)));
                        temp.erase(separatorIndex);
                        yyjson_mut_obj_add_strncpy(document, object, "destinationip", temp.data(), temp.size());
                        int64_t threshold1 = 0, threshold2 = 0;
                        if (profile.contains("threshold1"))
                            threshold1 = profile["threshold1"s].get<int64_t>();
                        if (profile.contains("threshold2"))
                            threshold2 = profile["threshold2"s].get<int64_t>();
                        yyjson_mut_obj_add_int(document, object, "threshold1", threshold1);
                        yyjson_mut_obj_add_int(document, object, "threshold2", threshold2);
                        // add "results" array
                        results = yyjson_mut_arr(document);
                        yyjson_mut_obj_add(object, yyjson_mut_str(document, "results"), results);

                        // reset timestamp for binding
                        resetBindingValues();
                        timestamp = feather.getInt(1);
                        timestampNext = timestamp + bindValue;

                        // instantly break loop
                        break;
                    }

                // if we didn't find profile, the test is deleted - skip related records
                if (!foundProfile) {
                    currentTest.clear();
                    continue;
                }
            } // we do nothing for any records without detailed test profile, since they'll be removed as time goes(and as of Mar.11th 2024 there's no request from GUI for results from multiple tests
        }

        if (bindValue == 0) {
            yyjson_mut_val *object2 = yyjson_mut_obj(document);
            yyjson_mut_arr_append(results, object2);
            yyjson_mut_obj_add_int(document, object2, "testedat", feather.getInt(1));
            yyjson_mut_obj_add_int(document, object2, "result", feather.getInt(3));
            yyjson_mut_obj_add_int(document, object2, "resultdetail", feather.getInt(4));
            yyjson_mut_obj_add_int(document, object2, "rtt", feather.getInt64(5));
            yyjson_mut_obj_add_int(document, object2, "bps", feather.getInt64(6));
        } else {
            now = feather.getInt(1);
            // reset value as needed
            if (now >= timestampNext) {
                // write down consolidated result
                yyjson_mut_val *object2 = yyjson_mut_obj(document);
                yyjson_mut_arr_append(results, object2);
                yyjson_mut_obj_add_int(document, object2, "timestamp", timestamp);
                yyjson_mut_obj_add_int(document, object2, "rttsum", rttSum);
                yyjson_mut_obj_add_int(document, object2, "rttcount", rttCount);
                yyjson_mut_obj_add_int(document, object2, "rttmax", rttMax);
                yyjson_mut_obj_add_int(document, object2, "timestamprttmax", timestampRttMax);
                yyjson_mut_obj_add_int(document, object2, "rttmin", rttCount == 0 ? 0 : rttMin);
                yyjson_mut_obj_add_int(document, object2, "timestamprttmin", timestampRttMin);
                yyjson_mut_obj_add_int(document, object2, "bpssum", bpsSum);
                yyjson_mut_obj_add_int(document, object2, "bpscount", bpsCount);
                yyjson_mut_obj_add_int(document, object2, "bpsmax", bpsMax);
                yyjson_mut_obj_add_int(document, object2, "timestampbpsmax", timestampBpsMax);
                yyjson_mut_obj_add_int(document, object2, "bpsmin", bpsCount == 0 ? 0 : bpsMin);
                yyjson_mut_obj_add_int(document, object2, "timestampbpsmin", timestampBpsMin);
                yyjson_mut_obj_add_int(document, object2, "errors", errors);

                // adjust timestamps and reset values
                resetBindingValues();
                timestamp += bindValue;
                timestampNext += bindValue;
                while (now >= timestampNext) { // fill the gap with zeroes if the gap of the timestamp from next record is higher than bind value(e.g. 2x or more)
                    yyjson_mut_val *object2 = yyjson_mut_obj(document);
                    yyjson_mut_arr_append(results, object2);
                    yyjson_mut_obj_add_int(document, object2, "timestamp", timestamp);
                    yyjson_mut_obj_add_int(document, object2, "rttsum", 0);
                    yyjson_mut_obj_add_int(document, object2, "rttcount", 0);
                    yyjson_mut_obj_add_int(document, object2, "rttmax", 0);
                    yyjson_mut_obj_add_int(document, object2, "timestamprttmax", 0);
                    yyjson_mut_obj_add_int(document, object2, "rttmin", 0);
                    yyjson_mut_obj_add_int(document, object2, "timestamprttmin", 0);
                    yyjson_mut_obj_add_int(document, object2, "bpssum", 0);
                    yyjson_mut_obj_add_int(document, object2, "bpscount", 0);
                    yyjson_mut_obj_add_int(document, object2, "bpsmax", 0);
                    yyjson_mut_obj_add_int(document, object2, "timestampbpsmax", 0);
                    yyjson_mut_obj_add_int(document, object2, "bpsmin", 0);
                    yyjson_mut_obj_add_int(document, object2, "timestampbpsmin", 0);
                    yyjson_mut_obj_add_int(document, object2, "errors", 0);

                    timestamp += bindValue;
                    timestampNext += bindValue;
                }
            }
            // accumulate values
            if (feather.getInt(3) == 8) { // success
                long long rtt = feather.getInt64(5), bps = feather.getInt64(6);
                rttSum += rtt;
                ++rttCount;
                if (rtt > rttMax) {
                    rttMax = rtt;
                    timestampRttMax = now;
                }
                if (rtt < rttMin) {
                    rttMin = rtt;
                    timestampRttMin = now;
                }
                bpsSum += bps;
                ++bpsCount;
                if (bps > bpsMax) {
                    bpsMax = bps;
                    timestampBpsMax = now;
                }
                if (bps < bpsMin) {
                    bpsMin = bps;
                    timestampBpsMin = now;
                }
            } else
                ++errors;
        }
    }
    feather.reset();
    feather.finalize();
    logger.log("Result row count: "s + std::to_string(rowCount));

    // write down the last consolidated result
    if (bindValue) {
        yyjson_mut_val *object2 = yyjson_mut_obj(document);
        yyjson_mut_arr_append(results, object2);
        yyjson_mut_obj_add_int(document, object2, "timestamp", timestamp);
        yyjson_mut_obj_add_int(document, object2, "rttsum", rttSum);
        yyjson_mut_obj_add_int(document, object2, "rttcount", rttCount);
        yyjson_mut_obj_add_int(document, object2, "rttmax", rttMax);
        yyjson_mut_obj_add_int(document, object2, "timestamprttmax", timestampRttMax);
        yyjson_mut_obj_add_int(document, object2, "rttmin", rttCount == 0 ? 0 : rttMin);
        yyjson_mut_obj_add_int(document, object2, "timestamprttmin", timestampRttMin);
        yyjson_mut_obj_add_int(document, object2, "bpssum", bpsSum);
        yyjson_mut_obj_add_int(document, object2, "bpscount", bpsCount);
        yyjson_mut_obj_add_int(document, object2, "bpsmax", bpsMax);
        yyjson_mut_obj_add_int(document, object2, "timestampbpsmax", timestampBpsMax);
        yyjson_mut_obj_add_int(document, object2, "bpsmin", bpsCount == 0 ? 0 : bpsMin);
        yyjson_mut_obj_add_int(document, object2, "timestampbpsmin", timestampBpsMin);
        yyjson_mut_obj_add_int(document, object2, "errors", errors);
    }

    // send result
    size_t bufferSize;
    char *buffer = yyjson_mut_write(document, YYJSON_WRITE_NOFLAG, &bufferSize);
    Civet7::respond200(connection, buffer, bufferSize);
    free(buffer);
    yyjson_mut_doc_free(document);
}

void Paradox::getResultsVersionSsh(mg_connection *connection, const std::string &portNumberRaw, const std::string &macAddress, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // get port number, ID and password
    uint16_t portNumber;
    try {
        portNumber = std::stoi(portNumberRaw.substr(1)); // drop first letter('s')
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to recognize port number: %s", portNumberRaw.data());
        return;
    }
    if (!parameters.contains("id"s) || !parameters.contains("password"s)) {
        mg_send_http_error(connection, 400, "Missing client authentication information.");
        return;
    }

    // get IP address from MAC
    latestMutex.lock();
    const auto copy = latest; // get a copy of "latest" data
    latestMutex.unlock();
    std::string ipString;
    for (const auto &item : copy)
        if (item["mac"s].get<std::string>() == macAddress) {
            ipString = item["sourceip"];
            break;
        }
    if (ipString.empty()) {
        mg_send_http_error(connection, 404, "No such device with MAC: %s", macAddress.data());
        return;
    }

    // connect to the target system and fetch revision number
    SshWrapper client;
    if (!client.connect(ipString, portNumber)) {
        mg_send_http_error(connection, 503, "Failed to connect to the client %s. Details: %s", ipString.data(), client.lastError.data()); // HTTP 503 service unavailable
        return;
    }
    if (!client.login(parameters.at("id"s), parameters.at("password"s))) {
        mg_send_http_error(connection, 511, "Failed to login with given authentication to %s", ipString.data()); // HTTP 511 Network Authentication Required
        return;
    }

    // fetch device information(currently version number only)
    std::string version;
    if (client.openInteractiveShell(10000, 10000)) {
        if (client.execute("sudo /Paradox/Faklient --status")) {
            std::string output = client.read(0, 100);

            // extract version number
            size_t start = output.find("Rev.");
            if (start != std::string::npos) { // output can be empty, if the binary is not Faklientwo
                size_t end = output.find('\n', start);
                version = output.substr(start, end - start - 1);
            }
        } else {
            mg_send_http_error(connection, 500, "Failed to run required command over SSH. Details: %s", client.lastError.data());
            return;
        }
    } else {
        mg_send_http_error(connection, 500, "Failed to start interactive shell. Details: %s", client.lastError.data());
        return;
    }

    // return version information
    std::string body = "{\"version\":\"" + version + "\"}";
    Civet7::respond200(connection, body.data(), body.size());
}

void Paradox::getResultsTabSeparated(const std::string &macAddress, FeatherLite &feather, mg_connection *connection)
{
    // initialize variables
    std::string currentTest;
    std::function<std::string(const std::string &)> buildPrefix = [&](const std::string &testName) -> std::string {
        tbb::concurrent_hash_map<std::string, nlohmann::json>::const_accessor a;
        if (devices.find(a, macAddress)) {
            // find out whether there's test with given name from the database table
            for (const auto &profile : a->second["ethtests"s]["scenarios"s])
                if (profile["name"].get<std::string>() == currentTest) {
                    const std::string server = profile["server"s];
                    const size_t separator = server.find(':');
                    int64_t threshold1 = 0, threshold2 = 0;
                    if (profile.contains("threshold1"))
                        threshold1 = profile["threshold1"s].get<int64_t>();
                    if (profile.contains("threshold2"))
                        threshold2 = profile["threshold2"s].get<int64_t>();
                    return profile["name"s].get<std::string>() + '\t' + profile["scenario"].get<std::string>() + '\t' + server.substr(0, separator) + '\t' + server.substr(separator + 1) + '\t' + std::to_string(threshold1) + '\t' + std::to_string(threshold2) + '\t';
                }
        }

        return ""s;
    };
    std::string chunk("Testname\tScenario\tDestinationIP\tDestinationPort\tThreshold1\tThreshold2\tSourceIp\tTestedAt\tResult\tResultDetail\tRTT\tBPS\n"s), prefix = buildPrefix(currentTest);
    chunk.reserve(110000000); // 110 MB

    // prepare for chunked encoding
    Civet7::respond200(connection, nullptr, 0, "text/tab-separated-values"s);
    while (feather.next() == SQLITE_ROW) {
        // check whether to change prefix
        auto testName = feather.getText(0);
        if (testName != currentTest) {
            currentTest = testName;
            prefix = buildPrefix(currentTest);
            if (prefix.empty()) {
                logger.log("Data mismatch between device list and database. MAC address: "s + macAddress + " / test name: "s + currentTest);
                continue;
            }
        }

        // build line
        chunk.append(prefix).append(feather.getText(2)).push_back('\t'); // source IP
        chunk
            .append(std::to_string(feather.getInt(1)) + '\t') // tested at
            .append(std::to_string(feather.getInt(3)) + '\t') // result
            .append(std::to_string(feather.getInt(4)) + '\t') // result detail
            .append(std::to_string(feather.getInt64(5)) + '\t') // RTT
            .append(std::to_string(feather.getInt64(6)) + '\t') // BPS
            .push_back('\n');

        // check whether to flush
        // flush chunk if its size is over 100MB
        if (chunk.size() > 100000000) {
            switch (mg_send_chunk(connection, chunk.data(), chunk.size())) {
            case 0:
                logger.log("Client closed socket. Cancelling operation."s);
                return;
            case -1:
                logger.log("Server encountered an error. Cancelling operation."s);
                return;
            default:
                chunk.clear();
            }
        }
    }
    feather.reset();
    feather.finalize();

    // send final chunk
    if (!chunk.empty())
        mg_send_chunk(connection, chunk.data(), chunk.size());
    mg_send_chunk(connection, "", 0);
}

void Paradox::getResultsLatest(mg_connection *connection)
{
    // get a copy of "latest" data
    latestMutex.lock();
    auto body = latest;
    latestMutex.unlock();

    // set order(index)
    for (auto &element : body) {
        std::pair<std::string, std::string> latestIndexKey = std::make_pair(element["mac"s].get<std::string>(), element["name"].get<std::string>());
        if (latestIndex.contains(latestIndexKey))
            element["index"s] = latestIndex.at(latestIndexKey);
        else
            element["index"s] = -1;
    }

    // if this build is for demo server, randomize status so that dashboard can be more "colorful"
#ifdef RANDOMIZELATESTX
    for (auto &element : body) {
        element["responsive"s] = (rand() / (RAND_MAX / 2)) > 0;
        element["result"s] = (rand() / (RAND_MAX / 2)) > 0 ? 8 : 9;
    }
#endif

    // send result
    Civet7::respond200(connection, body);
}

void Paradox::getResultsTopology(mg_connection *connection)
{
    // get a copy of "latest" data
    latestMutex.lock();
    auto body = topology;
    latestMutex.unlock();

    // send result
    Civet7::respond200(connection, body);
}

void Paradox::postResultsLatest(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check require parameter
    if (!parameters.contains("indices"s)) {
        mg_send_http_error(connection, 400, "Required parameter 'indices' not found.");
        return;
    }

    // update indices for GUI
    const std::string &rawJson = parameters.at("indices");
    auto newIndex = newLatestIndex(rawJson);
    latestIndexMutex.lock();
    latestIndex.swap(newIndex);
    latestIndexMutex.unlock();

    // save the file
    std::ofstream order("paradoxorders.json"s, std::ios::trunc);
    order << rawJson;
    order.close();

    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void Paradox::getRanking(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check required parameters
    if (parameters.contains("name"s) == 0) {
        mg_send_http_error(connection, 400, "Required parameter 'name' missing.");
        return;
    }
    size_t iEndUser = 0;
    try {
        if (parameters.contains("records"s))
            iEndUser = std::stoi(parameters.at("records"s));
    } catch (...) {
        logger.log("Failed to convert 'records' to number. Ignoring."s);
    }

    // enumerate registered MAC addresses
    struct ResultRecord
    {
        std::string mac, alias;
        long long rtt;
        int testedAt;
    };
    std::vector<ResultRecord> records;
    records.reserve(devices.size());
    for (const auto &pair : devices)
        records.push_back(ResultRecord{pair.first, pair.second["alias"s], -1, 0});

    // query DB with prepared statements
    FeatherLite feather("paradox.results"s, SQLITE_OPEN_READONLY);
    feather.prepare("SELECT Result, TestedAt, Rtt FROM ParadoxResults WHERE TestName=?1 AND Mac=?2 ORDER BY TestedAt DESC FETCH FIRST 1 ROW ONLY"s);
    const std::string &testName = parameters.at("name"s);
    for (auto &record : records) {
        feather.bindText(1, testName);
        feather.bindText(2, record.mac);
        if (feather.next() == SQLITE_ROW && feather.getInt(0) == 8) {
            record.testedAt = feather.getInt(1);
            record.rtt = feather.getInt64(2);
        }
        feather.reset();
    }
    feather.finalize();

    // sort results and remove records without proper RTT
    std::sort(records.begin(), records.end(), [](const ResultRecord &a, const ResultRecord &b) -> bool { return a.rtt > b.rtt; });
    while (records.back().rtt == -1)
        records.pop_back();

    // build result
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *root = yyjson_mut_arr(document), *object;
    yyjson_mut_doc_set_root(document, root);
    if (iEndUser == 0)
        iEndUser = records.size();
    for (size_t i = 0, iEnd = std::min(records.size(), iEndUser); i < iEnd; ++i) {
        object = yyjson_mut_obj(document);
        yyjson_mut_obj_add_strn(document, object, "mac", records.at(i).mac.data(), records.at(i).mac.size());
        yyjson_mut_obj_add_strn(document, object, "alias", records.at(i).alias.data(), records.at(i).alias.size());
        yyjson_mut_obj_add_int(document, object, "rtt", records.at(i).rtt);
        yyjson_mut_obj_add_int(document, object, "testedat", records.at(i).testedAt);
        yyjson_mut_arr_append(root, object);
    }

    // send result
    size_t bufferLength;
    char *buffer = yyjson_mut_write(document, YYJSON_WRITE_NOFLAG, &bufferLength);
    Civet7::respond200(connection, buffer, bufferLength);
    free(buffer);
    yyjson_mut_doc_free(document);
}
