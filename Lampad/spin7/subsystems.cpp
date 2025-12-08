#include "../sshwrapper.h"
#include "subsystems.h"
#include "feedrefinerabstract.h"
#include "civet7.hpp"
#include "codexindex.h"
#include "user.h"
#include "supercache.h"

#include <yyjson.h>

#include <sstream>
#include <filesystem>
#include <thread>
#include <functional>
#include <fstream>

#ifdef _WIN64
// must be included in this order(0)
#include <Windows.h> // system performance, etc.
#else // Linux
#endif

using namespace std::string_literals;

// externs
Logger SubSystems::logger("SubSystems"s);
std::string SubSystems::spin4Version("unknown"s);
std::string SubSystems::spin7Version("rev.620m-AI-MockUp-06"s);
size_t SubSystems::thresholdsSize = sizeof(SubSystems::Thresholds);
std::mutex SubSystems::fqdnMutex;
std::shared_mutex SubSystems::userDefinedAppMutex;
SuperCodex::IpFilter SubSystems::userDefinedApps;
std::string SubSystems::importPcapPath;

void SubSystems::initialize()
{
    logger.log("Recognize Spin4 version"s);
    system("/Lampad/spin4 --help 2> spin4help.log");
    std::ifstream spin4HelpLog("spin4help.log");
    std::string line;
    std::getline(spin4HelpLog, line, '\n');
    if (line.back() == '\r') // in Windows, line ends with '\r\n'
        line.pop_back();
    const size_t revisionIndex = line.find("rev.");
    if (revisionIndex != std::string::npos) // just in case file is corrupt
        spin4Version = line.substr(revisionIndex);
    logger.log("Recognized Spin4 version: "s + spin4Version);

    logger.log("Initialize user defined application management");
    initializeAppManagement();
}

void SubSystems::getVersion(mg_connection *connection)
{
    // build result JSON
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootObject = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, rootObject);
    yyjson_mut_obj_add_strn(document, rootObject, "spin7", spin7Version.data(), spin7Version.size());
    yyjson_mut_obj_add_strn(document, rootObject, "spin4", spin4Version.data(), spin4Version.size());

    Civet7::respond200(connection, document);
}
void SubSystems::postUpdate(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check whether the user is admin (not normal user)
    User::usersMutex.lock_shared();
    if (User::users[User::usernameFromConnection(connection)]["roleunpacked"] != 0) {
        mg_send_http_error(connection, 403, "Requested action is not allowed.");
        return;
    }
    User::usersMutex.unlock_shared();

    // write down update file to messy room
    std::string messRoomForUpdate = FeedRefinerAbstract::messyRoom + "/system_update"s;
    if (std::filesystem::exists(messRoomForUpdate))
        std::filesystem::remove_all(messRoomForUpdate);
    std::filesystem::create_directory(messRoomForUpdate);
    if (!parameters.contains("raw"s)) {
        mg_send_http_error(connection, 400, "Can't find file to be used on update. Maybe Content-Type is not application/octet-stream?");
        return;
    }
    const std::string &raw = parameters.at("raw"s);
    std::ofstream file(messRoomForUpdate + "/patch.tar.gz", std::ios::binary | std::ios::trunc);
    file.write(raw.data(), raw.size());
    file.close();

    // send 204 No Content
    mg_send_http_error(connection, 204, "\r\n\r\n");

    // extract file and run "lapply.sh"
    std::string command = "cd "s + messRoomForUpdate + " && tar xzf patch.tar.gz && systemd-run --scope ./lapply.sh"s;
    system(command.data());
}

void SubSystems::getSyslog(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // build query string
    std::string query, type;
    query.reserve(512);
    if (parameters.contains("type"s))
        type = parameters.at("type"s);
    if (type == "summary"s)
        query = "SELECT priority, hostip FROM syslog WHERE message LIKE ? AND hostname LIKE ? AND hostip LIKE ? AND syslogtag LIKE ?"s;
    else
        query = "SELECT receivedat, facility, priority, hostname, hostip, message, syslogtag FROM syslog WHERE message LIKE ? AND hostname LIKE ? AND hostip LIKE ? AND syslogtag LIKE ?"s;

    // check parameters
    if (parameters.contains("from"s))
        query.append(" AND receivedat>='"s + parameters.at("from"s) + '\'');
    if (parameters.contains("to"s))
        query.append(" AND receivedat<='"s + parameters.at("to"s) + '\'');
    if (parameters.contains("facility"s))
        try { // check whether the paramater is numeric
            auto number = std::stoi(parameters.at("facility"s));
            query.append(" AND facility="s + std::to_string(number));
        } catch (...) {
            // ignore
        }
    if (parameters.contains("priority"s))
        try { // check whether the paramater is numeric
            auto number = std::stoi(parameters.at("priority"s));
            query.append(" AND priority<="s + std::to_string(number));
        } catch (...) {
            // ignore
        }
    else if (type == "summary"s)
        query.append(" AND priority<=4"s);
    query.append(" ORDER BY receivedat DESC");
    if (parameters.contains("limit"s))
        try {
            auto verifier = std::stoul(parameters.at("limit")); // check whether the value is really convertable to number
            query.append(" LIMIT ").append(std::to_string(verifier)); // defend SQL injection attack
        } catch (...) {
            // ignore
        }

    // check existence of the database
    if (!std::filesystem::exists("syslog.spin514"s)) {
        mg_send_http_error(connection, 204, "\r\n\r\n");
        return;
    }

    // query to database
    FeatherLite feather("syslog.spin514"s, SQLITE_OPEN_READONLY);
    std::vector<std::string> sqlParameters(4);
    if (parameters.contains("message"s))
        sqlParameters[0] = '%' + parameters.at("message"s) + '%';
    else
        sqlParameters[0] = "%%"s;
    if (parameters.contains("hostname"s))
        sqlParameters[1] = '%' + parameters.at("hostname"s) + '%';
    else
        sqlParameters[1] = "%%"s;
    if (parameters.contains("hostip"s))
        sqlParameters[2] = '%' + SuperCodex::humanReadableIp(SuperCodex::stringFromHex(parameters.at("hostip"s))) + '%';
    else
        sqlParameters[2] = "%%"s;
    if (parameters.contains("syslogtag"s))
        sqlParameters[3] = '%' + parameters.at("syslogtag"s) + '%';
    else
        sqlParameters[3] = "%%"s;
    feather.prepare(query);
    feather.bindText(1, sqlParameters[0]);
    feather.bindText(2, sqlParameters[1]);
    feather.bindText(3, sqlParameters[2]);
    feather.bindText(4, sqlParameters[3]);

    // fetch result
    if (type == "summary"s)
        getSyslogSummary(connection, feather);
    else if (type == "tabseparated"s)
        getSyslogTabSeparted(connection, feather);
    else
        getSyslogDefault(connection, feather);
}

void SubSystems::getSyslogDefault(mg_connection *connection, FeatherLite &feather)
{
    // initialize JSON objects
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *root = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, root);

    // enumerate per username
    std::string temp;
    while (feather.next() == SQLITE_ROW) {
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_obj_add_int(document, object, "receivedat", feather.getInt(0));
        yyjson_mut_obj_add_int(document, object, "facility", feather.getInt(1));
        yyjson_mut_obj_add_int(document, object, "priority", feather.getInt(2));
        temp = feather.getText(3);
        yyjson_mut_obj_add_strncpy(document, object, "hostname", temp.data(), temp.size());
        temp = feather.getText(4);
        yyjson_mut_obj_add_strncpy(document, object, "hostip", temp.data(), temp.size());
        temp = feather.getText(5);
        yyjson_mut_obj_add_strncpy(document, object, "message", temp.data(), temp.size());
        temp = feather.getText(6);
        yyjson_mut_obj_add_strncpy(document, object, "syslogtag", temp.data(), temp.size());

        yyjson_mut_arr_add_val(root, object);
    }

    // return result to the client and free working memory
    Civet7::respond200(connection, document);
}

void SubSystems::getSyslogSummary(mg_connection *connection, FeatherLite &feather)
{
    // count number of messages
    struct Count
    {
        int emergencies, alerts, criticals, errors, warnings;
    };
    ankerl::unordered_dense::map<std::string, Count> counts;
    while (feather.next() == SQLITE_ROW) {
        std::string ip(feather.getText(1));
        switch (feather.getInt(0)) { // per priority/severity
        case 0:
            ++counts[ip].emergencies;
            break;
        case 1:
            ++counts[ip].alerts;
            break;
        case 2:
            ++counts[ip].criticals;
            break;
        case 3:
            ++counts[ip].errors;
            break;
        case 4:
            ++counts[ip].warnings;
            break;
        }
    }

    // initialize JSON objects
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *root = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, root);

    // enumerate counts
    for (const auto &pair : counts) {
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_obj_add_strncpy(document, object, "hostip", pair.first.data(), pair.first.size());
        const auto &count = pair.second;
        yyjson_mut_obj_add_int(document, object, "emergencies", count.emergencies);
        yyjson_mut_obj_add_int(document, object, "alerts", count.alerts);
        yyjson_mut_obj_add_int(document, object, "criticals", count.criticals);
        yyjson_mut_obj_add_int(document, object, "errors", count.errors);
        yyjson_mut_obj_add_int(document, object, "warnings", count.warnings);

        yyjson_mut_arr_add_val(root, object);
    }

    // return result to the client and free working memory
    Civet7::respond200(connection, document);
}

void SubSystems::getSyslogTabSeparted(mg_connection *connection, FeatherLite &feather)
{
    std::string result("ReceivedAt\tFacility\tPriority\tHostname\tHostIp\tMessage\tSyslogTag\n"s);
    result.reserve(1048576); // 1MB may be sufficient, I think?
    while (feather.next() == SQLITE_ROW) {
        // receivedat
        result.append(FeedRefinerAbstract::epochToIsoDate(feather.getInt(0))).push_back('\t');
        // facility
        switch (feather.getInt(1)) {
        case 0:
            result.append("Kernel messages"s).push_back('\t');
            break;
        case 1:
            result.append("User level messages"s).push_back('\t');
            break;
        case 2:
            result.append("Mail system"s).push_back('\t');
            break;
        case 3:
            result.append("System daemons"s).push_back('\t');
            break;
        case 4:
            result.append("Security/authentication messages"s).push_back('\t');
            break;
        case 5:
            result.append("Syslogd internal message"s).push_back('\t');
            break;
        case 6:
            result.append("Line printer subsystem"s).push_back('\t');
            break;
        case 7:
            result.append("Network news subsystem"s).push_back('\t');
            break;
        case 8:
            result.append("UUCP subsystem"s).push_back('\t');
            break;
        case 9:
            result.append("Clock daemon"s).push_back('\t');
            break;
        case 10:
            result.append("Security/authentication messages"s).push_back('\t');
            break;
        case 11:
            result.append("FTP daemon"s).push_back('\t');
            break;
        case 12:
            result.append("NTP subsystem"s).push_back('\t');
            break;
        case 13:
            result.append("Log audit"s).push_back('\t');
            break;
        case 14:
            result.append("Log alert"s).push_back('\t');
            break;
        case 15:
            result.append("Scheduling daemon"s).push_back('\t');
            break;
        case 16:
            result.append("Local facility 0"s).push_back('\t');
            break;
        case 17:
            result.append("Local facility 1"s).push_back('\t');
            break;
        case 18:
            result.append("Local facility 2"s).push_back('\t');
            break;
        case 19:
            result.append("Local facility 3"s).push_back('\t');
            break;
        case 20:
            result.append("Local facility 4"s).push_back('\t');
            break;
        case 21:
            result.append("Local facility 5"s).push_back('\t');
            break;
        case 22:
            result.append("Local facility 6"s).push_back('\t');
            break;
        case 23:
            result.append("Local facility 7"s).push_back('\t');
            break;
        default:
            result.append("Unknown("s + std::to_string(feather.getInt(1)) + ')').push_back('\t');
            break;
        }
        // priority
        switch (feather.getInt(2)) {
        case 0:
            result.append("Emergency"s).push_back('\t');
            break;
        case 1:
            result.append("Alert"s).push_back('\t');
            break;
        case 2:
            result.append("Critical"s).push_back('\t');
            break;
        case 3:
            result.append("Error"s).push_back('\t');
            break;
        case 4:
            result.append("Warning"s).push_back('\t');
            break;
        case 5:
            result.append("Notice"s).push_back('\t');
            break;
        case 6:
            result.append("Informational"s).push_back('\t');
            break;
        case 7:
            result.append("Debug"s).push_back('\t');
            break;
        }
        // hostname, hostip, message, syslog tag
        result.append(feather.getText(3)).push_back('\t');
        result.append(feather.getText(4)).push_back('\t');
        result.append(feather.getText(5)).push_back('\t');
        result.append(feather.getText(6)).push_back('\n');
    }
    Civet7::respond200(connection, result.data(), result.size(), "text/tab-separated-values"s);
}

void SubSystems::getSysInfo(mg_connection *connection)
{
    using namespace std::chrono_literals;
    int64_t cpu, ramFree, ramTotal;

#ifdef __linux__
    // get RAM usage
    std::ifstream meminfo("/proc/meminfo"s);
    for (std::string line; std::getline(meminfo, line);) {
        if (line.find("MemTotal:"s) == 0) {
            line.erase(line.size() - 3); // remove tailing " kB"
            ramTotal = 1024 * std::stoll(line.substr(line.rfind(' ') + 1));
        } else if (line.find("MemAvailable:"s) == 0) {
            line.erase(line.size() - 3); // remove tailing " kB"
            ramFree = 1024 * std::stoll(line.substr(line.rfind(' ') + 1));
        }
    }
    //#include <sys/sysinfo.h>
    //    struct sysinfo ramInfo;
    //    if(sysinfo(&ramInfo)) Civet7::respond200(connection, "\"Error on getting information.\"", 31);
    //    ramFree=ramInfo.freeram*ramInfo.mem_unit;
    //    ramTotal=ramInfo.totalram*ramInfo.mem_unit;

    // get CPU usage
    int64_t idle1 = 0, idle2 = 0, total1 = 0, total2 = 0;
    std::function<void(int64_t &, int64_t &)> readStat = [&](int64_t &idle, int64_t &total) {
        std::ifstream stat("/proc/stat"s);
        std::string line;
        std::getline(stat, line); // read first line(aggregated)
        line.erase(0, 5); // remove "cpu  " in head
        int counter = 0;
        std::istringstream recordReader(line);
        for (std::string record; std::getline(recordReader, record, ' ');) {
            if (counter == 3)
                idle = std::stoll(record);
            ++counter;
            total += std::stoll(record);
        }
    };

    // read, wait for 1 second, read again and calculate usage
    readStat(idle1, total1);
    std::this_thread::sleep_for(1s);
    readStat(idle2, total2);
    cpu = 100 - ((idle2 - idle1) * 100 / (total2 - total1));
#else
    // get RAM usage
    MEMORYSTATUSEX ramInfo;
    ramInfo.dwLength = sizeof(ramInfo);
    GlobalMemoryStatusEx(&ramInfo);
    ramFree = ramInfo.ullAvailPhys;
    ramTotal = ramInfo.ullTotalPhys;

    // get CPU usage: from https://stackoverflow.com/questions/23143693/retrieving-cpu-load-percent-total-in-windows-with-c
    FILETIME prevSysIdle, prevSysKernel, prevSysUser;
    // TIME DIFF FUNC
    std::function<ULONGLONG(const FILETIME, const FILETIME)> SubtractTimes = [&](const FILETIME one, const FILETIME two) {
        LARGE_INTEGER a, b;
        a.LowPart = one.dwLowDateTime;
        a.HighPart = one.dwHighDateTime;

        b.LowPart = two.dwLowDateTime;
        b.HighPart = two.dwHighDateTime;

        return a.QuadPart - b.QuadPart;
    };
    std::function<int(double &)> getCpuUsage = [&](double &val) {
        FILETIME sysIdle, sysKernel, sysUser;
        // sysKernel include IdleTime
        if (GetSystemTimes(&sysIdle, &sysKernel, &sysUser) == 0) // GetSystemTimes func FAILED return value is zero;
            return 0;

        if (prevSysIdle.dwLowDateTime != 0 && prevSysIdle.dwHighDateTime != 0) {
            ULONGLONG sysIdleDiff, sysKernelDiff, sysUserDiff;
            sysIdleDiff = SubtractTimes(sysIdle, prevSysIdle);
            sysKernelDiff = SubtractTimes(sysKernel, prevSysKernel);
            sysUserDiff = SubtractTimes(sysUser, prevSysUser);

            ULONGLONG sysTotal = sysKernelDiff + sysUserDiff;
            ULONGLONG kernelTotal = sysKernelDiff - sysIdleDiff; // kernelTime - IdleTime = kernelTime, because sysKernel include IdleTime

            if (sysTotal > 0) // sometimes kernelTime > idleTime
                val = (double) (((kernelTotal + sysUserDiff) * 100.0) / sysTotal);
        }

        prevSysIdle = sysIdle;
        prevSysKernel = sysKernel;
        prevSysUser = sysUser;

        return 1;
    };
    double cpuDouble;
    getCpuUsage(cpuDouble);
    std::this_thread::sleep_for(1s);
    getCpuUsage(cpuDouble);
    cpu = cpuDouble;
#endif

    // get disk information
    std::filesystem::space_info spaceInfo = std::filesystem::space(CodexIndex::feedRoot);

    // initialize JSON objects
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *root = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, root);

    // build JSON
    yyjson_mut_obj_add_int(document, root, "cpu", cpu);
    yyjson_mut_obj_add_int(document, root, "ramfree", ramFree);
    yyjson_mut_obj_add_int(document, root, "ramtotal", ramTotal);
    yyjson_mut_obj_add_int(document, root, "volumefree", spaceInfo.free);
    yyjson_mut_obj_add_int(document, root, "volumetotal", spaceInfo.capacity);

    // return result to the client and free working memory
    Civet7::respond200(connection, document);
}

void SubSystems::postRupdate(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check whether the user is admin (not normal user)
    User::usersMutex.lock_shared();
    if (User::users[User::usernameFromConnection(connection)]["roleunpacked"] != 0) {
        mg_send_http_error(connection, 403, "Requested action is not allowed.");
        return;
    }
    User::usersMutex.unlock_shared();

    // write down update file to messy room
    std::string messRoomPath = FeedRefinerAbstract::messyRoom + "/remote_update"s;
    if (std::filesystem::exists(messRoomPath))
        std::filesystem::remove_all(messRoomPath);
    std::filesystem::create_directory(messRoomPath);
    if (!parameters.contains("raw"s)) {
        mg_send_http_error(connection, 400, "Can't find file to be used on update. Maybe Content-Type is not application/octet-stream?");
        return;
    }
    const std::string &raw = parameters.at("raw"s);
    std::ofstream file(messRoomPath + path, std::ios::binary | std::ios::trunc);
    file.write(raw.data(), raw.size());
    file.close();

    // send 204 No Content
    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void SubSystems::getRupdate(mg_connection *connection)
{
    // check whether the user is admin (not normal user)
    User::usersMutex.lock_shared();
    if (User::users[User::usernameFromConnection(connection)]["roleunpacked"] != 0) {
        mg_send_http_error(connection, 403, "Requested action is not allowed.");
        return;
    }
    User::usersMutex.unlock_shared();

    // enumerate files
    std::string messRoomPath = FeedRefinerAbstract::messyRoom + "/remote_update"s;
    if (std::filesystem::exists(messRoomPath)) {
        // prepare for JSON document
        yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
        yyjson_mut_val *rootArray = yyjson_mut_arr(document);
        yyjson_mut_doc_set_root(document, rootArray);

        // enumerate files and return
        for (const auto &entry : std::filesystem::directory_iterator(messRoomPath))
            if (entry.is_regular_file()) {
                const std::string filename = entry.path().filename().string();
                yyjson_mut_arr_add_strncpy(document, rootArray, filename.data(), filename.size());
            }
        Civet7::respond200(connection, document);
    } else
        mg_send_http_error(connection, 404, "Remote patch directory not found on the server");
}

void SubSystems::patchRupdate(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    if (!parameters.contains("ip"s) || !parameters.contains("port"s) || !parameters.contains("id"s) || !parameters.contains("password"s) || !parameters.contains("file"s)) {
        mg_send_http_error(connection, 400, "Missing required argument(s): ip, port, id, password, file.");
        return;
    }
    uint16_t portNumber;
    try {
        portNumber = std::stoi(parameters.at("port"s));
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to recognize port number: %s", parameters.at("port"s).data());
        return;
    }

    // upload target file
    SshWrapper client;
    if (!client.connect(parameters.at("ip"s), portNumber)) {
        mg_send_http_error(connection, 503, "Failed to connect to the client %s. Details: %s", parameters.at("ip"s).data(), client.lastError.data()); // HTTP 503 service unavailable
        return;
    }
    if (!client.login(parameters.at("id"s), parameters.at("password"s))) {
        mg_send_http_error(connection, 511, "Failed to login with given authentication to %s", parameters.at("ip"s).data()); // HTTP 511 Network Authentication Required
        return;
    }
    auto sftpHandle = client.prepareSftp("patch.tar.gz"s, true);
    std::string localFilePath = FeedRefinerAbstract::messyRoom + "/remote_update/"s + parameters.at("file"s);
    std::ifstream fileToUpload(localFilePath);
    if (!fileToUpload.is_open()) {
        mg_send_http_error(connection, 404, "File not found: %s", parameters.at("file"s).data());
        return;
    }
    client.upload(fileToUpload, std::filesystem::file_size(localFilePath), 10000000000, sftpHandle);
    if (client.lastErrorCode != SSH_NO_ERROR) {
        mg_send_http_error(connection, 500, "Failed to upload file. Details: %s", client.lastError.data());
        return;
    }

    // decompress file and run `lapply.sh`
    SshWrapper runner;
    runner.connect(parameters.at("ip"s), portNumber);
    runner.login(parameters.at("id"s), parameters.at("password"s));
    if (runner.openInteractiveShell(10000, 10000)) {
        if (!runner.execute("nohup tar xzf patch.tar.gz && ~/lapply.sh > patch.log"))
            mg_send_http_error(connection, 500, "Failed to run the command. Details: %s", runner.lastError.data());
        std::this_thread::sleep_for(std::chrono::seconds(1));
    } else {
        mg_send_http_error(connection, 500, "Failed to start interactive shell. Details: %s", client.lastError.data());
        return;
    }

    // declare success
    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void SubSystems::deleteRupdate(mg_connection *connection, const std::string &path)
{
    // check whether the user is admin (not normal user)
    User::usersMutex.lock_shared();
    if (User::users[User::usernameFromConnection(connection)]["roleunpacked"] != 0) {
        mg_send_http_error(connection, 403, "Requested action is not allowed.");
        return;
    }
    User::usersMutex.unlock_shared();

    // check existence and remove file
    std::string fileToDelete = FeedRefinerAbstract::messyRoom + "/remote_update"s + path;
    if (!std::filesystem::exists(fileToDelete)) {
        mg_send_http_error(connection, 404, "File not found: %s", path.data());
        return;
    } else
        std::filesystem::remove(fileToDelete);

    // send 204 No Content
    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void SubSystems::getSnmpTrap(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // prepare for query string prototype
    std::string query, type;
    if (parameters.contains("type"s))
        type = parameters.at("type"s);
    if (type == "summary"s)
        query = "SELECT sender, traptype FROM snmptrap WHERE timestamp>=? AND timestamp<? AND sender LIKE ? AND hostname LIKE ? AND enterprisestring LIKE ? AND message LIKE ? "s;
    else
        query = "SELECT timestamp, sender, hostname, traptype, enterprisestring, message FROM snmptrap WHERE timestamp>=? AND timestamp<? AND sender LIKE ? AND hostname LIKE ? AND enterprisestring LIKE ? AND message LIKE ? "s;

    // check numeric parameters
    uint32_t from = 0, to = UINT32_MAX;
    int trapType = -1;
    try {
        if (parameters.contains("from"s))
            from = std::stoul(parameters.at("from"s));
        if (parameters.contains("to"s))
            to = std::stoul(parameters.at("to"s));
        if (parameters.contains("traptype"s))
            trapType = std::stoi(parameters.at("traptype"s));
    } catch (std::invalid_argument &e) {
        logger.log("Failed to convert string to number.");
    } catch (std::out_of_range &e) {
        logger.log("Number out of range.");
    }

    // build query parameters
    std::vector<std::string> sqlParameters;
    sqlParameters.reserve(4);
    if (parameters.contains("sender"s))
        sqlParameters.push_back('%' + parameters.at("sender"s) + '%');
    else
        sqlParameters.push_back("%%"s);
    if (parameters.contains("hostname"s))
        sqlParameters.push_back('%' + parameters.at("hostname"s) + '%');
    else
        sqlParameters.push_back("%%"s);
    if (parameters.contains("enterprisestring"s))
        sqlParameters.push_back('%' + parameters.at("enterprisestring"s) + '%');
    else
        sqlParameters.push_back("%%"s);
    if (parameters.contains("values"s))
        sqlParameters.push_back('%' + parameters.at("values"s) + '%');
    else
        sqlParameters.push_back("%%"s);
    if (trapType != -1) {
        if (type == "summary"s) { // if type is summary, override trap type conditions
            query.append("AND (traptype=1 OR traptype=2 OR traptype=4) "); // reset, link down, or authentication failure
        } else
            query.append("AND traptype=? ");
    }
    query.append("ORDER BY timestamp DESC");
    if (parameters.contains("limit"s))
        try {
            auto verifier = std::stoul(parameters.at("limit")); // check whether the value is really convertable to number
            query.append(" LIMIT ").append(std::to_string(verifier)); // defend SQL injection attack
        } catch (...) {
            // ignore
        }

    // query to database
    FeatherLite feather("snmptrap.spin162"s, SQLITE_OPEN_READONLY);
    feather.prepare(query);
    feather.bindInt(1, from);
    feather.bindInt(2, to);
    feather.bindText(3, sqlParameters[0]);
    feather.bindText(4, sqlParameters[1]);
    feather.bindText(5, sqlParameters[2]);
    feather.bindText(6, sqlParameters[3]);
    if (trapType != -1)
        feather.bindInt(7, trapType);

    // fetch result
    if (type == "summary")
        getSnmpTrapSummary(connection, feather);
    else if (type == "tabseparated")
        getSnmpTrapTabSeparted(connection, feather);
    else
        getSnmpTrapDefault(connection, feather);
}

void SubSystems::getSnmpTrapDefault(mg_connection *connection, FeatherLite &feather)
{
    // initialize JSON objects
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *root = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, root);

    // enumerate per username
    std::string temp;
    while (feather.next() == SQLITE_ROW) {
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_obj_add_int(document, object, "timestamp", feather.getInt(0));
        temp = SuperCodex::stringToHex(std::string(feather.getText(1)));
        yyjson_mut_obj_add_strncpy(document, object, "sender", temp.data(), temp.size());
        temp = feather.getText(2);
        yyjson_mut_obj_add_strncpy(document, object, "hostname", temp.data(), temp.size());
        yyjson_mut_obj_add_int(document, object, "traptype", feather.getInt(3));
        temp = feather.getText(4);
        yyjson_mut_obj_add_strncpy(document, object, "enterprisestring", temp.data(), temp.size());
        temp = feather.getText(5);
        yyjson_mut_obj_add_strncpy(document, object, "values", temp.data(), temp.size());

        yyjson_mut_arr_add_val(root, object);
    }

    // return result to the client and free working memory
    Civet7::respond200(connection, document);
}

void SubSystems::getSnmpTrapSummary(mg_connection *connection, FeatherLite &feather)
{
    // count number of messages
    struct Count
    {
        int reset, linkDown, authenticationFailure;
    };
    ankerl::unordered_dense::map<std::string, Count> counts;
    while (feather.next() == SQLITE_ROW) {
        std::string ip(feather.getBlob(0));
        switch (feather.getInt(1)) { // per priority/severity
        case 1:
            ++counts[ip].reset;
            break;
        case 2:
            ++counts[ip].linkDown;
            break;
        case 4:
            ++counts[ip].authenticationFailure;
            break;
        }
    }

    // initialize JSON objects
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *root = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, root);

    // write down counts
    std::string temp;
    for (const auto &pair : counts) {
        yyjson_mut_val *object = yyjson_mut_obj(document);
        temp = SuperCodex::stringToHex(pair.first);
        yyjson_mut_obj_add_strncpy(document, object, "sender", temp.data(), temp.size());
        const auto &count = pair.second;
        yyjson_mut_obj_add_int(document, object, "warmboot", count.reset);
        yyjson_mut_obj_add_int(document, object, "linkdown", count.linkDown);
        yyjson_mut_obj_add_int(document, object, "authfail", count.authenticationFailure);

        yyjson_mut_arr_add_val(root, object);
    }

    // return result to the client and free working memory
    Civet7::respond200(connection, document);
}

void SubSystems::getSnmpTrapTabSeparted(mg_connection *connection, FeatherLite &feather)
{
    std::string result("Timestamp\tSender\tHostname\tTrapType\tEnterpriseString\tValue\n"s);
    result.reserve(1048576); // 1MB may be sufficient, I think?
    while (feather.next() == SQLITE_ROW) {
        // timestamp
        result.append(FeedRefinerAbstract::epochToIsoDate(feather.getInt(0))).push_back('\t');
        // sender, hostname
        result.append(SuperCodex::humanReadableIp(std::string(feather.getText(1))) + '\t').append(std::string(feather.getText(2)) + '\t');
        // trap type
        switch (feather.getInt(3)) {
        case 0:
            result.append("Cold Start"s).push_back('\t');
            break;
        case 1:
            result.append("Warm Start(reset)"s).push_back('\t');
            break;
        case 2:
            result.append("Link Down"s).push_back('\t');
            break;
        case 3:
            result.append("Link Up"s).push_back('\t');
            break;
        case 4:
            result.append("Authentication Failure"s).push_back('\t');
            break;
        case 5:
            result.append("EGP Neighbor Loss"s).push_back('\t');
            break;
        case 6:
            result.append("Enterprise Specific"s).push_back('\t');
            break;
        }
        // enterprise string, value
        result.append(feather.getText(4)).push_back('\t');
        result.append(feather.getText(5)).push_back('\n');
    }
    Civet7::respond200(connection, result.data(), result.size(), "text/tab-separated-values"s);
}

void SubSystems::initializeAppManagement()
{
    logger.log("Initialize application manager"s);
    // create database for FQDN cache
    if (!std::filesystem::exists("apps.fqdns"s)) {
        FeatherLite feather("apps.fqdns"s);
        feather.useWal();
        feather.exec("CREATE TABLE fqdns(name TEXT, ip BLOB, UNIQUE(name,ip));"
                     "CREATE INDEX idxfqdns1 on fqdns(ip);"s);
    }

    // create database for user defined applications as needed
    std::string userDefinedAppsPath("apps.user"s);
    if (!std::filesystem::exists(userDefinedAppsPath)) {
        FeatherLite userDefinedApps(userDefinedAppsPath);
        userDefinedApps.useWal();
        userDefinedApps.exec("CREATE TABLE raw(name STRING NOT NULL UNIQUE, ips STRING, port INTEGER, thresholds BLOB);"
                             "CREATE INDEX idxraw1 on raw(name);"s);
    }
    updateUserDefinedApp();
}

void SubSystems::postApp(mg_connection *connection, const std::string &path, ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check required parameters
    if (!parameters.contains("name"s) || !parameters.contains("ips"s) || !parameters.contains("port"s)) {
        mg_send_http_error(connection, 400, "One or more required parameters(\"name\", \"ips\", \"port\") not found.");
        return;
    }
    uint16_t port;
    try {
        port = std::stoi(parameters.at("port"s));
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to convert port to number. Check whether parameter contains only numbers(0~9)");
        return;
    }

    // parse any threshold data
    Thresholds thresholds;
    try {
        std::function<std::pair<std::string, std::string>(const std::string &rawString)> split = [](const std::string &rawString) -> std::pair<std::string, std::string> {
            size_t splitter = rawString.find(',');
            if (splitter == std::string::npos)
                throw "Failed to find splitter";
            return std::make_pair(rawString.substr(0, splitter), rawString.substr(splitter + 1));
        };
        if (parameters.contains("thresholdsrtt"s)) {
            const auto pair = split(parameters.at("thresholdsrtt"s));
            thresholds.rtt1 = std::stoull(pair.first);
            thresholds.rtt2 = std::stoull(pair.second);
        }
        if (parameters.contains("thresholdsrseponserate"s)) {
            const auto pair = split(parameters.at("thresholdsrseponserate"s));
            thresholds.responseRate1 = std::stoull(pair.first);
            thresholds.responseRate2 = std::stoull(pair.second);
        }
        if (parameters.contains("thresholdsretransmission"s)) {
            const auto pair = split(parameters.at("thresholdsretransmission"s));
            thresholds.tcpRetransmission1 = std::stoull(pair.first);
            thresholds.tcpRetransmission2 = std::stoull(pair.second);
        }
        if (parameters.contains("thresholdstcp0w"s)) {
            const auto pair = split(parameters.at("thresholdstcp0w"s));
            thresholds.tcpZeroWindows1 = std::stoull(pair.first);
            thresholds.tcpZeroWindows2 = std::stoull(pair.second);
        }
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to convert threshold(s) to number. Check whether parameter representation is correct");
        return;
    }

    // prepare for variables
    std::lock_guard<std::shared_mutex> guard(userDefinedAppMutex);
    FeatherLite apps("apps.user"s);
    apps.useWal();
    const std::string name = parameters.at("name");

    // remove existing application data
    apps.prepare("DELETE FROM raw WHERE name=?;"s);
    apps.bindText(1, name);
    apps.next();
    apps.reset();
    apps.finalize();

    // register new raw data
    apps.prepare("INSERT INTO raw(name,ips,port,thresholds) VALUES(?,?,?,?);");
    apps.bindText(1, name);
    apps.bindText(2, parameters.at("ips"s));
    apps.bindInt(3, port);
    apps.bindBlob(4, &thresholds, thresholdsSize);
    apps.next();
    apps.reset();
    apps.finalize();

    // finalize
    updateUserDefinedApp();
    Civet7::respond200(connection, "0"); // request from GUI developer(Chavly)
}

void SubSystems::getApp(mg_connection *connection, ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // prepare for result JSON
    auto document = yyjson_mut_doc_new(nullptr);
    auto rootArray = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, rootArray);

    // build consolidated list of name-IPs
    std::string temp;
    FeatherLite apps("apps.user"s, SQLITE_OPEN_READONLY);
    apps.prepare("SELECT name,ips,port,thresholds FROM raw;");
    while (apps.next() == SQLITE_ROW) {
        // prepare for object
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_append(rootArray, object);
        // general information
        temp = apps.getText(0);
        yyjson_mut_obj_add_strncpy(document, object, "name", temp.data(), temp.size());
        temp = apps.getText(1);
        yyjson_mut_obj_add_strncpy(document, object, "ips", temp.data(), temp.size());
        yyjson_mut_obj_add_int(document, object, "port", apps.getInt(2));
        // thresholds
        Thresholds thresholds;
        if (!apps.isNull(3)) {
            const auto raw = apps.getBlob(3);
            memcpy(&thresholds, raw.data(), raw.size());
        }
        yyjson_mut_val *thresholdsObject = yyjson_mut_obj(document);
        yyjson_mut_obj_add_val(document, object, "thresholds", thresholdsObject);
        yyjson_mut_obj_add_uint(document, thresholdsObject, "rtt1", thresholds.rtt1);
        yyjson_mut_obj_add_uint(document, thresholdsObject, "rtt2", thresholds.rtt2);
        yyjson_mut_obj_add_uint(document, thresholdsObject, "responserate1", thresholds.responseRate1);
        yyjson_mut_obj_add_uint(document, thresholdsObject, "responserate2", thresholds.responseRate2);
        yyjson_mut_obj_add_uint(document, thresholdsObject, "tcpretransmission1", thresholds.tcpRetransmission1);
        yyjson_mut_obj_add_uint(document, thresholdsObject, "tcpretransmission2", thresholds.tcpRetransmission2);
        yyjson_mut_obj_add_uint(document, thresholdsObject, "tcpzerowindows1", thresholds.tcpZeroWindows1);
        yyjson_mut_obj_add_uint(document, thresholdsObject, "tcpzerowindows2", thresholds.tcpZeroWindows2);
    }

    // return result
    Civet7::respond200(connection, document);
}

void SubSystems::deleteApp(mg_connection *connection, const std::string &path)
{
    std::string appName(path.substr(1));
    std::lock_guard<std::shared_mutex> guard(userDefinedAppMutex);

    FeatherLite apps("apps.user"s);
    // remove from apps
    apps.prepare("DELETE FROM raw WHERE name=?;");
    apps.bindText(1, appName);
    apps.next();
    apps.reset();
    apps.finalize();

    // finalize
    updateUserDefinedApp();
    Civet7::respond200(connection, "0"); // request from GUI developer(Chavly)
}

void SubSystems::updateUserDefinedApp()
{
    SuperCodex::IpFilter newUserDefined;
    FeatherLite apps("apps.user"s, SQLITE_OPEN_READONLY);
    apps.prepare("SELECT name, ips, port FROM raw"s);
    while (apps.next() == SQLITE_ROW) {
        std::istringstream splitter(std::string(apps.getText(1)));
        for (std::string ip; std::getline(splitter, ip, ',');)
            newUserDefined.registerNetwork(ip, apps.getInt(2), std::string(apps.getText(0)));
    }
    apps.reset();
    apps.finalize();

    // swap data
    std::swap(newUserDefined, userDefinedApps);
}

SuperCodex::IpFilter SubSystems::copyUserDefinedApp()
{
    std::shared_lock<std::shared_mutex> lock(userDefinedAppMutex);
    return userDefinedApps;
}

SubSystems::FqdnGetter::FqdnGetter()
    : feather("apps.fqdns"s, SQLITE_OPEN_READONLY)
{
    feather.useWal();
    feather.prepare("SELECT name FROM fqdns WHERE ip=?;"s);
}

std::vector<std::string> SubSystems::FqdnGetter::get(const std::string_view &ip)
{
    std::vector<std::string> result;
    // prepare for result
    feather.bindBlob(1, ip.data(), ip.size());
    while (feather.next() == SQLITE_ROW)
        result.push_back(std::string(feather.getText(0)));

    // reset statement for later use
    feather.reset();

    return result;
}

void SubSystems::postImportPcap(mg_connection *connection, const std::string &path, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    if (path.size() <= 1) {
        mg_send_http_error(connection, 400, "File name is not declared");
        return;
    }
    if (!parameters.contains("raw"s)) {
        mg_send_http_error(connection, 400, "Can't find raw PCAP file stream");
        return;
    }

    // create import PCAP directory if one doesn't exist (e.g. deleted)
    if (!std::filesystem::exists(importPcapPath))
        std::filesystem::create_directory(importPcapPath);

    // write down file
    const std::string &raw = parameters.at("raw"s);
    std::ofstream file(importPcapPath + path, std::ios::binary | std::ios::trunc);
    file.write(raw.data(), raw.size());
    file.close();

    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void SubSystems::patchImportPcap(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    if (!std::filesystem::exists(importPcapPath)) {
        mg_send_http_error(connection, 404, "NO PCAP files registered to import");
        return;
    }

    // determine required parameters
    if (!parameters.contains("feedname"s)) {
        mg_send_http_error(connection, 400, "Required parameter(feedname) doesn't exist");
        return;
    }

    // check whether the feed already exists
    const std::string &feedname = parameters.at("feedname"s);
    std::filesystem::path newFeed = CodexIndex::feedRoot + feedname;
    if (std::filesystem::exists(newFeed)) {
        mg_send_http_error(connection, 409, "Data feed(%s) already exists", feedname.data());
        return;
    }

    // enumerate uploaded files
    std::vector<std::filesystem::path> sources;
    for (const auto &entry : std::filesystem::directory_iterator(importPcapPath))
        if (entry.is_regular_file())
            sources.push_back(entry.path());

    // create new data feed directory and move files
    std::filesystem::create_directory(newFeed);
    for (const auto &source : sources) {
        std::filesystem::path destination(newFeed);
        destination.append(source.filename().string());
        std::filesystem::copy_file(source, destination); // std::filesystem::rename may emit exception if source and destination reside in different partition/volume, especially on Linux
    }
    std::filesystem::remove_all(importPcapPath);

    // start spin4
#ifdef _WIN32
    std::string command = "spin4 "s + feedname;
#else
    std::string command = "./spin4 "s + feedname;
#endif
    auto result = system(command.data());
    if (result == 0)
        Civet7::respond200(connection, "\r\n", 2, "text/plain");
    else
        mg_send_http_error(connection, 500, "There can be internal server error during import");
}

void SubSystems::getImportPcap(mg_connection *connection)
{
    if (!std::filesystem::exists(importPcapPath)) {
        mg_send_http_error(connection, 404, "NO PCAP files registered to import");
        return;
    }

    // enumerate and sort files
    std::vector<std::string> files;
    for (const auto &entry : std::filesystem::directory_iterator(importPcapPath))
        files.push_back(entry.path().filename().string());
    std::sort(files.begin(), files.end());

    // build result JSON
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *rootArray = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, rootArray);
    for (const auto &file : files)
        yyjson_mut_arr_add_strn(document, rootArray, file.data(), file.size());

    // respond
    Civet7::respond200(connection, document);
}
void SubSystems::deleteImportPcap(mg_connection *connection, const std::string &path)
{
    if (!std::filesystem::exists(importPcapPath)) {
        mg_send_http_error(connection, 404, "NO PCAP files registered to import");
        return;
    }

    if (path.empty() || path == "/"s) { // delete all the files
        std::filesystem::remove_all(importPcapPath);
        mg_send_http_error(connection, 204, "\r\n\r\n");
    } else { // delete specific file
        if (!std::filesystem::exists(importPcapPath + path)) {
            mg_send_http_error(connection, 404, "No such file: %s", path.data());
            return;
        }
        std::filesystem::remove(importPcapPath + path); // filename must contains '/' in front
        mg_send_http_error(connection, 204, "\r\n\r\n");
    }
}

void SubSystems::getWorkingHoursReport(mg_connection *connection, const std::string feedName, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check whether the feed exists
    if (!DataFeed::feeds.contains(feedName)) {
        mg_send_http_error(connection, 404, "Data feed not found: %s", feedName.data());
        return;
    }

    WorkingHourCondition reportCondition;

    // parse parameters
    try {
        // from, to
        reportCondition.from = std::stoi(parameters.at("from"s));
        reportCondition.to = std::stoi(parameters.at("to"s));

        // weekdays
        const std::string &weekdaysRaw = parameters.at("weekdays"s);
        for (size_t i = 0; i < 7; ++i)
            reportCondition.weekdays[i] = (weekdaysRaw.at(i) == '1');

        // base
        const std::string &base = parameters.at("base"s);
        if (base == "bytes"s || base == "bps"s) {
            reportCondition.chapterToOpen = SuperCodex::BPSPERSESSION;
            reportCondition.toBps = (base == "bps"s);
        } else if (base == "packets"s)
            reportCondition.chapterToOpen = SuperCodex::PPSPERSESSION;
        else if (base == "latencies"s)
            reportCondition.chapterToOpen = SuperCodex::RTTS;
        else if (base == "timeouts"s)
            reportCondition.chapterToOpen = SuperCodex::TIMEOUTS;
        else if (base == "tcprsts"s)
            reportCondition.chapterToOpen = SuperCodex::TCPRSTS;
        else if (base == "tcpzerowindows"s)
            reportCondition.chapterToOpen = static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPZEROWINDOW);
        else if (base == "tcpdupacks"s)
            reportCondition.chapterToOpen = SuperCodex::TCPDUPACKS;
        else if (base == "tcpretransmissions"s)
            reportCondition.chapterToOpen = SuperCodex::TCPRETRANSMISSIONS;
        else if (base == "tcpoutoforders"s)
            reportCondition.chapterToOpen = static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPOUTOFORDER);
        else if (base == "tcpportsreused"s)
            reportCondition.chapterToOpen = static_cast<SuperCodex::ChapterType>(SuperCodex::ChapterType::TCPMISCANOMALIES + MA_TCPPORTSREUSED);
        else
            throw "unknown base";

        // hstart, hend
        const std::string &hStart = parameters.at("hstart"s), &hEnd = parameters.at("hend"s);
        reportCondition.hStartHour = std::stoi(hStart.substr(0, 2));
        if (reportCondition.hStartHour > 23)
            throw "time value out of bound";
        reportCondition.hStartMinute = std::stoi(hStart.substr(2));
        if (reportCondition.hStartMinute > 59)
            throw "time value out of bound";
        reportCondition.hEndHour = std::stoi(hEnd.substr(0, 2));
        if (reportCondition.hEndHour > 23)
            throw "time value out of bound";
        reportCondition.hEndMinute = std::stoi(hEnd.substr(2));
        if (reportCondition.hEndMinute > 59)
            throw "time value out of bound";

        // select how to organize the data
        try {
            const std::string &groupByRaw = parameters.at("groupby");
            WorkingHourResult result;
            if (groupByRaw == "days"s)
                result = getWorkingHoursReportByDay(feedName, reportCondition);
            else if (groupByRaw == "tags"s)
                result = getWorkingHoursReportPerTag(feedName, reportCondition);
            else if (groupByRaw == "services"s)
                result = getWorkingHoursReportPerService(feedName, reportCondition);
            else
                throw "Can't recognize standard for grouping";

            // exception handling: no data
            if (result.records.empty()) {
                mg_send_http_error(connection, 404, "No records for given condition. Timestamp out of bounds or SuperCache may not be available for the time.");
                return;
            }

            // get the top
            auto &allTimeTop = result.records.front();
            for (const auto &pair : result.records)
                if (pair.second.top > allTimeTop.second.top)
                    allTimeTop = pair;

            // return result
            if (parameters.contains("type"s) && parameters.at("type"s) == "tabseparated"s) {
                // send in tab separated format
                std::string response;
                response.reserve(10000000); // about 10MB
                response.append("Key\tValue\tTop\tTopAt\n"s);
                // eenumerate individual records
                for (const auto &pair : result.records)
                    response.append(pair.first).append('\t' + std::to_string(pair.second.sum)).append('\t' + std::to_string(pair.second.top)).append('\t' + FeedRefinerAbstract::epochToIsoDate(pair.second.topAt)).push_back('\n');
                // show all time top
                response.append("================================================================================\n").append("Top value all the time: "s).append(std::to_string(allTimeTop.second.top) + " ("s).append(allTimeTop.first).append(", "s).append(FeedRefinerAbstract::epochToIsoDate(allTimeTop.second.topAt)).push_back(')');

                Civet7::respond200(connection, response.data(), response.size(), "text/tab-separated-values");
            } else {
                // send in JSON
                yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
                yyjson_mut_val *rootObject = yyjson_mut_obj(document);
                yyjson_mut_doc_set_root(document, rootObject);
                // eenumerate individual records
                yyjson_mut_val *recordsArray = yyjson_mut_arr(document);
                yyjson_mut_obj_add_val(document, rootObject, "records", recordsArray);
                std::string temp;
                for (const auto &pair : result.records) {
                    yyjson_mut_val *object = yyjson_mut_obj(document);
                    yyjson_mut_arr_add_val(recordsArray, object);
                    yyjson_mut_obj_add_strncpy(document, object, "key", pair.first.data(), pair.first.size());
                    yyjson_mut_obj_add_sint(document, object, "value", pair.second.sum);
                    yyjson_mut_obj_add_sint(document, object, "top", pair.second.top);
                    yyjson_mut_obj_add_sint(document, object, "topat", pair.second.topAt);
                }
                // show all time top
                yyjson_mut_val *topObject = yyjson_mut_obj(document);
                yyjson_mut_obj_add_val(document, rootObject, "top", topObject);
                yyjson_mut_obj_add_strn(document, topObject, "key", allTimeTop.first.data(), allTimeTop.first.size());
                yyjson_mut_obj_add_int(document, topObject, "top", allTimeTop.second.top);
                yyjson_mut_obj_add_int(document, topObject, "topat", allTimeTop.second.topAt);

                // response
                Civet7::respond200(connection, document);
            }
        } catch (std::exception &e) {
            mg_send_http_error(connection, 500, "Internal server error. Details: %s", e.what());
            return;
        } catch (...) {
            mg_send_http_error(connection, 500, "Internal server error. Details unknown.");
            return;
        }
    } catch (...) {
        mg_send_http_error(connection, 400, "Failed to detect / parse required parameters");
        return;
    }
}

SubSystems::WorkingHourResult SubSystems::getWorkingHoursReportByDay(const std::string &feedName, const WorkingHourCondition &condition)
{
    WorkingHourResult result;
    std::string currentDate, dateOnRecord;
    uint64_t recordsRead = 0; // number of database records read(one per minute)
    WorkingHourResult::Stat stat{}, statZero{};
    FeedRefinerAbstract::ValuesRtt rtts{}, rttsZero{}; // for RTT
    getWorkingHoursReportReadDatabase(feedName, condition, [&](const uint32_t timestamp, const SuperCache::PmpiTriplet &triplet) {
        dateOnRecord = FeedRefinerAbstract::epochToIsoDate(timestamp, "%Y-%m-%d"); // date only
        if (currentDate.empty()) // there's no way to get starting date before SQL query loop
            currentDate = dateOnRecord;
        if (currentDate != dateOnRecord) {
            // flush data
            if (condition.chapterToOpen == SuperCodex::RTTS) // preprocess
                stat.sum = rtts.represent();
            else if (condition.toBps && recordsRead) {
                stat.sum = stat.sum * 8 / (recordsRead * 60);
                stat.top = stat.top * 8 / 60; // this is for only one minute
            }
            result.records.push_back(std::make_pair(currentDate, stat));

            // reset counters
            currentDate = dateOnRecord;
            recordsRead = 0;
            stat = statZero;
            rtts = rttsZero;
        }

        // accumulate values
        ++recordsRead;
        if (condition.chapterToOpen == SuperCodex::RTTS) {
            for (const char *cursor = triplet.perDestinationRaw.data(), *cursorEnd = cursor + triplet.perDestinationRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingleRtt)
                rtts += ((const std::pair<FeedRefinerTopN::KeySingle, FeedRefinerTopN::ValuesRtt> *) cursor)->second;
            const auto representative = rtts.represent();
            if (stat.top < representative) {
                stat.top = representative;
                stat.topAt = timestamp;
            }
        } else if (condition.chapterToOpen == SuperCodex::BPSPERSESSION || condition.chapterToOpen == SuperCodex::PPSPERSESSION) {
            uint64_t sum = 0;
            for (const char *cursor = triplet.perDestinationRaw.data(), *cursorEnd = cursor + triplet.perDestinationRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle)
                sum += ((const std::pair<FeedRefinerTopN::KeySingle, uint64_t> *) cursor)->second;
            stat.sum += sum;
            if (stat.top < sum) {
                stat.top = sum;
                stat.topAt = timestamp;
            }
        } else {
            uint64_t sum = 0;
            for (const char *cursor = triplet.perDestinationRaw.data(), *cursorEnd = cursor + triplet.perDestinationRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle2)
                sum += ((const std::pair<FeedRefinerTopN::KeySingle, std::pair<uint64_t, uint64_t>> *) cursor)->second.first;
            stat.sum += sum;
            if (stat.top < sum) {
                stat.top = sum;
                stat.topAt = timestamp;
            }
        }
    });

    // flush data for last day(unsaved yet)
    if (condition.chapterToOpen == SuperCodex::RTTS) // preprocess
        stat.sum = rtts.represent();
    else if (condition.toBps && recordsRead) {
        stat.sum = stat.sum * 8 / (recordsRead * 60);
        stat.top = stat.top * 8 / 60; // this is for only one minute
    }
    result.records.push_back(std::make_pair(currentDate, stat));

    return result;
}

SubSystems::WorkingHourResult SubSystems::getWorkingHoursReportPerTag(const std::string &feedName, const WorkingHourCondition &condition)
{
    // register tags with name ending with asterisk(*) only
    std::vector<std::pair<SuperCodex::IpFilter, std::string>> filters; // IP filter for specific tag + that tag name
    nlohmann::json tags = nlohmann::json::parse(std::ifstream(CodexIndex::feedRoot + feedName + "/tags.json"s));
    for (const auto &pair : tags.items()) {
        std::pair<SuperCodex::IpFilter, std::string> filterPair;
        filterPair.second = pair.key();
        if (filterPair.second.front() == '*') { // tag name starting with asterisk + IP address is NOT empty
            const auto &ips = pair.value()["ips"s];
            if (!ips.empty()) // IPs is empty = "all"(=meaningless)
                for (const auto &ip : ips)
                    filterPair.first.registerNetwork(ip.get<std::string>(), 0, ""s);
        }

        if (!filterPair.first.isEmpty)
            filters.push_back(filterPair);
    }

    // prepare for enumerating tags for specific IP
    std::function<ankerl::unordered_dense::set<std::string>(const std::string &, const std::string &)> getTagNames = [&](const std::string &ip, const std::string &ip2) -> ankerl::unordered_dense::set<std::string> {
        ankerl::unordered_dense::set<std::string> result;
        result.reserve(filters.size());

        for (const auto &pair : filters) {
            const auto &filter = pair.first;
            if (filter.contains(ip))
                result.insert(pair.second);
            if (filter.contains(ip2))
                result.insert(pair.second);
        }

        return result;
    };

    // initalize variables
    uint64_t recordsRead = 0; // number of database records read(one per minute)
    ankerl::unordered_dense::map<std::string, FeedRefinerTopN::ValuesRtt> rttsAccumulated, rttsGrouped;
    ankerl::unordered_dense::map<std::string, uint64_t> grouped;
    ankerl::unordered_dense::map<std::string, WorkingHourResult::Stat> accumulated;
    getWorkingHoursReportReadDatabase(feedName, condition, [&](const uint32_t timestamp, const SuperCache::PmpiTriplet &triplet) {
        // accumulate values
        ++recordsRead;

        // if we deal with RTT......
        if (condition.chapterToOpen == SuperCodex::RTTS) {
            // merge data per tag
            rttsGrouped.clear();
            for (const char *cursor = triplet.perIpToServiceRaw.data(), *cursorEnd = cursor + triplet.perIpToServiceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToServiceRtt) {
                const auto item = (const std::pair<FeedRefinerTopN::KeyIpToService, FeedRefinerTopN::ValuesRtt> *) cursor;
                const auto ipLength = item->first.ipLength;
                if (ipLength == 4 || ipLength == 16) {
                    const auto tagNames = getTagNames(std::string(item->first.ip1, ipLength), std::string(item->first.ip2, ipLength));
                    if (!tagNames.empty())
                        for (const auto &tagName : tagNames)
                            rttsGrouped[tagName] += item->second;
                }
            }

            // merge per tag values for this minute, and determine top
            for (const auto &rttNow : rttsGrouped) {
                auto &target = accumulated[rttNow.first];
                // merge per tag value
                rttsAccumulated[rttNow.first] += rttNow.second;

                // determine top
                const auto representativeNow = rttNow.second.represent();
                if (target.top < representativeNow) {
                    target.top = representativeNow;
                    target.topAt = timestamp;
                }
            }
        } else { // data source is not RTT
            // merge data per tag
            grouped.clear();
            if (condition.chapterToOpen == SuperCodex::BPSPERSESSION || condition.chapterToOpen == SuperCodex::PPSPERSESSION) { // BPS or PPS
                for (const char *cursor = triplet.perIpToServiceRaw.data(), *cursorEnd = cursor + triplet.perIpToServiceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService) {
                    const auto item = (const std::pair<FeedRefinerTopN::KeyIpToService, uint64_t> *) cursor;
                    const auto ipLength = item->first.ipLength;
                    if (ipLength == 4 || ipLength == 16) {
                        const auto tagNames = getTagNames(std::string(item->first.ip1, ipLength), std::string(item->first.ip2, ipLength));
                        if (!tagNames.empty())
                            for (const auto &tagName : tagNames)
                                grouped[tagName] += item->second;
                    }
                }
            } else { // everything else
                for (const char *cursor = triplet.perIpToServiceRaw.data(), *cursorEnd = cursor + triplet.perIpToServiceRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeIpToService2) {
                    const auto item = (const std::pair<FeedRefinerTopN::KeyIpToService, std::pair<uint64_t, uint64_t>> *) cursor;
                    const auto ipLength = item->first.ipLength;
                    if (ipLength == 4 || ipLength == 16) {
                        const auto tagNames = getTagNames(std::string(item->first.ip1, ipLength), std::string(item->first.ip2, ipLength));
                        if (!tagNames.empty())
                            for (const auto &tagName : tagNames)
                                grouped[tagName] += item->second.first;
                    }
                }
            }

            // merge per tag values for this minute, and determine top
            for (const auto &now : grouped) {
                auto &target = accumulated[now.first];
                const auto value = now.second;
                // merge per tag value
                accumulated[now.first].sum += value;

                // determine top
                if (target.top < value) {
                    target.top = value;
                    target.topAt = timestamp;
                }
            }
        }
    });

    // prepare for result
    std::vector<std::pair<std::string, WorkingHourResult::Stat>> result = accumulated.values();
    // post processing
    if (condition.chapterToOpen == SuperCodex::RTTS) { // if the data source is RTTs, convert raw records into representative valus
        for (auto &pair : result)
            if (rttsAccumulated.contains(pair.first))
                pair.second.sum = rttsAccumulated[pair.first].represent();
            else
                logger.oops("No data for tag "s + pair.first);
    } else if (condition.toBps && recordsRead) {
        for (auto &pair : result) {
            pair.second.sum = pair.second.sum * 8 / (recordsRead * 60);
            pair.second.top = pair.second.top * 8 / 60;
        }
    }

    // sort result and return
    std::sort(result.begin(), result.end(), [](const std::pair<std::string, WorkingHourResult::Stat> &a, const std::pair<std::string, WorkingHourResult::Stat> &b) -> bool { return a.second.sum > b.second.sum; });
    return WorkingHourResult{result};
}

SubSystems::WorkingHourResult SubSystems::getWorkingHoursReportPerService(const std::string &feedName, const WorkingHourCondition &condition)
{
    // initialize some variables
    size_t maxServiceIps = 100000; // determines the limit of service IPs the hashmap will have
    uint64_t recordsRead = 0; // number of database records read(one per minute)
    ankerl::unordered_dense::map<std::string, FeedRefinerTopN::ValuesRtt> rttsAccumulated, rttsGrouped;
    rttsAccumulated.reserve(maxServiceIps * 2);
    rttsGrouped.reserve(maxServiceIps * 2);
    ankerl::unordered_dense::map<std::string, uint64_t> grouped;
    ankerl::unordered_dense::map<std::string, WorkingHourResult::Stat> accumulated;
    accumulated.reserve(maxServiceIps * 2);
    grouped.reserve(maxServiceIps * 2);

    // prepare for service name cache
    const SuperCodex::IpFilter userDefinedServices = copyUserDefinedApp();
    ankerl::unordered_dense::map<std::string, std::vector<std::string>> fqdnCache; // IP address + FQDNs
    FqdnGetter fqdnGetter;
    std::function<std::vector<std::string>(const std::string &, const uint16_t)> getServiceNames = [&](const std::string &ip, const uint16_t port) -> std::vector<std::string> {
        if (!fqdnCache.contains(ip))
            fqdnCache[ip] = fqdnGetter.get(ip);

        auto result = fqdnCache[ip];
        std::string userDefinedService = userDefinedServices.getAlias(ip, port);
        if (!userDefinedService.empty())
            result.push_back(userDefinedService);

        return result;
    };

    // read SuperCache
    getWorkingHoursReportReadDatabase(feedName, condition, [&](const uint32_t timestamp, const SuperCache::PmpiTriplet &triplet) {
        // accumulate values
        ++recordsRead;
        if (condition.chapterToOpen == SuperCodex::RTTS) {
            // merge data per service
            rttsGrouped.clear();
            for (const char *cursor = triplet.perDestinationRaw.data(), *cursorEnd = cursor + triplet.perDestinationRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingleRtt) {
                const auto item = (const std::pair<FeedRefinerTopN::KeySingle, FeedRefinerTopN::ValuesRtt> *) cursor;
                const auto ipLength = item->first.ipLength;
                if (ipLength == 4 || ipLength == 16) {
                    const auto serviceNames = getServiceNames(std::string((const char *) item->first.ip, item->first.ipLength), item->first.port);
                    if (!serviceNames.empty())
                        for (const auto &service : serviceNames)
                            rttsGrouped[service] += item->second;
                }
            }

            // merge per tag values for this minute, and determine top
            for (const auto &rttNow : rttsGrouped) {
                auto &target = accumulated[rttNow.first];
                // merge per tag value
                rttsAccumulated[rttNow.first] += rttNow.second;

                // determine top
                const auto representativeNow = rttNow.second.represent();
                if (target.top < representativeNow) {
                    target.top = representativeNow;
                    target.topAt = timestamp;
                }
            }
        } else {
            grouped.clear();
            if (condition.chapterToOpen == SuperCodex::BPSPERSESSION || condition.chapterToOpen == SuperCodex::PPSPERSESSION) {
                for (const char *cursor = triplet.perDestinationRaw.data(), *cursorEnd = cursor + triplet.perDestinationRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle) {
                    const auto item = (const std::pair<FeedRefinerTopN::KeySingle, uint64_t> *) cursor;
                    const size_t ipLength = item->first.ipLength;
                    if (ipLength == 4 || ipLength == 16) {
                        const auto serviceNames = getServiceNames(std::string((const char *) item->first.ip, item->first.ipLength), item->first.port);
                        if (!serviceNames.empty())
                            for (const auto &service : serviceNames)
                                grouped[service] += item->second;
                    }
                }
            } else {
                for (const char *cursor = triplet.perDestinationRaw.data(), *cursorEnd = cursor + triplet.perDestinationRaw.size(); cursor < cursorEnd; cursor += SuperCache::pmpiSizeSingle2) {
                    const auto item = (const std::pair<FeedRefinerTopN::KeySingle, std::pair<uint64_t, uint64_t>> *) cursor;
                    const size_t ipLength = item->first.ipLength;
                    if (ipLength == 4 || ipLength == 16) {
                        const auto serviceNames = getServiceNames(std::string((const char *) item->first.ip, item->first.ipLength), item->first.port);
                        if (!serviceNames.empty())
                            for (const auto &service : serviceNames)
                                grouped[service] += item->second.first;
                    }
                }
            }

            // merge per values for this minute, and determine top
            for (const auto &now : grouped) {
                auto &target = accumulated[now.first];
                const auto value = now.second;
                // merge per tag value
                accumulated[now.first].sum += value;

                // determine top
                if (target.top < value) {
                    target.top = value;
                    target.topAt = timestamp;
                }
            }
        }

        // remain only top max records
        if (condition.chapterToOpen == SuperCodex::RTTS) {
            if (rttsAccumulated.size() >= maxServiceIps * 3 / 2) {
                auto values = rttsAccumulated.values();
                std::sort(values.begin(), values.end(), [](const std::pair<std::string, FeedRefinerTopN::ValuesRtt> &a, const std::pair<std::string, FeedRefinerTopN::ValuesRtt> &b) -> bool { return a.second.represent() > b.second.represent(); });
                values.resize(maxServiceIps);
                rttsAccumulated.replace(std::move(values));
            }
        } else if (accumulated.size() >= maxServiceIps * 3 / 2) {
            auto values = accumulated.values();
            std::sort(values.begin(), values.end(), [](const std::pair<std::string, WorkingHourResult::Stat> &a, const std::pair<std::string, WorkingHourResult::Stat> &b) -> bool { return a.second.sum > b.second.sum; });
            values.resize(maxServiceIps);
            accumulated.replace(std::move(values));
        }
    });

    // prepare for result
    std::vector<std::pair<std::string, WorkingHourResult::Stat>> result = accumulated.values();
    // post processing
    if (condition.chapterToOpen == SuperCodex::RTTS) { // if the data source is RTTs, convert raw records into representative valus
        for (auto &pair : result)
            if (rttsAccumulated.contains(pair.first))
                pair.second.sum = rttsAccumulated[pair.first].represent();
            else
                logger.oops("No data for tag "s + pair.first);
    } else if (condition.toBps && recordsRead) {
        for (auto &pair : result) {
            pair.second.sum = pair.second.sum * 8 / (recordsRead * 60);
            pair.second.top = pair.second.top * 8 / 60;
        }
    }

    // sort result and return
    std::sort(result.begin(), result.end(), [](const std::pair<std::string, WorkingHourResult::Stat> &a, const std::pair<std::string, WorkingHourResult::Stat> &b) -> bool { return a.second.sum > b.second.sum; });
    return WorkingHourResult{result};
}

void SubSystems::getWorkingHoursReportReadDatabase(const std::string &feedName, const WorkingHourCondition &condition, std::function<void(const uint32_t, const SuperCache::PmpiTriplet &)> buildRecords)
{
    // prepare for first starting and ending time in day as epoch timestamp
    time_t from = condition.from, to = condition.to, todayFrom, todayTo, midnightLastDay;
    struct tm timestampInTm, lastDayInTm;
#ifdef WIN32
    localtime_s(&timestampInTm, &from);
    localtime_s(&lastDayInTm, &to);
#else
    localtime_r(&from, &timestampInTm);
    localtime_r(&to, &lastDayInTm);
#endif
    // determine epoch timestamp for 23:59:59 of last day, which is used as the point of loop termination
    lastDayInTm.tm_hour = 23;
    lastDayInTm.tm_min = 59;
    lastDayInTm.tm_sec = 59;
    midnightLastDay = mktime(&lastDayInTm);

    // determine lookback window for first day
    auto weekday = timestampInTm.tm_wday; // weekday
    timestampInTm.tm_sec = 0;
    timestampInTm.tm_hour = condition.hStartHour;
    timestampInTm.tm_min = condition.hStartMinute;
    todayFrom = mktime(&timestampInTm); // starting time in epoch timestamp
    timestampInTm.tm_hour = condition.hEndHour;
    timestampInTm.tm_min = condition.hEndMinute;
    todayTo = mktime(&timestampInTm); // ending time in epoch timestamp

    // start loop
    while (todayFrom < midnightLastDay) {
        if (condition.weekdays[weekday]) {
            // prepare for database access
            FeatherLite feather(CodexIndex::feedRoot + feedName + "/supercache.pmpi"s, SQLITE_OPEN_READONLY);
            feather.prepare("SELECT originalsize,filepath,timestamp FROM rows WHERE timestamp>=? AND timestamp<=? AND chapter=?;"s);
            feather.bindInt(1, todayFrom);
            feather.bindInt(2, todayTo);
            feather.bindInt(3, condition.chapterToOpen);

            // read record and build records, and free memory after work is done
            while (feather.next() == SQLITE_ROW) {
                auto triplet = SuperCache::getPmpiTriplet(std::string(feather.getText(1)), feather.getInt(0));
                buildRecords(feather.getInt(2), triplet);
                delete[] triplet.decompressedRaw;
            }
        }

        // go to next day
        todayFrom += 86400;
        todayTo += 86400;
        weekday = (++weekday) % 7;
    }
}
