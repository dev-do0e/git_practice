#include "civet7.hpp"

#include <filesystem>
#include <sstream>
#include <yyjson.h>

#include "codexindex.h"
#include "paradox.h"
#include "paranoia.h"
#include "subsystems.h"
#include "user.h"
#include "svcd.h"
#include "reportmanager.h"
#include "ailampadxanomaly.h"

// extern variables
std::string Civet7::startupTime;
mg_context *Civet7::context;
std::string Civet7::staticFileRoot;
mg_form_data_handler Civet7::formHandlerProto;
ankerl::unordered_dense::map<std::string, std::string> Civet7::kvs;
std::string Civet7::kvsFilePath("kvs.json"s);
std::mutex Civet7::kvsMutex;
Logger Civet7::logger("Civet7"s);

using namespace std::string_literals;

void Civet7::start(const nlohmann::json &settings)
{
    logger.log("Start up Civet7"s);

    // record startup time
    startupTime = FeedRefinerAbstract::epochToIsoDate(time(nullptr));

    // load global key-value store
    yyjson_read_err readError;
    yyjson_doc *document = yyjson_read_file(kvsFilePath.data(), YYJSON_READ_NOFLAG, nullptr, &readError);
    if (document == nullptr) {
        logger.oops("Failed to parse kvs.json. Detatils: "s + readError.msg);
        if (std::filesystem::exists(kvsFilePath)) {
            logger.oops("Removing kvs.json from disk");
            std::filesystem::remove(kvsFilePath);
        }
    } else {
        yyjson_val *root = yyjson_doc_get_root(document);
        if (yyjson_is_obj(root)) {
            yyjson_obj_iter iter = yyjson_obj_iter_with(root);
            for (yyjson_val *key = yyjson_obj_iter_next(&iter); key; key = yyjson_obj_iter_next(&iter))
                kvs[yyjson_get_str(key)] = yyjson_get_str(yyjson_obj_iter_get_val(key));
        }
    }
    yyjson_doc_free(document);

    // read feeds
    logger.log("Read feeds from "s + CodexIndex::feedRoot);
    auto feedRootSize = CodexIndex::feedRoot.size();
    for (const auto &feedPath : std::filesystem::directory_iterator(CodexIndex::feedRoot))
        if (std::filesystem::is_directory(feedPath)) {
            std::string feedName = feedPath.path().string().substr(feedRootSize);
            if (feedName == "lost+found"s || feedName.at(0) == '.') {
                logger.log("Skip directory: "s + feedName);
                continue;
            } else
                logger.log("Adding new feed: " + feedName);
            DataFeed::feeds[feedName] = new DataFeed(feedName); // register all subdirectories
        }

    // set form handler
    formHandlerProto.field_found = fieldFound;
    formHandlerProto.field_get = getField;
    formHandlerProto.field_store = storeField;
    formHandlerProto.user_data = nullptr;

    // send configurations to CivetWeb
    auto configuration = settings["Civet7"];
    char **config = (char **) malloc(sizeof(char *) * configuration.size() * 2 + 1);
    int cursor = 0;
    for (auto member = configuration.cbegin(), memberEnd = configuration.cend(); member != memberEnd; ++member) {
        // write name
        std::string key = member.key();
        config[cursor] = (char *) malloc(key.size() + 1);
        memcpy(config[cursor], key.data(), key.size());
        config[cursor][key.size()] = '\0'; // make it null-terminated
        cursor++;
        // get value
        std::string valueString;
        if (member.value().is_number_integer())
            valueString = std::to_string(member.value().get<int>());
        else if (member.value().is_string())
            valueString.append(member.value().get<std::string>());
        // write value
        config[cursor] = (char *) malloc(valueString.size() + 1);
        memcpy(config[cursor], valueString.c_str(), valueString.size());
        config[cursor][valueString.size()] = '\0'; // // make it null-terminated
        ++cursor;
    }
    config[cursor] = nullptr;

    // start server
    struct mg_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    context = mg_start(&callbacks, nullptr, const_cast<const char **>(config));
    mg_server_ports portListening[2];
    auto numberOfPorts = mg_get_server_ports(context, 2, portListening);
    logger.log("Number of ports listening: "s + std::to_string(numberOfPorts));
    for (int i = 0; i < numberOfPorts; ++i)
        logger.log("Listening to "s + std::to_string(portListening[i].port));

    // register main request handler
    mg_set_request_handler(context, "/q/", processQuery, nullptr);
    mg_set_request_handler(context, "/~/", controlSpin7, nullptr);
    mg_set_request_handler(context, "/_/", controlParadox, nullptr);
    mg_set_request_handler(context, "/", sendStaticFile, nullptr);
}

int Civet7::sendStaticFile(mg_connection *connection, void *data)
{
    const mg_request_info *request = mg_get_request_info(connection);

    // 요청 메서드가 GET이 아니면 405 에러 반환
    logger.log("Static file request from "s + request->remote_addr + ':' + request->request_uri);
    if (memcmp(request->request_method, "GET", 3))
        return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");

    // 파일 경로 생성 및 파일 존재 여부 확인 후 전송
    std::string localPath(staticFileRoot + request->local_uri);
    if (std::filesystem::exists(localPath) && std::filesystem::is_regular_file(localPath))
        mg_send_file(connection, localPath.data());
    else
        mg_send_file(connection, (staticFileRoot + "/index.html"s).data());

    return 1;
}

// 코드 자체는 간결하고, GET 요청만 허용하며, 파일이 없으면 index.html을 반환하는 구조입니다.
// 개선점이 있다면, 
// 1. 경로 탐색(Directory Traversal) 공격 방지(예: ../ 등) 체크가 필요할 수 있습니다.
// 2. 파일이 없을 때 404 에러를 반환하는 것도 고려해볼 수 있습니다.
// 3. mg_send_file의 반환값을 체크해서 에러 로깅을 추가할 수도 있습니다.

int Civet7::processQuery(mg_connection *connection, void *data)
{
    const mg_request_info *request = mg_get_request_info(connection);

    // prepare for path routing
    std::string path(request->local_uri), method(request->request_method);
    for (int i = 0, iEnd = path.size() - 2; i < iEnd; i++)
        while (path.at(i) == '/' && path.at(i + 1) == '/')
            path.erase(i + 1); // remove repeated slashes(e.g. "//")
    if (path[path.size() - 1] == '/')
        path.pop_back(); // remove tailing '/'
    path.erase(0, 2); // remove heading "/q"

    // get parameters(urlencoded + JSON)
    ankerl::unordered_dense::map<std::string, std::string> parameters = requestParameters(connection, method);

    // process / check login
    if (parameters.contains("username") && method == "POST")
        User::login(connection, parameters); // process login
    else {
        // check login
        User::usersMutex.lock_shared();
        std::string username = User::usernameFromConnection(connection);
        User::usersMutex.unlock_shared();
        if (username.empty()) {
            logger.log("Civet7 Query without login: "s + method + ' ' + request->local_uri + " from "s + request->remote_addr + ':' + std::to_string(request->remote_port));
            return 1 + mg_send_http_error(connection, 403, "This session doesn't come with valid user authentication. Please login and try again.");
        }

        // log query
        logger.log("Query: "s + method + ' ' + request->local_uri + " by "s + username + " from "s + request->remote_addr + ':' + std::to_string(request->remote_port));

        // route: /kvs
        if (path.find("/kvs"s) == 0) {
            path.erase(0, 4); // remove header "/kvs"
            if (method == "GET"s)
                getValues(connection);
            else if (method == "POST"s)
                setValues(connection, parameters);
            else if (method == "DELETE"s)
                deleteValues(connection, username);
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
        }

        // route: /sysinfo
        else if (path.find("/sysinfo") == 0) {
            path.erase(0, 8); // remove header "/sysinfo"
            if (method == "GET"s)
                SubSystems::getSysInfo(connection);
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
        }

        // route: /feed
        else if (path.find("/feed"s) == 0) {
            path.erase(0, 5); // remove header "/feed"
            if (path.empty()) {
                if (method == "GET"s) {
                    std::string feedList = DataFeed::enumerateFeeds();
                    mg_send_http_ok(connection, "application/json", feedList.size());
                    mg_write(connection, feedList.data(), feedList.size());
                    return 1;
                } else
                    return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
            } else {
                // get feed name
                std::string feedName = cutPath(path).erase(0, 1);

                // check existence of the feed
                if (!DataFeed::feeds.contains(feedName))
                    return 1 + mg_send_http_error(connection, 404, "Unknown feed. check the name of the feed and try again");

                // route: feed->schrodinger
                else if (path.find("/schrodinger"s) == 0) {
                    path.erase(0, 12); // remove "/schrodinger"
                    if (method == "GET")
                        DataFeed::feeds.at(feedName)->getSchrodinger(connection, parameters);
                    else
                        return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
                }

                // route: feed->refinery
                else if (path.find("/refinery"s) == 0) {
                    path.erase(0, 9); // remove "/refinery"
                    if (method == "POST"s)
                        DataFeed::feeds.at(feedName)->postRefinery(connection, username, parameters);
                    else if (method == "GET"s) {
                        if (path.empty())
                            DataFeed::feeds.at(feedName)->getProgress(connection, username);
                        else
                            DataFeed::feeds.at(feedName)->getRefinery(connection, username, path, parameters);
                    } else if (method == "DELETE"s)
                        DataFeed::feeds.at(feedName)->deleteRefinery(connection, username, path);
                    else if (method == "PUT"s)
                        DataFeed::feeds.at(feedName)->putRefinery(connection, username, path, parameters);
                    else
                        return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
                }

                // route: feed->tag
                else if (path.find("/tag"s) == 0) {
                    path.erase(0, 4); // remove "/tag"
                    if (method == "GET"s) {
                        if (path.empty())
                            DataFeed::feeds.at(feedName)->getTag(connection);
                        else
                            return 1 + mg_send_http_error(connection, 404, "\r\n\r\n");
                        ;

                    } else if (method == "PUT"s)
                        DataFeed::feeds.at(feedName)->putTag(connection, path, parameters);
                    else if (method == "DELETE"s)
                        DataFeed::feeds.at(feedName)->deleteTag(connection, path);
                    else
                        return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
                }

                // route: feed->ip
                else if (path.find("/ip"s) == 0) {
                    path.erase(0, 3); // remove "/ip/"
                    if (method == "GET"s)
                        DataFeed::feeds.at(feedName)->getIp(connection, path.erase(0, 1)); // check which tags this IP belongs to
                    else
                        return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
                }

                // route: feed->pcap
                else if (path.find("/pcap"s) == 0) {
                    path.erase(0, 5); // remove "/pcap"
                    if (method == "GET"s)
                        DataFeed::feeds.at(feedName)->getPcap(connection, parameters);
                    else
                        return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
                }

                // route: feed->bpms
                else if (path.find("/bpms"s) == 0) {
                    path.erase(0, 5); // remove "/bpms"
                    if (method == "GET"s)
                        DataFeed::feeds.at(feedName)->getBpms(connection, parameters);
                    else
                        return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
                }

                // route: feed->events
                else if (path.find("/events"s) == 0) {
                    path.erase(0, 7); // remove "/events"
                    if (method == "GET"s)
                        DataFeed::feeds.at(feedName)->getEvents(connection, parameters);
                    else
                        return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
                }

                // route: feed->size
                else if (path.find("/size"s) == 0) {
                    path.erase(0, 5); // remove "/size"
                    if (method == "GET"s) {
                        std::string buffer = std::to_string(DataFeed::codexIndex->codexSize(feedName));
                        respond200(connection, buffer.data(), buffer.size(), "text/text"s);
                    } else
                        return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
                }

                // route: feed->workinghours
                else if (path.find("/workinghours"s) == 0) {
                    path.erase(0, 13); // remove "/workinghours"
                    if (method == "GET"s)
                        SubSystems::getWorkingHoursReport(connection, feedName, parameters);
                    else
                        return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
                }

                // anything else. :P
                else
                    return 1 + mg_send_http_error(connection, 404, "\r\n\r\n");
            }
        }

        // route: /svcd
        else if (path.find("/svcd"s) == 0) {
            path.erase(0, 5); // remove heading "/svcd"
            if (path.empty())
                mg_send_http_error(connection, 400, "data feed not found");
            else {
                if (method == "GET")
                    ServiceDashboard::getSvcd(connection, path.substr(1));
                else
                    return 1 + mg_send_http_error(connection, 405, "\r\n");
            }
        }

        // route: /paradox
        else if (path.find("/paradox"s) == 0) {
            path.erase(0, 8); // remove heading "/paradox"
            if (path.empty()) {
                if (method == "GET"s)
                    Paradox::enumerateDevices(connection);
                else
                    return 1 + mg_send_http_error(connection, 405, "\r\n");
            } else {
                path.erase(0, 1);
                if (method == "GET"s) {
                    if (path == "ranking"s)
                        Paradox::getRanking(connection, parameters);
                    else if (path == "latest"s)
                        Paradox::getResultsLatest(connection);
                    else if (path == "topology"s)
                        Paradox::getResultsTopology(connection);
                    else
                        Paradox::getResults(connection, path, parameters);
                } else if (method == "POST"s) {
                    if (path == "latest"s)
                        Paradox::postResultsLatest(connection, parameters);
                    else
                        Paradox::updateDeviceDescription(connection, path, parameters, ""s);
                } else if (method == "DELETE"s)
                    Paradox::deleteDeviceOrResults(connection, path, parameters);
                else
                    return 1 + mg_send_http_error(connection, 405, "\r\n");
            }
        }

        // route: /paranoia
        else if (path.find("/paranoia"s) == 0) {
            path.erase(0, 9); // remove heading "/paranoia"
            if (path.empty()) { // enumerate devices
                if (method == "GET"s)
                    Paranoia::enumerateDevices(connection, parameters);
                else
                    return 1 + mg_send_http_error(connection, 405, "\r\n");
            } else { // do some details
                if (method == "GET"s) {
                    if (path == "/latest")
                        Paranoia::showLatestResults(connection);
                    else
                        Paranoia::getTestResults(connection, path, parameters);
                } else if (method == "PUT"s)
                    Paranoia::updateTestScenarios(connection, path, parameters);
                else if (method == "PATCH"s)
                    Paranoia::changeSettings(connection, path, parameters);
                else if (method == "DELETE"s)
                    Paranoia::deleteDevice(connection, path);
                else if (method == "POST"s)
                    Paranoia::postBlob(connection, path, parameters);
                else
                    return 1 + mg_send_http_error(connection, 405, "\r\n");
            }
        }

        // route: /cipgroups
        else if (path.find("/cipgroups"s) == 0) {
            path.erase(0, 10);
            if (method == "GET"s)
                ServiceDashboard::getSvcdCips(connection);
            else if (method == "POST"s)
                ServiceDashboard::postSvcdCips(connection, parameters);
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n");
        }

        // route: /reports
        else if (path.find("/reports"s) == 0) {
            path.erase(0, 8);
            if (method == "GET"s)
                ReportManager::getReport(connection, path, parameters);
            else if (method == "POST"s)
                ReportManager::postReport(connection, parameters);
            else if (method == "DELETE"s)
                ReportManager::deleteReport(connection, path);
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n");
        }

        // route: /user
        else if (path.find("/user"s) == 0) {
            path.erase(0, 5); // remove heading "/user"
            if (path.empty()) {
                if (method == "GET"s)
                    User::enumerateUsers(connection, username);
                else if (method == "PUT"s)
                    User::changePassword(connection, username, parameters);
                else if (method == "POST"s)
                    User::addNewUser(connection, username, parameters);
                else
                    return 1 + mg_send_http_error(connection, 405, "\r\n");
            } else {
                path.erase(0, 1);
                if (method == "PUT"s)
                    User::updateAcl(connection, username, path, parameters);
                else if (method == "DELETE"s)
                    User::deleteUser(connection, username, path);
                else
                    return 1 + mg_send_http_error(connection, 405, "\r\n");
            }
        }

        // route: /startuptime
        else if (path == "/startuptime"s) {
            if (method == "GET"s) {
                mg_send_http_ok(connection, "text/plain", startupTime.size());
                mg_write(connection, startupTime.data(), startupTime.size());
                return 1;
            } else
                return 1 + mg_send_http_error(connection, 405, "\r\n");
        }

        // route: /syslog
        else if (path.find("/syslog"s) == 0) {
            path.erase(0, 7); // remove heading "/syslog"
            if (method == "GET"s)
                SubSystems::getSyslog(connection, parameters);
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n");
        }

        // route: /snmptrap
        else if (path.find("/snmptrap"s) == 0) {
            path.erase(0, 9); // remove heading "/snmptrap"
            if (method == "GET"s)
                SubSystems::getSnmpTrap(connection, parameters);
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n");
        }

        // route: /app
        else if (path.find("/app"s) == 0) {
            path.erase(0, 4); // remove "/app"
            if (method == "POST"s)
                SubSystems::postApp(connection, path, parameters);
            else if (method == "GET"s)
                SubSystems::getApp(connection, parameters);
            else if (method == "DELETE"s)
                SubSystems::deleteApp(connection, path);
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
        }

        // route: /importpcap
        else if (path.find("/importpcap"s) == 0) {
            path.erase(0, 11); // remove heading "/importpcap"
            if (method == "GET"s)
                SubSystems::getImportPcap(connection);
            else if (method == "POST"s)
                SubSystems::postImportPcap(connection, path, parameters);
            else if (method == "DELETE"s)
                SubSystems::deleteImportPcap(connection, path);
            else if (method == "PATCH"s)
                SubSystems::patchImportPcap(connection, parameters);
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n");
        }

        // route: /rupdate
        else if (path.find("/rupdate"s) == 0) {
            path.erase(0, 8); // remove heading "/rupdate"
            if (method == "POST"s)
                SubSystems::postRupdate(connection, path, parameters);
            else if (method == "GET"s)
                SubSystems::getRupdate(connection);
            else if (method == "DELETE"s)
                SubSystems::deleteRupdate(connection, path);
            else if (method == "PATCH"s)
                SubSystems::patchRupdate(connection, parameters);
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n");
        }

        // route: /logout
        else if (path == "/logout"s) {
            if (method == "GET"s)
                User::logout(connection);
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n");
        }

        // route: /throttle
        else if (path == "/throttle"s) {
            if (method == "GET"s) {
                std::string throttle = std::to_string(FeedRefinerAbstract::trafficThrottle);
                Civet7::respond200(connection, throttle.data(), throttle.size());
            } else
                return 1 + mg_send_http_error(connection, 405, "\r\n");
        }

        // route: /maxage
        else if (path == "/maxage"s) {
            if (method == "GET"s) {
                std::string maxAge = std::to_string(User::maxAge);
                Civet7::respond200(connection, maxAge.data(), maxAge.size());
            } else
                return 1 + mg_send_http_error(connection, 405, "\r\n");
        }

        // route: /version
        else if (path == "/version"s) {
            if (method == "GET"s)
                SubSystems::getVersion(connection);
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n");
        }

        // route: /whoami
        else if (path == "/whoami"s) {
            username = '"' + username + '"';
            mg_send_http_ok(connection, "application/json", username.size());
            mg_write(connection, username.data(), username.size());
            return 1;
        }

        // route: /detonate
        else if (path == "/detonate"s) {
            if (method == "GET"s)
                exit(3001); // BOOM
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n");
        }

        // route: /update
        else if (path == "/update"s) {
            if (method == "POST"s)
                SubSystems::postUpdate(connection, parameters);
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n");
        }

        // route: /ai
        else if (path.find("/ai"s) == 0) {
            path.erase(0, 3); // remove heading "/ai"
            if(path.find("/lampad-x"s) == 0){
                path.erase(0, 9); // remove heading "/lampad-x"
                if(path.find("/anomaly"s) == 0){
                    if (method == "POST"s){
                        AiLampadxAnomaly::getInstance()->postAiLampadxAnomaly(connection, parameters);
                    }else if (method == "GET"s){
                        path.erase(0, 8); // remove heading "/anomaly"
                        AiLampadxAnomaly::getInstance()->getAiLampadxAnomaly(connection, parameters, path);
                    }else{
                        return 1 + mg_send_http_error(connection, 405, "\r\n");
                    }
                }else if (path.find("/prepared"s) == 0){
                    if (method == "GET"s){
                        AiLampadxAnomaly::getInstance()->getAiLampadxPrepared(connection);
                    }else{
                        return 1 + mg_send_http_error(connection, 405, "\r\n");
                    }
                }else{
                    return 1 + mg_send_http_error(connection, 404, "Query unknown.");
                }
            } else {
                return 1 + mg_send_http_error(connection, 404, "Query unknown.");
            }
        }

        // route: everything else
        else
            return 1 + mg_send_http_error(connection, 404, "Query unknown.");
    }

    return 1;
}

int Civet7::controlSpin7(mg_connection *connection, void *data)
{
    const mg_request_info *request = mg_get_request_info(connection);
    std::string path(request->local_uri + 2), method = (request->request_method);

    // path contains feed name, and request body contains the details
    if (method == "PATCH"s) { // PATCH: used only and foremost(and probably most frequently) for "new codex announcement" from spin4
        // get raw post data
        std::string body;
        body.reserve(1048576);
        char buffer[1048576];
        int dataSize = 0;
        do {
            dataSize = mg_read(connection, buffer, static_cast<size_t>(1048576));
            if (dataSize > 0)
                body.append(buffer, dataSize);
        } while (dataSize > 0); // 0: connection is closed. -1: no more data to read
        if (body.empty())
            logger.oops("PATH doesn't contain body"s);

        // route path
        if (path.find("/c/"s) == 0) { // add new codices from Spin4
            path.erase(0, 3);

            // create new data feed object if it is brand new
            if (!body.empty() && DataFeed::feeds.contains(path) == 0)
                DataFeed::feeds[path] = new DataFeed(path);

            // send data to codex index
            DataFeed::codexIndex->addCodices(path, body);
            mg_send_http_error(connection, 204, "\r\n\r\n");
        }
    } else { // others: follow usual routing
        // prepare for path routing
        for (int i = 0, iEnd = path.size() - 2; i < iEnd; i++)
            while (path.at(i) == '/' && path.at(i + 1) == '/')
                path.erase(i + 1);
        if (path[path.size() - 1] == '/')
            path.pop_back(); // remove tailing '/'

        // get parameters(urlencoded + JSON)
        ankerl::unordered_dense::map<std::string, std::string> parameters = requestParameters(connection, method);

        if (path.find("/paranoia"s) == 0) {
            path.erase(0, 9); // remove header "/paranoia"
            if (method == "PUT") // receive new test results
                Paranoia::storeNewTestResults(connection, path, parameters);
            else if (method == "GET") // report the latest time test result was uploaded & any configuration changes server wants to send(if the device is not registered, send zero in the latest time)
                Paranoia::describeStatus(connection, path, parameters);
            else
                return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
        } else if (path.find("/codices"s) == 0) {
            path.erase(0, 8); // remove header "/codices"
            if (method == "GET"s) {
                try {
                    // check parameters
                    SuperCodex::Conditions conditions;
                    if (parameters.contains("from"s))
                        conditions.from = std::stoi(parameters.at("from"s));
                    if (parameters.contains("to"s))
                        conditions.to = std::stoi(parameters.at("to"s));
                    conditions.dataFeed = parameters.at("feed"s);
                    auto codices = DataFeed::codexIndex->codices(conditions);
                    if (codices.empty()) {
                        mg_send_http_error(connection, 404, "No codices for desginated time period.");
                        return 1;
                    }

                    // build result
                    std::string result;
                    result.reserve(codices.size() * (codices.front().size() + 1));
                    for (const auto &codex : codices)
                        result.append(codex).push_back('\n');

                    // send list of codices in text/plain
                    mg_send_http_ok(connection, "text/plain", result.size());
                    mg_write(connection, result.data(), result.size());
                } catch (std::exception &e) {
                    mg_send_http_error(connection, 400, "Error processing the request. Details: %s", e.what());
                    return 2;
                }
            } else
                return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
        } else if (path.find("/feeds") == 0) {
            path.erase(0, 6); // remove "/feeds"
            if (path.empty()) {
                if (method == "GET"s) {
                    std::string feedList = DataFeed::enumerateFeeds();
                    mg_send_http_ok(connection, "application/json", feedList.size());
                    mg_write(connection, feedList.data(), feedList.size());
                    return 1;
                } else
                    return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
            }
        } else if (path.find("/epoch") == 0) {
            path.erase(0, 6); // remove "/epoch"
            if (path.empty()) {
                if (method == "GET"s) {
                    std::string now(std::to_string(time(nullptr)));
                    mg_send_http_ok(connection, "text/plain", now.size());
                    mg_write(connection, now.data(), now.size());
                    return 1;
                } else
                    return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");
            }
        }

        // route: anything else
        else
            return 1 + mg_send_http_error(connection, 403, "\r\n\r\n");
    }

    return 1;
}

ankerl::unordered_dense::map<std::string, std::string> Civet7::requestParameters(mg_connection *connection, const std::string &method)
{
    // get parameters(urlencoded)
    ankerl::unordered_dense::map<std::string, std::string> parameters;
    mg_form_data_handler formHandler = formHandlerProto;
    formHandler.user_data = &parameters;
    mg_handle_form_request(connection, &formHandler);

    // convert from JSON requests as needed
    auto contentType = mg_get_header(connection, "Content-Type");
    if (contentType) {
        // get raw parameter string
        std::string requestBody;
        if (method == "GET"s)
            requestBody = parameters["jsonrequest"];
        else {
            char readBuffer[1000000];
            int bytesRead = mg_read(connection, readBuffer, 1000000);
            while (bytesRead > 0) {
                requestBody.append(readBuffer, bytesRead);
                bytesRead = mg_read(connection, readBuffer, 1000000);
            }
        }

        if (std::string(contentType).find("application/json"s) == 0) {
            // parse JSON
            if (requestBody[0] == '{') { // parse only if parameter is JSON object
                yyjson_doc *document = yyjson_read(requestBody.data(), requestBody.size(), YYJSON_READ_NOFLAG);
                yyjson_val *root = yyjson_doc_get_root(document);
                yyjson_obj_iter iter = yyjson_obj_iter_with(root);
                for (yyjson_val *key = yyjson_obj_iter_next(&iter); key; key = yyjson_obj_iter_next(&iter)) {
                    yyjson_val *value = yyjson_obj_iter_get_val(key);
                    if (yyjson_is_str(value))
                        parameters[yyjson_get_str(key)] = std::string(yyjson_get_str(value), yyjson_get_len(value));
                    else if (yyjson_is_int(value))
                        parameters[yyjson_get_str(key)] = std::to_string(yyjson_get_int(value));
                    else if (yyjson_is_uint(value))
                        parameters[yyjson_get_str(key)] = std::to_string(yyjson_get_uint(value));
                    else if (yyjson_is_bool(value))
                        parameters[yyjson_get_str(key)] = yyjson_get_bool(value) ? "true"s : "false"s;
                    else if (yyjson_is_arr(value) || yyjson_is_obj(value))
                        parameters[yyjson_get_str(key)] = stringifyyy(value);
                }
                yyjson_doc_free(document);
            }
        } else if (std::string(contentType).find("application/octet-stream"s) == 0)
            parameters["raw"] = std::move(requestBody);
    }

    return parameters;
}

std::string Civet7::stringifyyy(yyjson_val *value)
{
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);

    yyjson_mut_val *valueCopy = yyjson_val_mut_copy(document, value);
    yyjson_mut_doc_set_root(document, valueCopy);

    size_t bufferSize;
    char *buffer = yyjson_mut_write(document, YYJSON_WRITE_NOFLAG, &bufferSize);
    std::string result(buffer, bufferSize);
    free(buffer);
    return result;
}

int Civet7::controlParadox(mg_connection *connection, void *data)
{
    using namespace std::string_literals;
    const mg_request_info *request = mg_get_request_info(connection);

    // prepare for path routing
    std::string path(request->local_uri), method(request->request_method);
    for (int i = 0, iEnd = path.size() - 2; i < iEnd; i++)
        while (path.at(i) == '/' && path.at(i + 1) == '/')
            path.erase(i + 1);
    if (path[path.size() - 1] == '/')
        path.pop_back(); // remove tailing '/'
    path.erase(0, 3); // remove heading "/_/", remaining only MAC address of the unit

    // get parameters(urlencoded + JSON)
    ankerl::unordered_dense::map<std::string, std::string> parameters = requestParameters(connection, method);

    // variable "path" is treated as the MAC address of the device
    if (method == "GET"s)
        Paradox::getLastUpdateTime(connection, path);
    else if (method == "POST"s)
        Paradox::updateTestResults(connection, path, parameters);
    else
        return 1 + mg_send_http_error(connection, 405, "\r\n\r\n");

    return 1;
}

int Civet7::fieldFound(const char *key, const char *fileName, char *path, size_t pathLen, void *userData)
{
    // save everything to parameters
    return MG_FORM_FIELD_STORAGE_GET;
}

int Civet7::getField(const char *key, const char *value, size_t valueLen, void *userData)
{
    ankerl::unordered_dense::map<std::string, std::string> &parameters = *static_cast<ankerl::unordered_dense::map<std::string, std::string> *>(userData);
    parameters[std::string(key)].append(value, valueLen);

    return MG_FORM_FIELD_HANDLE_GET;
}

int Civet7::storeField(const char *path, long long fileSize, void *userData)
{
    // do nothing. :P
    return 1;
}

std::string Civet7::cutPath(std::string &path)
{
    // cut path
    int slash = path.find('/', 1);
    if (slash > 0) {
        std::string result = path.substr(0, slash);
        path.erase(0, slash);
        return result;
    } else
        return ""s;
}

void Civet7::respond200(mg_connection *connection, yyjson_mut_doc *document)
{
    size_t size;
    yyjson_write_err parserError;
    char *resultRaw = yyjson_mut_write_opts(document, YYJSON_WRITE_ALLOW_INVALID_UNICODE, nullptr, &size, &parserError);
    if (size == 0) {
        logger.log("Zero(0) size result. JSON parser error: "s + parserError.msg);
        mg_send_http_error(connection, 204, "\r\n\r\n");
        return;
    }
    respond200(connection, resultRaw, size);
    free(resultRaw);
    yyjson_mut_doc_free(document);
}

void Civet7::respond200(mg_connection *connection, const nlohmann::json &body)
{
    std::string dump = body.dump();
    respond200(connection, dump.data(), dump.size());
}

void Civet7::respond200(mg_connection *connection, const char *data, const size_t size, const std::string &mimeType)
{
    std::string headersToAppend(mimeType);
    const char *cookieHeader = mg_get_header(connection, "Cookie");
    if (cookieHeader) {
        // obtain current cookie and extend its life span
        char buffer[256];
        int bufferSize = mg_get_cookie(cookieHeader, "Civet7Token", buffer, 256);
        if (bufferSize > 1) {
            // build session data and send HTTP 200
            headersToAppend.append("\r\nSet-Cookie: Civet7Token="s).append(buffer, bufferSize).append(User::sessionSuffix);
        }
    }

    // return
    if (size == 0) {
        auto result = mg_send_http_ok(connection, headersToAppend.data(), -1); // empty body: initiate chunked mode
        if (result < 0)
            logger.oops("Failed to respond with HTTP 200 OK."s);
    } else {
        mg_send_http_ok(connection, headersToAppend.data(), size);
        mg_write(connection, data, size);
    }
}

void Civet7::getValues(mg_connection *connection)
{
    // initialize JSON objects
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *root = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, root);

    kvsMutex.lock();
    if (mg_get_request_info(connection)->query_string) { // filter selected pairs only
        std::string queryString(mg_get_request_info(connection)->query_string);
        for (size_t percentIndex = queryString.find('%'); percentIndex != std::string::npos; percentIndex = queryString.find('%', percentIndex)) // unescape percent encoding
            queryString.replace(percentIndex, 3, 1, static_cast<char>(std::stoi(queryString.substr(percentIndex + 1, 2), nullptr, 16)));
        std::istringstream lineReader(queryString);
        for (std::string item; std::getline(lineReader, item, ',');) {
            if (kvs.contains(item)) {
                yyjson_mut_val *key, *value;
                key = yyjson_mut_strncpy(document, item.data(), item.size());
                const auto &valueString = kvs[item];
                value = yyjson_mut_strn(document, valueString.data(), valueString.size());
                yyjson_mut_obj_add(root, key, value);
            }
        }
    } else { // send everything
        for (const auto &pair : kvs) {
            yyjson_mut_val *key, *value;
            key = yyjson_mut_strn(document, pair.first.data(), pair.first.size());
            value = yyjson_mut_strn(document, pair.second.data(), pair.second.size());
            yyjson_mut_obj_add(root, key, value);
        }
    }
    kvsMutex.unlock();

    // generate stringified JSON document
    size_t bufferSize;
    char *buffer = yyjson_mut_write(document, YYJSON_WRITE_NOFLAG, &bufferSize);

    // send result and free document
    mg_send_http_ok(connection, "application/json", bufferSize);
    mg_write(connection, buffer, bufferSize);
    free(buffer);
    yyjson_mut_doc_free(document);
}

void Civet7::setValues(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // write down parameters
    kvsMutex.lock();
    for (const auto &parameter : parameters)
        kvs[parameter.first] = parameter.second;
    saveValues();
    kvsMutex.unlock();

    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void Civet7::deleteValues(mg_connection *connection, const std::string &currentUser)
{
    // check if the query is empty
    if (mg_get_request_info(connection)->query_string == nullptr) {
        mg_send_http_error(connection, 403, "Query string is empty. Rejecting request.");
        return;
    }

    // prepare to get query
    std::string queryString(mg_get_request_info(connection)->query_string);
    std::istringstream lineReader(queryString);

    // write down result
    kvsMutex.lock();
    for (std::string item; std::getline(lineReader, item, ',');)
        if (kvs.contains(item))
            kvs.erase(item);
    saveValues();
    kvsMutex.unlock();

    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void Civet7::saveValues()
{
    // initialize JSON objects
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *root = yyjson_mut_obj(document);
    yyjson_mut_doc_set_root(document, root);

    for (const auto &pair : kvs) {
        yyjson_mut_val *key, *value;
        key = yyjson_mut_strncpy(document, pair.first.data(), pair.first.size());
        value = yyjson_mut_strn(document, pair.second.data(), pair.second.size());
        yyjson_mut_obj_add(root, key, value);
    }

    // write down KVS JSON file and free memory
    yyjson_mut_write_file(kvsFilePath.data(), document, YYJSON_WRITE_NOFLAG, nullptr, nullptr);
    yyjson_mut_doc_free(document);
}
