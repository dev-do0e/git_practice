#ifndef AILAMPADXANOMALY_H
#define AILAMPADXANOMALY_H

#include <civetweb.h>
#include <string>
#include <ankerl/unordered_dense.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <vector>
#include <string>

#include "../loghandler.h"

class AiLampadxAnomaly{
    
public:
    //Singletone
    static AiLampadxAnomaly* getInstance();
    
    //API
    void postAiLampadxAnomaly(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
    void getAiLampadxAnomaly(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters, std::string &path);
    void getAiLampadxPrepared(mg_connection *connection);

private:
    static Logger logger;
    static AiLampadxAnomaly* instance;

    std::mutex ai_data_mutex; //lampadx_anomaly_detection/<MAC>/scenario_name.json 관련 mutex
    std::mutex ai_data_prepared_mutex; //lampadx_anomaly_detection/prepared_list.json 관련 mutex
    
    struct X_device_info;
    bool setPreparedList(mg_connection *connection);

    bool validateScenarioJson(const nlohmann::json& doc, std::string& err_msg);
    bool validateParameters(mg_connection *connection, const std::vector<std::string>& required_keys, const ankerl::unordered_dense::map<std::string, std::string> &parameters);

    //응답 return
    void respondJson(mg_connection* connection, const int& status, const std::string& error_code, const std::string& message);
    void respondJson(mg_connection* connection, const int& status, const std::string& body);
};

#endif //AILAMPADXANOMALY_H
