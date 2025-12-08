#include "ailampadxanomaly.h"
#include "civet7.hpp"
#include "../loghandler.h"

#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <regex>

using namespace std::string_literals;

Logger AiLampadxAnomaly::logger("AiLampadxAnomaly"s);

AiLampadxAnomaly* AiLampadxAnomaly::getInstance()
{
    static AiLampadxAnomaly* instance = nullptr;
    if(instance == nullptr){
        instance = new AiLampadxAnomaly();
    }
    return instance;
}

void AiLampadxAnomaly::postAiLampadxAnomaly(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    std::lock_guard<std::mutex> lock(ai_data_mutex);

    //[예외처리]
    std::vector<std::string> required_keys = {
        "device_mac", "device_alias", "device_ip", "device_responsive", "scenario_name", "threshold", "time_range", "values"
    };
    if((this->validateParameters(connection, required_keys, parameters)) == false) return;

    nlohmann::json jsonBody;
    // 문자열로 유지해야 하는 필드 목록
    const std::vector<std::string> string_fields = {"scenario_name", "device_mac", "device_alias", "device_ip"};
    for (const auto& thing : parameters) {
        const std::string& key = thing.first;
        const std::string& value = thing.second;
        bool is_string_fields = std::find(string_fields.begin(), string_fields.end(), key) != string_fields.end();
        if(is_string_fields == true){
            jsonBody[key] = value; 
        } else if (nlohmann::json::accept(value)) {
            jsonBody[key] = nlohmann::json::parse(value); // "111" = 111로 파싱, "/"111/"" = "111"로 파싱
        } else {
            jsonBody[key] = value;
        }
    }
    std::string err_msg;
    if (!this->validateScenarioJson(jsonBody, err_msg)) {
        respondJson(connection, 400, "INVALID_JSON", err_msg);
        return;
    }

    //2) json 객체를 .tmp로 (/Lampad/lampadx_anomaly_detection/<MAC>/<scenario>.json)에 임시 저장, 임시 파일에 먼저 써놓았다가 교체 진행.
    std::string mac_folder = jsonBody["device_mac"].get<std::string>();
    for (char &c : mac_folder){
        if (c >= 'a' && c <= 'z') {
            c = c - 32;
        }
        if (c==':' || c==' ' || c=='/' || c=='-'){
             c = '_';
        }
    }
    jsonBody["device_mac"] = mac_folder;
    std::string scenario = jsonBody["scenario_name"].get<std::string>();
    std::error_code ec;
    std::filesystem::path dir = std::filesystem::path("/Lampad") / "lampadx_anomaly_detection" / mac_folder;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        this->respondJson(connection, 500, "MKDIR_FAILED", "서버에서 내부적으로 오류가 발생했습니다.");
        return;
    }
    std::filesystem::path out_path = dir / (scenario + ".json");
    bool existed_before = std::filesystem::exists(out_path, ec);
    const std::string json_text = jsonBody.dump(2);
    std::filesystem::path tmp_path = out_path; 
    tmp_path += ".tmp";
    {
        std::ofstream ofs(tmp_path, std::ios::binary);
        if (!ofs) {
            this->respondJson(connection, 500, "OPEN_FAILED", "서버에서 내부적으로 오류가 발생했습니다.");
            return;
        }
        ofs.write(json_text.data(), static_cast<std::streamsize>(json_text.size()));
        ofs.flush();
        if (!ofs.good()) {
            ofs.close();
            std::filesystem::remove(tmp_path);
            this->respondJson(connection, 500, "WRITE_FAILED", "서버에서 내부적으로 오류가 발생했습니다.");
            return;
        }
    }
    std::filesystem::rename(tmp_path, out_path, ec);
    if (ec) {
        std::filesystem::remove(out_path, ec); 
        ec.clear();
        std::filesystem::rename(tmp_path, out_path, ec);
        if (ec) {
            std::ifstream ifs(tmp_path, std::ios::binary);
            std::ofstream ofs(out_path, std::ios::binary | std::ios::trunc);
            ofs << ifs.rdbuf();
            ifs.close(); 
            ofs.close();
            std::filesystem::remove(tmp_path);
            if (!std::filesystem::exists(out_path)) {
                this->respondJson(connection, 500, "REPLACE_FAILED", "서버에서 내부적으로 오류가 발생했습니다.");
                return;
            }
        }
    }

    if(this->setPreparedList(connection) == false){
        return;
    };

    //성공 메시지 반환.
    this->respondJson(connection, 200, "null", existed_before ? "기존 파일을 교체했습니다." : "새 파일을 생성했습니다.");
}

struct AiLampadxAnomaly::X_device_info{
    struct Prepared_scenarios{
        bool ai_ready;
        std::string name;
    };
    std::string device_alias;
    std::string device_ip;
    bool device_responsive;
    std::vector<Prepared_scenarios> prepared_scenarios;
};

bool AiLampadxAnomaly::setPreparedList(mg_connection* connection)
{
    std::lock_guard<std::mutex> lock(ai_data_prepared_mutex);

    std::filesystem::path root = "/Lampad/lampadx_anomaly_detection";
    const std::string output_name = "prepared_list.json";

    // 3) "YYYY-MM-DDTHH:MM:SS" → epoch(sec), 시간대 보정 없이 그대로 계산
    auto changeToEpochtime = [](const std::string& text) -> long long {
        // 형식 보장 가정(앞 19자 사용)
        int Y = std::stoi(text.substr(0, 4));
        int m = std::stoi(text.substr(5, 2));
        int d = std::stoi(text.substr(8, 2));
        int H = std::stoi(text.substr(11, 2));
        int M = std::stoi(text.substr(14, 2));
        int S = std::stoi(text.substr(17, 2));

        std::tm t = {};
        t.tm_year = Y - 1900;  // 1900 기준
        t.tm_mon  = m - 1;     // 0-11
        t.tm_mday = d;         // 1-31
        t.tm_hour = H;         // 0-23
        t.tm_min  = M;         // 0-59
        t.tm_sec  = S;         // 0-60

        // 문자열을 '그대로' 초로 변환 (UTC로 간주, 로컬 보정 없음)
        #if defined(_WIN32)
            std::time_t tt = _mkgmtime(&t);   // Windows
        #else
            std::time_t tt = timegm(&t);      // POSIX
        #endif
        return static_cast<long long>(tt);
    };
    const long long SEVEN_DAYS = 7LL * 24 * 60 * 60;

    std::unordered_map<std::string, AiLampadxAnomaly::X_device_info> grouped;
    // 재귀로 폴더 훑으면서 *.json 처리
    std::error_code ec;
    for (std::filesystem::recursive_directory_iterator it(root, ec); it != std::filesystem::recursive_directory_iterator(); ++it) {
        if (ec)
            break;
        const std::filesystem::directory_entry& entry = *it;
        if (!entry.is_regular_file(ec))
            continue;

        const std::filesystem::path& p = entry.path();
        const std::string file_name = p.filename().string();
        // prepared_list.json 제외, .json만
        if (file_name == output_name)
            continue;
        if (p.extension().string() != ".json")
            continue;

        const std::string mac = p.parent_path().filename().string();
        const std::string scenario_name = p.stem().string();
        
        nlohmann::json doc;
        std::ifstream ifs(p, std::ios::binary);
        try {
            doc = nlohmann::json::parse(ifs);
        } catch (const std::exception& e) {
            logger.log("Non-json file: mac=" + mac + ", file=" + file_name + ", path=" + p.string() + ", error=" + std::string(e.what()));
            continue;
        }

        std::string err_msg;
        if (!this->validateScenarioJson(doc, err_msg)) {
            logger.log("Non-json file: mac=" + mac + ", file=" + file_name + ", path=" + p.string() + " is invalid json");
            continue;
        }
        
        const nlohmann::json& time_range = doc["time_range"];
        long long begin_epoch = changeToEpochtime(time_range["start"].get<std::string>());
        long long end_epoch = changeToEpochtime(time_range["end"].get<std::string>());
        bool aiReady = (end_epoch - begin_epoch) >= SEVEN_DAYS;

        auto& info = grouped[mac];
        info.device_alias = doc["device_alias"].get<std::string>();
        info.device_ip = doc["device_ip"].get<std::string>();
        info.device_responsive = doc["device_responsive"].get<bool>();

        // 시나리오 push
        AiLampadxAnomaly::X_device_info::Prepared_scenarios ps;
        ps.ai_ready = aiReady;
        ps.name = scenario_name;
        info.prepared_scenarios.push_back(std::move(ps));
    }

    // 최종 결과 JSON 만들기
    nlohmann::json result = nlohmann::json::array();
    for (auto& kv : grouped) {
        const std::string& macKey = kv.first;
        const auto& info = kv.second;

        nlohmann::json scenarios = nlohmann::json::array();
        for (const auto& s : info.prepared_scenarios) {
            scenarios.push_back({
                {"name", s.name},
                {"ai_ready", s.ai_ready}
            });
        }

        result.push_back({
            {"device_mac", macKey},
            {"device_alias", info.device_alias},
            {"device_ip", info.device_ip},
            {"device_responsive", info.device_responsive},
            {"scenarios", scenarios}
        });
    }

    // prepared_list.json을 .tmp에 쓰고 rename으로 교체(원자성)
    std::filesystem::path out_path = root / output_name;
    const std::string json_text = result.dump(2);
    std::filesystem::path tmp_path = out_path;
    tmp_path += ".tmp";
    {
        std::ofstream ofs(tmp_path, std::ios::binary);
        if (!ofs) {
            this->respondJson(connection, 500, "OPEN_FAILED", "서버에서 내부적으로 오류가 발생했습니다.");
            return false;
        }
        ofs.write(json_text.data(), static_cast<std::streamsize>(json_text.size()));
        ofs.flush();
        if (!ofs.good()) {
            ofs.close();
            std::filesystem::remove(tmp_path);
            this->respondJson(connection, 500, "WRITE_FAILED", "서버에서 내부적으로 오류가 발생했습니다.");
            return false;
        }
    }

    std::filesystem::rename(tmp_path, out_path, ec);
    if (ec) {
        std::filesystem::remove(out_path, ec);
        ec.clear();
        std::filesystem::rename(tmp_path, out_path, ec);
        if (ec) {
            std::ifstream ifs(tmp_path, std::ios::binary);
            std::ofstream ofs(out_path, std::ios::binary | std::ios::trunc);
            ofs << ifs.rdbuf();
            ifs.close();
            ofs.close();
            std::filesystem::remove(tmp_path);
            if (!std::filesystem::exists(out_path)) {
                this->respondJson(connection, 500, "REPLACE_FAILED", "서버에서 내부적으로 오류가 발생했습니다.");
                return false;
            }
        }
    }
    return true; // 성공
}

void AiLampadxAnomaly::getAiLampadxPrepared(mg_connection *connection)
{
    std::lock_guard<std::mutex> lock(ai_data_prepared_mutex);

    std::filesystem::path json_path  = "/Lampad/lampadx_anomaly_detection/prepared_list.json";
    // 1) 존재 여부만 확인해서 없으면 404
    std::error_code ec;
    if (!std::filesystem::exists(json_path, ec) || ec) {
        this->respondJson(connection, 404, "NOT_FOUND", "요청한 파일이 존재하지 않습니다.");
        return;
    }

    // 2) 파일 읽어서 그대로 content에 반환
    std::ifstream ifs(json_path, std::ios::binary);
    if (!ifs) {
        this->respondJson(connection, 500, "OPEN_FAILED", "서버에서 내부적으로 오류가 발생했습니다.");
        return;
    }
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();

    // 3) 저장된 JSON 파싱
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(content);
    } catch (...) {
        this->respondJson(connection, 500, "CORRUPTED_JSON", "서버에서 내부적으로 오류가 발생했습니다.");
        return;
    }

    this->respondJson(connection, 200, doc.dump(2));
}

void AiLampadxAnomaly::getAiLampadxAnomaly(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters, std::string &path)
{
    std::lock_guard<std::mutex> lock(ai_data_mutex);

    //[예외처리]
    std::vector<std::string> required_keys = {
        "device_mac", "scenario_name"
    };
    if((this->validateParameters(connection, required_keys, parameters)) == false) return;

    //parameters 값 추출하고 device_mac 조금 손봐주기
    std::string device_mac = (parameters.find("device_mac"))->second;
    std::string scenario_name = (parameters.find("scenario_name"))->second;
    for (char &c : device_mac){
        //소문자를 대문자로 변경
        if (c >= 'a' && c <= 'z') {
            c = c - 32;
        }
        //device_mac에서 쓸법한 문자를 "_"로 치환
        if (c==':' || c==' ' || c=='/' || c=='-'){
             c = '_';
        }
    }

    std::filesystem::path dir  = std::filesystem::path("/Lampad") / "lampadx_anomaly_detection" / device_mac;
    std::filesystem::path json_path = dir / (scenario_name + ".json");
    // 4) 존재 여부만 확인해서 없으면 404
    std::error_code ec;
    if (!std::filesystem::exists(json_path, ec) || ec) {
        this->respondJson(connection, 404, "NOT_FOUND", "요청한 파일이 존재하지 않습니다.");
        return;
    }

    // 5) 파일 읽어서 그대로 content에 반환
    std::ifstream ifs(json_path, std::ios::binary);
    if (!ifs) {
        this->respondJson(connection, 500, "OPEN_FAILED", "서버에서 내부적으로 오류가 발생했습니다.");
        return;
    }
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();

    // 6) 저장된 JSON 파싱 (둘 다 필요한 기반)
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(content);
    } catch (...) {
        this->respondJson(connection, 500, "CORRUPTED_JSON", "서버에서 내부적으로 오류가 발생했습니다.");
        return;
    }
    std::string err_msg;
    if (!this->validateScenarioJson(doc, err_msg)) {
        respondJson(connection, 500, "SCHEMA_MISMATCH", "서버가 합의된 응답 스키마를 생성하지 못했습니다.");
        return;
    }

    // 7-1) path에 threshold가 있으면 threshold만 꺼내어 지정한 형태로 응답
    if (path.find("/threshold"s) == 0) {
        nlohmann::json resp;
        // device_mac / scenario_name은 요청값 기준으로 넣어줌
        resp["device_mac"] = device_mac;
        resp["scenario_name"] = scenario_name;
        if (doc.contains("threshold") && doc["threshold"].is_object()) {
            resp["threshold"] = doc["threshold"];
        } else {
            // threshold가 없으면 빈 객체로
            resp["threshold"] = nlohmann::json::object();
        }
        this->respondJson(connection, 200, resp.dump(2));
        return;
    }

    // 7-2) onlythreshold=false → 파일 전체 그대로 반환
    this->respondJson(connection, 200, doc.dump(2));
}

bool AiLampadxAnomaly::validateScenarioJson(const nlohmann::json& doc, std::string& err_msg)
{
    // 2. 필드별 타입 검사
    if(!doc["device_mac"].is_string()){
        err_msg = "device_mac의 타입은 string 이어야 합니다.";
        return false;
    }
    if(!doc["device_alias"].is_string()){
        err_msg = "device_alias의 타입은 string 이어야 합니다.";
        return false;
    }
    if(!doc["device_ip"].is_string()){
        err_msg = "device_ip의 타입은 string 이어야 합니다.";
        return false;
    }
    if(!doc["device_responsive"].is_boolean()){
        err_msg = "device_responsive의 타입은 bool 이어야 합니다.";
        return false;
    }
    if(!doc["scenario_name"].is_string()){
        err_msg = "scenario_name의 타입은 string 이어야 합니다.";
        return false;
    }
    if (!doc["threshold"].is_object()) {
        err_msg = "threshold의 타입은 object이어야 합니다.";
        return false;
    } else {
        const auto& threshold = doc["threshold"];
        if (!threshold.contains("major_ns")) {
            err_msg = "필수 키 'threshold.major_ns'값이 존재하지 않습니다.";
            return false;
        } 
        else if (!threshold["major_ns"].is_number()) {
            err_msg = "threshold.major_ns의 타입은 number이어야 합니다.";
            return false;
        }
        if (!threshold.contains("minor_ns")) {
            err_msg = "필수 키 'threshold.minor_ns'값이 존재하지 않습니다.";
            return false;
        }
        else if (!threshold["minor_ns"].is_number()) {
            err_msg = "threshold.minor_ns의 타입은 number이어야 합니다.";
            return false;
        }
        if (threshold["major_ns"].get<long long>() < threshold["minor_ns"].get<long long>()) {
            err_msg = "threshold.major_ns는 threshold.minor_ns보다 크거나 같아야 합니다.";
            return false;
        }
    }
    if (!doc["time_range"].is_object()) {
        err_msg = "time_range의 타입은 object이어야 합니다.";
        return false;
    } else {
        const auto& time_range = doc["time_range"];
        if (!time_range.contains("start")) {
            err_msg = "필수 키 'time_range.start'값이 존재하지 않습니다.";
            return false;
        }
        else if (!time_range["start"].is_string()) {
            err_msg = "time_range.start의 타입은 string이어야 합니다.";
            return false;
        }
        if (!time_range.contains("end")) {
            err_msg = "필수 키 'time_range.end'값이 존재하지 않습니다.";
            return false;
        }
        else if (!time_range["end"].is_string()) {
            err_msg = "time_range.end의 타입은 string이어야 합니다.";
            return false;
        }
        // ISO-8601 간단 검증용 정규식
        static const std::regex iso8601(R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$)");
        if (!std::regex_match(time_range["start"].get<std::string>(), iso8601)) {
            err_msg = "time_range.start가 ISO-8601 format이 아닙니다.";
            return false;
        }
        else if (!std::regex_match(time_range["end"].get<std::string>(), iso8601)) {
            err_msg = "time_range.end가 ISO-8601 format이 아닙니다.";
            return false;
        }
    }
    if (!doc["values"].is_array()) {
        err_msg = "values의 타입은 array이어야 합니다.";
        return false;
    }
    const auto& values = doc["values"];
    for (size_t i = 0; i < values.size(); ++i) {
        const auto& value = values[i];
        if (!value.contains("timestamp")) {
            err_msg = "values " + std::to_string(i) + "번 째에 필수 키 'timestamp' 값이 존재하지 않습니다.";
            return false;
        }
        else if(!value["timestamp"].is_string()){
            err_msg = "values " + std::to_string(i) + "번 째에 timestamp의 타입은 string이어야 합니다.";
            return false;
        }
        if (!value.contains("rtt_ns")) {
            err_msg = "values " + std::to_string(i) + "번 째에 필수 키 'rtt_ns' 값이 존재하지 않습니다.";
            return false;
        }
        else if (!value["rtt_ns"].is_number()) {
            err_msg = "values " + std::to_string(i) + "번 째에 rtt_ns의 타입은 number이어야 합니다.";
            return false;
        }
        if (!value.contains("status")) {
            err_msg = "values " + std::to_string(i) + "번 째에 필수 키 'status' 값이 존재하지 않습니다.";
            return false;
        }
        else if (!value["status"].is_array()) {
            err_msg = "values " + std::to_string(i) + "번 째에 status의 타입은 array이어야 합니다.";
            return false;
        }
        for (size_t j = 0; j < value["status"].size(); ++j) {
            if (!value["status"][j].is_string()) {
                err_msg = "values " + std::to_string(i) + "번 째에 status의" + std::to_string(j) + "번 째 데이터의 타입은 string이어야 합니다.";
                return false;
            }
        }
    }

    // 3. MAC, IP 형식 간단 검증
    static const std::regex mac_pattern(R"(^([0-9A-Fa-f]{2}([ :/_-])){5}[0-9A-Fa-f]{2}$)");
    if (!std::regex_match(doc["device_mac"].get<std::string>(), mac_pattern)) {
        err_msg = "device_mac은 ':', ' ', '/', '-', '_' 중 하나의 구분자로 구성된 6쌍 MAC이어야 합니다. (예: 58_11_22_E2_CF_C3)";
        return false;
    }

    static const std::regex ip_pattern(R"(^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$)");
    if (!std::regex_match(doc["device_ip"].get<std::string>(), ip_pattern)) {
        err_msg = "device_ip의 형태가 올바르지 않습니다.";
        return false;
    }

    // 모두 통과
    return true;
}

bool AiLampadxAnomaly::validateParameters(mg_connection *connection, const std::vector<std::string>& required_keys ,const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    //1) parameters 비었으면 JSON 포맷 아님
    if (parameters.empty()) {
        this->respondJson(connection, 400, "INVALID_FORMAT", "지원하지 않는 포맷이거나, 파라미터가 없습니다.");
        return false;
    }
    //2) 필수 키 검사
    if (!required_keys.empty()) {
        for (const std::string& required_key : required_keys) {
            if (parameters.find(required_key) == parameters.end()) {
                this->respondJson(connection, 400, "NO_REQUIRED_KEY", "필수 키 '" + required_key + "'값이 존재하지 않습니다.");
                return false;
            }
        }
    }
    return true;
}

void AiLampadxAnomaly::respondJson(mg_connection* connection, const int& status_code, const std::string& error_code, const std::string& message)
{
    // 1) HTTP reason phrase 매핑
    std::string reason = "OK";
    switch (status_code) {
        case 200: reason = "OK"; break;
        case 400: reason = "Bad Request"; break;
        case 404: reason = "Not Found"; break;
        case 500: reason = "Internal Server Error"; break;
        default:  reason = "OK"; break;
    }

    // 2) 공통 JSON 바디 구성 및 response body의 text 구성
    nlohmann::json j;
    std::string status_msg = "error";
    if(status_code>=200 && status_code < 300){
        status_msg = "ok";
    }
    j = {
            {"status", status_msg},
            {"error_code", error_code},
            {"message", message}
        };
    const std::string body = j.dump(2);

    // 3) 송신
    mg_printf(connection,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status_code, reason.c_str(), body.size(), body.c_str());
}

void AiLampadxAnomaly::respondJson(mg_connection* connection, const int& status_code, const std::string& body)
{
    mg_printf(connection,
        "HTTP/1.1 %d OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status_code, body.size(), body.c_str());
}