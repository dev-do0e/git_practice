#include "user.h"

#include "../license.h"
#include "civetweb.h"
#include "datafeed.h"
#include <mutex>
#include <sstream>
#include <fstream>
#include <string>
#include <yyjson.h>
    
#include "civet7.hpp"

// extern variables
std::string User::sessionSeed, User::sessionSuffix;
nlohmann::json User::users;
ankerl::unordered_dense::map<std::string, SuperCodex::IpFilter> User::acls;
std::shared_mutex User::usersMutex;
Logger User::logger("User");
int User::maxAge = 0; // session cookie

using namespace std::string_literals;

void User::initialize(const std::string &sessionSeed, const int tokenTimeout)
{
    // set suffix for cookie for login session management
    maxAge = tokenTimeout;
    User::sessionSeed = sessionSeed;
    sessionSuffix.append("; Path=/; Max-Age="s).append(std::to_string(tokenTimeout)).append("; SameSite=Lax");

    // read users.json
    logger.log("Load user authentication"s);
    std::unique_lock locker(usersMutex);
    bool usersJsonLoaded = false;
    try {
        users = nlohmann::json::parse(std::ifstream("users.json"s));
        usersJsonLoaded = true;
    } catch (std::exception &e) {
        logger.oops("Failed to load user authentication. Details: "s + e.what());
    } catch (...) {
        logger.oops("Failed to load user authentication. Details unknown"s);
    }

    // if failed to load users.json, load from backup
    if (!usersJsonLoaded)
        try {
            logger.log("Recovering authentication information from backup copy"s);
            users = nlohmann::json::parse(std::ifstream("users.json.backup"s));
            std::filesystem::copy_file("users.json.backup", "users.json", std::filesystem::copy_options::overwrite_existing);
            usersJsonLoaded = true;
        } catch (std::exception &e) {
            logger.oops("Failed to load backup. Details: "s + e.what());
        } catch (...) {
            logger.oops("Failed to load backup. Details unknown"s);
        }

    // if everything fails, just revert back to the factory default
    if (!usersJsonLoaded) {
        logger.oops("Failed to load authentcation from both original and backup. Falling back to factory default"s);
        users = nlohmann::json::object();
        auto &lampad = users["lampad"];
        const std::string hashedPassword = spin7PasswordHashed("lampad"s, "lampad"s);
        lampad["password"s] = hashedPassword;
        lampad["role"s] = spin7RoleHashed("lampad"s, hashedPassword, '0');
        saveUsers();
    }

    // make a backup for current users.json, which should be at least "readable"
    std::filesystem::copy_file("users.json"s, "users.json.backup", std::filesystem::copy_options::overwrite_existing);

    // unpack a few stuff
    for (auto &item : users.items()) {
        unpackAcl(item.key()); // ACL IPs
        if (spin7RoleHashed(item.key(), item.value()["password"], '0') == item.value()["role"])
            item.value()["roleunpacked"] = 0;
        else
            item.value()["roleunpacked"] = 1;

        item.value()["sessionid"] = sessionIdCalculated(item.key());
    }
}

void User::login(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    const std::string &username = parameters.at("username"), &password = parameters.at("password"), sessionId = sessionIdCalculated(username);
    auto request = mg_get_request_info(connection);

    // check existence of username
    std::unique_lock locker(usersMutex);
    if (!users.contains(username)) {
        logger.oops("Invalid username: "s + request->local_uri + " by "s + username + " from "s + request->remote_addr + ':' + std::to_string(request->remote_port));
        mg_send_http_error(connection, 403, "username or password is incorrect");
        return;
    }
    auto &user = users[username];

    // check lockdown
    if (user["failurecount"s] >= 5) {
        if (user["lastlogintrial"].get<int>() < time(nullptr) - 300)
            user["failurecount"s] = 0; // more than 5 minutes passed since lockdown.
        else {
            int fiveMinutes = user["lastlogintrial"].get<int>() + 300;
            mg_send_http_error(connection, 403, "user under lockdown. Time left: %lli seconds", fiveMinutes - time(nullptr));
            return;
        }
    }

    // check password
    user["lastlogintrial"] = time(nullptr);
    if (spin7PasswordHashed(username, password) == user["password"].get<std::string>()) {
        // check ACL
        const std::string remoteAddress(request->remote_addr);
        const auto &targetAcl = acls[username];
        if (!targetAcl.isEmpty && !targetAcl.contains(SuperCodex::computerReadableIp(remoteAddress))) {
            logger.oops("Login against ACL: "s + username + " from " + remoteAddress);
            mg_send_http_error(connection, 403, "Login attempt from disallowed IP");
            return;
        }

        // record login information(IP and timestamp)
        user["lastloginip"] = remoteAddress;
        user["failurecount"s] = 0; // reset counter
        logger.log("Login confirmed: "s + request->local_uri + " by " + username + " from " + remoteAddress + ':' + std::to_string(request->remote_port));

        // respond
        std::string cookieHeader("application/json\r\nSet-Cookie: Civet7Token="s.append(sessionId).append(sessionSuffix).append("\r\nCivet7Token: ").append(sessionId)), body(DataFeed::enumerateFeeds());
        mg_send_http_ok(connection, cookieHeader.data(), body.size());
        mg_write(connection, body.data(), body.size());
    } else { // password is incorrect
        logger.oops("Invalid password: "s + request->local_uri + " by "s + username + " from "s + request->remote_addr + ':' + std::to_string(request->remote_port));
        if (user.contains("failurecount"s) && user["failurecount"s].is_number())
            user["failurecount"s] = user["failurecount"s].get<int>() + 1;
        else
            user["failurecount"s] = 1;
        logger.log("Failure count: "s + std::to_string(user["failurecount"].get<int>()));
        mg_send_http_error(connection, 403, "username or password is incorrect");
    }

    // write down last login information to disk
    saveUsers();
}

void User::enumerateUsers(mg_connection *connection, const std::string &username)
{
    // initialize JSON objects
    yyjson_mut_doc *document = yyjson_mut_doc_new(nullptr);
    yyjson_mut_val *root = yyjson_mut_arr(document);
    yyjson_mut_doc_set_root(document, root);

    // enumerate per username
    std::string temp;
    std::string usernameWithoutTag = username.substr(0, username.find('\t'));
    std::shared_lock locker(usersMutex);
    switch (users.at(usernameWithoutTag).at("roleunpacked"s).get<int>()) {
    case 0:
        for (const auto &item : users.items()) { // per each user
            // add object to root array
            yyjson_mut_val *object = yyjson_mut_obj(document);
            yyjson_mut_arr_add_val(root, object);

            // push information
            const auto &description = item.value();
            yyjson_mut_obj_add_strncpy(document, object, "username", item.key().data(), item.key().size());
            yyjson_mut_obj_add_int(document, object, "role", description["roleunpacked"s].get<int>());
            if (description.contains("lastloginip")) { // has last login
                temp = description.at("lastloginip"s);
                yyjson_mut_obj_add_strncpy(document, object, "lastloginfrom", temp.data(), temp.size());
                temp = FeedRefinerAbstract::epochToIsoDate(description.at("lastlogintrial"s), "%Y-%m-%d %H:%M:%S");
                yyjson_mut_obj_add_strncpy(document, object, "lastloginat", temp.data(), temp.size());
            }
            if (description.contains("acl"s) && description.is_string()) {
                temp = description.at("acl"s);
                yyjson_mut_obj_add_strncpy(document, object, "acl", temp.data(), temp.size());
            }
        }
        break;
    default: {
        // add object to root array
        yyjson_mut_val *object = yyjson_mut_obj(document);
        yyjson_mut_arr_add_val(root, object);

        // push information
        const auto &description = users.at(username);
        yyjson_mut_obj_add_strncpy(document, object, "username", username.data(), username.size());
        yyjson_mut_obj_add_int(document, object, "role", description["roleunpacked"s].get<int>());
        if (description.contains("lastloginip")) { // has last login
            temp = description.at("lastloginip"s);
            yyjson_mut_obj_add_strncpy(document, object, "lastloginfrom", temp.data(), temp.size());
            temp = FeedRefinerAbstract::epochToIsoDate(description.at("lastlogintrial"s), "%Y-%m-%d %H:%M:%S");
            yyjson_mut_obj_add_strncpy(document, object, "lastloginat", temp.data(), temp.size());
        }
        if (description.contains("acl"s)) {
            temp = description.at("acl"s);
            yyjson_mut_obj_add_strncpy(document, object, "acl", temp.data(), temp.size());
        }
    } break;
    }

    // return result to the client and free working memory
    size_t bufferSize;
    char *buffer = yyjson_mut_write(document, YYJSON_WRITE_NOFLAG, &bufferSize);
    Civet7::respond200(connection, buffer, bufferSize);
    free(buffer);
    yyjson_mut_doc_free(document);
}

void User::addNewUser(mg_connection *connection, const std::string &currentUser, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    std::unique_lock locker(usersMutex);

    // check if current user is super user
    if (users[currentUser]["roleunpacked"] != 0) {
        mg_send_http_error(connection, 403, "Requested action is not allowed.");
        return;
    }

    // check existence of parameters
    if (!parameters.contains("id") || !parameters.contains("pw") || !parameters.contains("role")) {
        mg_send_http_error(connection, 400, "One or more required parameters(id, pw, role) are missing.");
        return;
    }

    // check username
    std::string newUsername = parameters.at("id");
    if (newUsername.empty()) {
        mg_send_http_error(connection, 403, "Username is empty.");
        return;
    }
    for (const char &ch : newUsername)
        if (!isalnum(ch)) {
            mg_send_http_error(connection, 403, "Only alphanumeric characters are allowed for username.");
            return;
        }

    // check role
    char role = parameters.at("role").at(0);
    if (role < '0' || role > '1') {
        mg_send_http_error(connection, 400, "Spin7 can't understand the value for the role of new user.");
        return;
    }

    // prepare to write
    std::string newPasswordHashed = spin7PasswordHashed(newUsername, parameters.at("pw")), newRoleHashed = spin7RoleHashed(newUsername, newPasswordHashed, role), sessionId(sessionIdCalculated(newUsername));

    // check duplicate username
    if (users.contains(newUsername)) {
        mg_send_http_error(connection, 403, "Username already exists.");
        return;
    }

    // add new user to users.json
    users[newUsername]["password"s] = newPasswordHashed;
    users[newUsername]["role"s] = newRoleHashed;
    unpackAcl(newUsername);
    users[newUsername]["roleunpacked"s] = static_cast<int>(role) - 48; // 48=='0'
    users[newUsername]["sessionid"s] = sessionIdCalculated(newUsername);
    saveUsers();

    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void User::changePassword(mg_connection *connection, const std::string &username, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    // check existence of parameters
    if (!parameters.contains("currentpassword"s) || !parameters.contains("changedpassword"s)) {
        mg_send_http_error(connection, 400, "Required parameters are missing.");
        return;
    }

    std::string currentPassworHashed = spin7PasswordHashed(username, parameters.at("currentpassword")), newPasswordHashed = spin7PasswordHashed(username, parameters.at("changedpassword"));

    std::unique_lock locker(usersMutex);
    auto &description = users[username];
    // check whether current password is correct
    if (currentPassworHashed != description["password"]) {
        mg_send_http_error(connection, 403, "Current password is incorrect");
        return;
    }

    // set new hashed password and changed hashed role
    users[username]["password"s] = newPasswordHashed;
    users[username]["role"s] = spin7RoleHashed(username, newPasswordHashed, description["roleunpacked"].get<int>() + 48); // ASCII code '0'
    saveUsers();

    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void User::deleteUser(mg_connection *connection, const std::string &currentUser, const std::string &targetUser)
{
    std::unique_lock locker(usersMutex);

    // check if current user is super user
    if (users[currentUser]["roleunpacked"] != 0) {
        mg_send_http_error(connection, 403, "Requested action is not allowed.");
        return;
    }

    // check whether the user wants to delete himself(to prevent from deleting the only user or corrupting login)
    if (targetUser == usernameFromConnection(connection)) {
        mg_send_http_error(connection, 409, "You can't delete yourself.");
        return;
    }

    // remove user from users.json and users cache
    users.erase(targetUser);
    saveUsers();

    mg_send_http_error(connection, 204, "\r\n\r\n");
}

void User::logout(mg_connection *connection)
{
    // invalidate Civet7Token
    std::shared_lock locker(usersMutex);
    std::string cookieHeader = std::string("application/json\r\nSet-Cookie: Civet7Token=0").append(sessionSuffix), body("\"user " + usernameFromConnection(connection) + " is successfully logged out.\"");

    // respond
    mg_send_http_ok(connection, cookieHeader.data(), body.size());
    mg_write(connection, body.data(), body.size());
}

std::string User::sessionIdCalculated(const std::string &username)
{
    return SuperCodex::stringToHex(buildDigest(username + sessionSeed, EVP_sha3_256()));
}

std::string User::usernameFromConnection(mg_connection *connection)
{
    std::string loginTag;
    const std::string sessionId = sessionIdFromConnection(connection, loginTag);
    if (sessionId.empty())
        return ""s;

    // get user information
    for (auto &pair : users.items())
        if (pair.value()["sessionid"] == sessionId) {
            // get username
            std::string username = pair.key();

            // check ACL
            const auto &acl = acls[username];
            if (!acl.isEmpty && !acl.contains(SuperCodex::computerReadableIp(mg_get_request_info(connection)->remote_addr)))
                return "";

            // return username. if tag is found, add it to username
            if (!loginTag.empty())
                username.append('\t' + loginTag);
            return username;
        }

    // no such username
    return ""s;
}

void User::updateAcl(mg_connection *connection, const std::string &currentUser, const std::string &username, const ankerl::unordered_dense::map<std::string, std::string> &parameters)
{
    std::unique_lock locker(usersMutex);

    // check if current user is super user
    if (users[currentUser]["roleunpacked"] != 0) {
        mg_send_http_error(connection, 403, "Only super users are allowed to use the feature.");
        return;
    }

    const std::string sessionId = sessionIdCalculated(username);
    // check existence of target username
    if (!users.contains(username)) {
        mg_send_http_error(connection, 404, "No such user");
        return;
    }

    // update acl
    if (parameters.contains("acl"s)) {
        users[username]["acl"s] = parameters.at("acl"s);
        unpackAcl(username);
        saveUsers();
        mg_send_http_error(connection, 204, "\r\n\r\n");
    } else
        mg_send_http_error(connection, 400, "Required parameter(\"acl\") not found.");
}

std::string User::sessionIdFromConnection(mg_connection *connection, std::string &loginTag)
{
    // try to find Civet7Token from cookie
    const char *cookieHeader = mg_get_header(connection, "Cookie");
    char buffer[256];
    int bufferSize = mg_get_cookie(cookieHeader, "Civet7Token", buffer, 256);
    if (bufferSize > 1)
        return std::string(buffer, bufferSize);
    else { // find Civet7Token from HTTP request headers
        const char *civet7Header = mg_get_header(connection, "Civet7Token"); // Civet7Token
        if (civet7Header) {
            const char *tag = mg_get_header(connection, "Civet7Tag");
            if (tag)
                loginTag = tag; // provided custom login tag is used
            else
                loginTag = mg_get_request_info(connection)->remote_addr; // client IP is used as login tag
            return civet7Header;
        }
    }

    // if everything fails, just return empty string to announce it failed to get session information
    return ""s;
}

void User::unpackAcl(const std::string &user)
{
    // initialize a few variables
    const auto &targetAclString = users[user]["acl"s];
    if (!targetAclString.is_string())
        return;
    const std::string &aclRaw = targetAclString.get<std::string>();
    if (aclRaw.empty())
        return;
    SuperCodex::IpFilter acl;

    // validate and register ACL IPs
    std::istringstream tokenizer(aclRaw);
    for (std::string ip; std::getline(tokenizer, ip, ',');) {
        bool ipIsOk = true;
        // check whether the string consists of hexadecimal numbers only
        for (const auto &ch : ip)
            if (!((ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f') || (ch >= '0' && ch <= '9'))) {
                logger.oops("Not valid hexadecimal number string: "s + ip);
                ipIsOk = false;
                break;
            }
        if (!ipIsOk) // move to next IP address
            continue;

        // make the IP hexadecimal to lowercase
        std::transform(ip.begin(), ip.end(), ip.begin(), [](char c) -> char { return std::tolower(c); });

        // register to ACL
        acl.registerNetwork(ip);
    }

    // register new ACL
    acls[user] = acl;
}

void User::saveUsers()
{
    // save file
    bool succeeded = false;
    for (int i = 0; i < 3; ++i)
        try { // try up to 3 times
            // remove unnecessary keys from each object
            nlohmann::json toSave = users;
            for (auto &item : toSave.items()) {
                item.value().erase("roleunpacked"s);
                item.value().erase("sessionid"s);
            }

            // write to file
            std::ofstream saveFile("users.json"s, std::ios::trunc);
            saveFile << toSave;
            saveFile.close();

            // check the file by loading and parsing it from disk. on success nothing happens, while on failure exception is thrown
            (void) nlohmann::json::parse(std::ifstream("users.json"s));

            // success without exception: break loop. we don't need to repeat
            succeeded = true;
            break;
        } catch (std::exception &e) {
            logger.oops("Failed to save users.json. Details: "s + e.what());
        } catch (...) {
            logger.oops("Failed to save users.json. Details unknown."s);
        }

    // if success, make a copy of current file. else, revert
    if (succeeded)
        std::filesystem::copy_file("users.json", "users.json.backup", std::filesystem::copy_options::overwrite_existing);
    else {
        logger.oops("Failed to save users.json. reverting back to backup");
        std::filesystem::copy_file("users.json.backup", "users.json", std::filesystem::copy_options::overwrite_existing);
    }
}
