#ifndef USER_H
#define USER_H

#include <shared_mutex>
#include <ankerl/unordered_dense.h>
#include <nlohmann/json.hpp>

#include "../loghandler.h"
#include "../supercodex.h"

// forward declaration
struct mg_connection;

namespace User
{
// user authentication
extern std::string sessionSeed, sessionSuffix;
struct FreePass {
    std::string sessionId, tag;
    int lastKeepAlivRequest;
};
void login(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void logout(mg_connection *connection);

// user management
void initialize(const std::string &sessionSeed, const int tokenTimeout);
void enumerateUsers(mg_connection *connection, const std::string &username);
void addNewUser(mg_connection *connection, const std::string &currentUser, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void changePassword(mg_connection *connection, const std::string &username, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void deleteUser(mg_connection *connection, const std::string &currentUser, const std::string &targetUser);
void updateAcl(mg_connection *connection, const std::string &currentUser, const std::string &username, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void saveUsers();

// support and utility functions
std::string sessionIdCalculated(const std::string &username);
std::string sessionIdFromConnection(mg_connection *connection, std::string &loginTag);
std::string usernameFromConnection(mg_connection *connection);
void unpackAcl(const std::string &user);

// backend
extern nlohmann::json users; // nlohmann::json provides hashmap mechanism for JSON object
extern ankerl::unordered_dense::map<std::string, SuperCodex::IpFilter> acls;
extern std::shared_mutex usersMutex;
extern Logger logger;
extern int maxAge;
};

#endif // USER_H
