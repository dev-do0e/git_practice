#ifndef CIVET7_H
#define CIVET7_H

#include <civetweb.h>
#include <ankerl/unordered_dense.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <yyjson.h>

#include "datafeed.h"
#include "../loghandler.h"

// forward declarations

namespace Civet7 {
// variables
extern mg_context *context;
extern std::string staticFileRoot;
extern Logger logger;

// startup + utilities
void start(const nlohmann::json &settings);
std::string cutPath(std::string &path);
void respond200(mg_connection *connection, yyjson_mut_doc *document);
void respond200(mg_connection *connection, const nlohmann::json &body);
void respond200(mg_connection *connection, const char *data, const size_t size, const std::string &mimeType = "application/json"s);
extern std::string startupTime;

// request handlers
int sendStaticFile(mg_connection *connection, void *data);
int processQuery(mg_connection *connection, void *data);
int controlSpin7(mg_connection *connection, void *data);
int controlParadox(mg_connection *connection, void *data);

// form handlers
ankerl::unordered_dense::map<std::string, std::string> requestParameters(mg_connection *connection, const std::string &method);
extern struct mg_form_data_handler formHandlerProto;
int fieldFound(const char *key, const char *fileName, char *path, size_t pathLen, void *userData);
int getField(const char *key, const char *value, size_t valueLen, void *userData);
int storeField(const char *path, long long fileSize, void *userData);
std::string stringifyyy(yyjson_val *value); // utility function used in requestParameters()

// global key-value store
extern ankerl::unordered_dense::map<std::string, std::string> kvs;
extern std::string kvsFilePath;
extern std::mutex kvsMutex;
void getValues(mg_connection *connection);
void setValues(mg_connection *connection, const ankerl::unordered_dense::map<std::string, std::string> &parameters);
void deleteValues(mg_connection *connection, const std::string &currentUser);
void saveValues();
} // namespace Civet7

#endif // CIVET7_H
