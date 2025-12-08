#ifndef FEATHERLITE_H
#define FEATHERLITE_H

#include <string>
#include <string_view>
#include <sqlite3.h>

using namespace std::string_literals;

class FeatherLite
{
public:
    explicit FeatherLite(const std::string &filename, int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    bool isOpen();
    ~FeatherLite();

    // some utility functions
    std::string lastError();
    bool optimize(const std::string &schema = "main"s);
    void useWal(const bool useWal = true);
    bool hasTable(const std::string &tableName);
    bool checkpoint(const int mode = SQLITE_CHECKPOINT_PASSIVE);
    bool exec(const std::string &query, int (*callback)(void *, int, char **, char **) = nullptr, void *argument1 = nullptr);
    bool dump(const std::string &table, const std::string &targetFile);
    bool append(const std::string &table, const std::string &targetFile, const std::string &attachAs, const std::string &targetTable);
    int rowsChanged();

    // prepare
    bool prepare(const std::string &query);

    // bind
    bool bindNull(int position);
    bool bindInt(int position, const int value);
    bool bindInt64(int position, const long long value);
    bool bindText(int position, const std::string &value);
    bool bindText(int position, const std::string_view &value);
    bool bindBlob(int position, const std::string &value);
    bool bindBlob(int position, const void *data, const size_t size);
    bool reset();

    // get result
    int next();
    bool isNull(int columnNumber);
    int getInt(int columnNumber);
    int64_t getInt64(int columnNumber);
    std::string_view getText(int columnNumber);
    std::string_view getBlob(int columnNumber);


    // finalize
    bool finalize();

private:
    // SQLite handles
    sqlite3 *db1 = nullptr;
    sqlite3_stmt *statement = nullptr;

    // flags
    bool openSuccessful = false;
};

#endif // FEATHERLITE_H
