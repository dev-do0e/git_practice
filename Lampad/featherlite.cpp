#include "featherlite.h"
#include <thread>
#include <chrono>

FeatherLite::FeatherLite(const std::string &filename, int flags)
{
    for (int i = 0; i < 10; ++i) {
        // open file
        int result = sqlite3_open_v2(filename.c_str(), &db1, flags, nullptr);
        if (result == SQLITE_OK) {
            openSuccessful = true;

            // optimize I/O performance for main schema
            optimize();

            break;
        } else if (result == SQLITE_BUSY) { // database can be temporarily busy, so try again up to 10 times
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        } else
            break; // anything else: unexpected error. just quit
    }
}

bool FeatherLite::isOpen()
{
    return openSuccessful;
}

FeatherLite::~FeatherLite()
{
    reset();
    finalize();
    sqlite3_close_v2(db1); // c.f. this call has return value(or error code), but is there any way we can use this?
}

std::string FeatherLite::lastError()
{
    return sqlite3_errmsg(db1);
}

bool FeatherLite::optimize(const std::string &schema)
{
    // prepare for pragma
    std::string command = "PRAGMA "s + schema + ".page_size=4096;" // page size
                          + "PRAGMA "s + schema + ".cache_size=20000;" // cache size
                          + "PRAGMA "s + schema + ".locking_mode=NORMAL;" // locking mode
                          + "PRAGMA "s + schema + ".synchronous=OFF;" // synchronous
        ;

    // run everything at once and return result
    return exec(command);
}

void FeatherLite::useWal(const bool useWal)
{
    if (useWal)
        exec("PRAGMA main.journal_mode=WAL;");
}

bool FeatherLite::hasTable(const std::string &tableName)
{
    // check whether the database has table
    bool tableFound = false;
    prepare("SELECT name FROM sqlite_master WHERE type IN ('table') AND name=? AND name NOT LIKE 'sqlite_%' ORDER BY name;");
    bindText(1, tableName);
    while (next())
        if (getBlob(0) == tableName) {
            tableFound = true;
            break;
        }
    reset();
    finalize();
    return tableFound;
}

bool FeatherLite::checkpoint(const int mode)
{
    return SQLITE_OK == sqlite3_wal_checkpoint_v2(db1, nullptr, mode, nullptr, nullptr);
}

bool FeatherLite::exec(const std::string &query, int (*callback)(void *, int, char **, char **), void *argument1)
{
    return sqlite3_exec(db1, query.data(), callback, argument1, nullptr) == SQLITE_OK;
}

bool FeatherLite::dump(const std::string &table, const std::string &targetFile)
{
    sqlite3 *db2 = nullptr;
    if (sqlite3_open_v2(targetFile.c_str(), &db2, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK)
        return false;
    if (sqlite3_exec(db2,
                     "PRAGMA main.page_size=4096;"
                     "PRAGMA main.cache_size=5000;"
                     "PRAGMA main.locking_mode=NORMAL;"
                     "PRAGMA main.synchronous=OFF;",
                     nullptr,
                     nullptr,
                     nullptr)
        != SQLITE_OK)
        return false;
    sqlite3_backup *backup = sqlite3_backup_init(db2, "main", db1, "main");
    if (backup == nullptr)
        return false;
    if (sqlite3_backup_step(backup, -1) != SQLITE_DONE)
        return false;
    if (sqlite3_backup_finish(backup))
        return false;
    sqlite3_close_v2(db2);
    return true;
}

bool FeatherLite::append(const std::string &table, const std::string &targetFile, const std::string &attachAs, const std::string &targetTable)
{
    std::string query;
    // attach database file
    query = "ATTACH DATABASE '"s + targetFile + "' AS "s + attachAs;
    if (sqlite3_exec(db1, query.data(), nullptr, nullptr, nullptr) != SQLITE_OK)
        return false;

    // optimize target for fastest write
    exec("PRAGMA " + attachAs
         + ".page_size=4096;"
           "PRAGMA "
         + attachAs
         + ".cache_size=5000;"
           "PRAGMA "
         + attachAs
         + ".locking_mode=NORMAL;"
           "PRAGMA "
         + attachAs
         + ".synchronous=NORMAL;"
           "PRAGMA "
         + attachAs
         + ".journal_mode=MEMORY;"
           "PRAGMA "
         + attachAs + ".cache_size=20000;" // https://www.sqlite.org/pragma.html#pragma_cache_size
    );

    // append to table in the disk
    query = "INSERT INTO "s + attachAs + '.' + targetTable + " SELECT * FROM "s + table;
    if (sqlite3_exec(db1, query.data(), nullptr, nullptr, nullptr) != SQLITE_OK)
        return false;

    // detach database
    query = "DETACH DATABASE "s + attachAs;
    if (sqlite3_exec(db1, query.data(), nullptr, nullptr, nullptr) != SQLITE_OK)
        return false;
    return true;
}

int FeatherLite::rowsChanged()
{
    return sqlite3_changes(db1);
}

bool FeatherLite::reset()
{
    return sqlite3_reset(statement) == SQLITE_OK;
}

bool FeatherLite::prepare(const std::string &query)
{
    return sqlite3_prepare_v2(db1, query.data(), query.size(), &statement, nullptr) == SQLITE_OK;
}

int FeatherLite::getInt(int columnNumber)
{
    return sqlite3_column_int(statement, columnNumber);
}

int64_t FeatherLite::getInt64(int columnNumber)
{
    return sqlite3_column_int64(statement, columnNumber);
}

std::string_view FeatherLite::getText(int columnNumber)
{
    return std::string_view((const char *) sqlite3_column_text(statement, columnNumber), sqlite3_column_bytes(statement, columnNumber));
}

std::string_view FeatherLite::getBlob(int columnNumber)
{
    return std::string_view(static_cast<const char *>(sqlite3_column_blob(statement, columnNumber)), sqlite3_column_bytes(statement, columnNumber));
}

bool FeatherLite::isNull(int columnNumber)
{
    return sqlite3_column_type(statement, columnNumber) == SQLITE_NULL;
}

int FeatherLite::next()
{
    // the successful result can be either SQLITE_ROW or SQLITE_DONE, depending on the situation(i.e. SELECT or INSERT)
    return sqlite3_step(statement);
}

bool FeatherLite::bindNull(int position)
{
    return sqlite3_bind_null(statement, position) == SQLITE_OK;
}

bool FeatherLite::bindInt(int position, const int value)
{
    return sqlite3_bind_int(statement, position, value) == SQLITE_OK;
}

bool FeatherLite::bindInt64(int position, const long long value)
{
    return sqlite3_bind_int64(statement, position, value) == SQLITE_OK;
}

bool FeatherLite::bindBlob(int position, const std::string &value)
{
    return sqlite3_bind_blob(statement, position, value.data(), value.size(), nullptr) == SQLITE_OK;
}

bool FeatherLite::bindBlob(int position, const void *data, const size_t size)
{
    return sqlite3_bind_blob(statement, position, data, size, nullptr) == SQLITE_OK;
}

bool FeatherLite::bindText(int position, const std::string &value)
{
    return sqlite3_bind_text(statement, position, value.data(), value.size(), nullptr) == SQLITE_OK;
}

bool FeatherLite::bindText(int position, const std::string_view &value)
{
    return sqlite3_bind_text(statement, position, value.data(), value.size(), nullptr) == SQLITE_OK;
}

bool FeatherLite::finalize()
{
    int result = sqlite3_finalize(statement);
    statement = nullptr;
    return result == SQLITE_OK;
}
