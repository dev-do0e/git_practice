#ifndef MYRIAD_H
#define MYRIAD_H

#ifdef __linux__
    #include <mariadb/mysql.h>
#else
    #include <mysql/mysql.h>
#endif
#include <string>
#include "loghandler.h"

class Myriad
{
public:
    Myriad();
    ~Myriad();

    // public interfaces
    int exec(const std::string &query);
    int execReal(const std::string &query);
    std::string lastError();

    // prepare-bind-run. currently, only column-wise binding is supported(as of current, row-wise binding seems to be unnecessary). https://mariadb.com/kb/en/mysql_bind/
    bool prepare(const std::string &query, const int numberOfColumns);
    void bind(const int column, std::vector<long> &data, char *indicators);
    void bind(const int column, std::vector<std::string> &data);
    bool execPrepared(const unsigned int arraySize=1);
    void closePrepared();

    // environmental variables
    static std::string host, user, password, db;
    static unsigned int serverPort;
    static unsigned long serverFlags;

private:
    // dealing with MySQL / MariaDB connections
    MYSQL *connector=nullptr;
    MYSQL_RES *queryResult=nullptr;

    // statement control
    MYSQL_STMT *statement=nullptr;
    MYSQL_BIND *bindParameters=nullptr;
    std::vector<std::pair<char **, unsigned long *>> stringBuffers; // pointer for strings + pointer for lengths

    // logger
    Logger logger;
};

#endif // MYRIAD_H
