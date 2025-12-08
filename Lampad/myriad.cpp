#include "myriad.h"
#include <string.h>

using namespace std::string_literals;

// static variables
std::string Myriad::host, Myriad::user, Myriad::password, Myriad::db;
unsigned int Myriad::serverPort=3306; // default for MySQL & MariaDB
unsigned long Myriad::serverFlags=0;

Myriad::Myriad(): logger("Myriad"s)
{
    connector=mysql_init(nullptr);
    if(!connector) {
        logger.log("Critical: failed to initialize MySQL connector"s);
        return;
    }
    mysql_optionsv(connector, MYSQL_SET_CHARSET_NAME, (void *)"utf8mb4"); // set character encoding to UTF-8 4 bytes
    if(!mysql_real_connect(connector, host.data(), user.data(), password.data(), db.empty()?nullptr:db.data(), serverPort, nullptr, serverFlags)) {
        logger.log("Critical: failed to connect to the database"s);
        return;
    }
}

Myriad::~Myriad()
{
    if(connector) mysql_close(connector);
}

int Myriad::exec(const std::string &query)
{
    return mysql_query(connector, query.data());
}

int Myriad::execReal(const std::string &query)
{
    int result=mysql_real_query(connector, query.data(), query.size());
    if(result) queryResult=mysql_use_result(connector);
    if(mysql_num_fields(queryResult)==0) {
        logger.log("Warning: no query result for "s+query);
        return -1;
    }
    return result;
}

std::string Myriad::lastError()
{
    return mysql_error(connector);
}

bool Myriad::prepare(const std::string &query, const int numberOfColumns)
{
    // prepare for statement
    statement=mysql_stmt_init(connector);
    if(mysql_stmt_prepare(statement, query.data(), query.size())) {
        logger.log("Error in statement preparation: "s+mysql_stmt_sqlstate(statement)+" + "s+mysql_error(connector));
        return false;
    }

    // prepare for bind metadata
    bindParameters=new MYSQL_BIND[numberOfColumns]{};
    memset(bindParameters, 0, sizeof(MYSQL_BIND)*numberOfColumns);

    return true;
}

void Myriad::bind(const int column, std::vector<long> &data, char *indicators)
{
    bindParameters[column].buffer_type=MYSQL_TYPE_LONG;
    bindParameters[column].buffer=data.data();
    bindParameters[column].u.indicator=indicators;
}

void Myriad::bind(const int column, std::vector<std::string> &data)
{
    // build buffers
    size_t dataSize=data.size();
    char **buffer=new char*[dataSize];
    unsigned long *lengths=new unsigned long[dataSize];
    for(int i=0, iEnd=data.size(); i<iEnd; ++i) {
        buffer[i]=data[i].data();
        lengths[i]=data[i].size();
    }

    // register strings
    bindParameters[column].buffer_type=MYSQL_TYPE_STRING;
    bindParameters[column].buffer=buffer;
    bindParameters[column].length=lengths;
    stringBuffers.push_back(std::make_pair(buffer, lengths));
}

bool Myriad::execPrepared(const unsigned int arraySize)
{
    logger.log("DEBUG/E1");
    // set array size
    mysql_stmt_attr_set(statement, STMT_ATTR_ARRAY_SIZE, &arraySize);

    logger.log("DEBUG/E2");
    // recognize fully configured parameter bindings
    mysql_stmt_bind_param(statement, bindParameters);

    logger.log("DEBUG/E3");
    // run the statement
    if(mysql_stmt_execute(statement)) {
        logger.log("DEBUG/E3.1");
        logger.log("Error in statement execution: "s+mysql_stmt_sqlstate(statement)+" + "s+mysql_error(connector));
        return false;
    }
    return true;
}

void Myriad::closePrepared()
{
    logger.log("DEBUG/C1");
    mysql_stmt_close(statement);
    logger.log("DEBUG/C2");
    delete[] bindParameters;

    // clear string buffers
    for(auto &pair: stringBuffers) {
        logger.log("DEBUG/C3");
        delete[] pair.first;
        logger.log("DEBUG/C4");
        delete[] pair.second;
    }
    stringBuffers.clear();
}
