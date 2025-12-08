#ifndef LOGHANDLER_H
#define LOGHANDLER_H

#include <iostream>
#include <functional>
#include <mutex>

// new log interface
class Logger {
public:
    static void initializeFileWrite(const std::string &logRoot, const std::string &fileName);
    static void cancelFileWrite();
    Logger(const std::string header);
    void setLogHeader(const std::string header);
    void log(const std::string message) const;
    void debug(const std::string message) const;
    void oops(const std::string message) const;
    void fatal(const std::string message);
    void logAndEcho(const std::string message) const;

private:
    std::string header;

    // utility functions
    void timestamp(std::ostream &outStream) const;

    // shared resources
    static std::function<void()> prepare;
    static std::ostream *logStream;
    static std::string logRoot, fileName;
    static std::mutex mutex;
};

class LogStopwatch {
public:
    LogStopwatch(Logger *logger, const std::string &description);
    ~LogStopwatch();
    void lap(const std::string lapDescription);

private:

#ifdef WIN32
    std::chrono::system_clock::time_point timerStart, lapStart;
    
#else
    std::chrono::system_clock::time_point timerStart, lapStart;
    
#endif
    Logger *logger;
    std::string description;
};
#endif // LOGHANDLER_H
