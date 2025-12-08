#include "loghandler.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

// static resources declaration
std::function<void()> Logger::prepare = []() {}; // do nothing
std::ostream *Logger::logStream = &std::cerr; // default: show logs on stderr
std::string Logger::logRoot, Logger::fileName;
std::mutex Logger::mutex;

using namespace std::string_literals;

void Logger::initializeFileWrite(const std::string &logRoot, const std::string &fileName)
{
    Logger::logRoot = logRoot;
    if (Logger::logRoot.at(Logger::logRoot.size() - 1) != '/')
        Logger::logRoot.push_back('/'); // append tailing slash as needed
    Logger::fileName = '/' + fileName + ".log"s;
    logStream = new std::ofstream;
    prepare = [&]() {
        // get struct tm
        time_t timeRaw = time(nullptr);
        tm nowTm;
#ifdef __linux__
        localtime_r(&timeRaw, &nowTm); // Linux
#else
        localtime_s(&nowTm, &timeRaw); // Windows
#endif

        // get and adjust month and day
        std::string month(std::to_string(nowTm.tm_mon + 1)), day(std::to_string(nowTm.tm_mday));
        if (month.size() < 2)
            month = '0' + month;
        if (day.size() < 2)
            day = '0' + day;

        // open stream
        std::string targetPath = Logger::logRoot + std::to_string(nowTm.tm_year + 1900) + '-' + month + '-' + day;
        if (!std::filesystem::exists(targetPath))
            std::filesystem::create_directories(targetPath); // make directory if it doesn't exist
        targetPath.append(Logger::fileName);
        dynamic_cast<std::ofstream *>(logStream)->close();
        dynamic_cast<std::ofstream *>(logStream)->open(targetPath, std::ofstream::out | std::ofstream::ate | std::ofstream::app);
    };
    std::cout << "Saving logs to " << Logger::logRoot << std::endl;
}

void Logger::cancelFileWrite()
{
    prepare = []() {};
    logStream = &std::cerr;
}

Logger::Logger(const std::string header)
{
    // build actual log header string
    setLogHeader(header);
}

void Logger::setLogHeader(const std::string header)
{
    this->header = header + " ("s;
}

void Logger::log(const std::string message) const
{
    // mutex is outside try-catch block: if mutex has problems, this is a serious problem - we need to stop the process from running and find out the reason
    mutex.lock();
    try {
        prepare();
        timestamp(*logStream);
        *logStream << header << std::this_thread::get_id() << ")> "s << message << std::endl;
    } catch (...) {
        // do nothing. just sliently ignore
    }
    mutex.unlock();
}

void Logger::debug(const std::string message) const
{
    log("|DEBUG| "s + message);
}

void Logger::oops(const std::string message) const
{
    log("|OOPS| "s + message);
}

void Logger::logAndEcho(const std::string message) const
{
    if (logStream == &std::cerr)
        log(message);
    else {
        std::stringstream stream;
        mutex.lock();
        prepare();
        timestamp(stream);
        stream << header << std::this_thread::get_id() << ")> "s << message << std::endl;
        std::string string = stream.str();
        *logStream << string;
        std::cerr << string;
        mutex.unlock();
    }
}

void Logger::fatal(const std::string message)
{
    log(message);
    abort();
}

void Logger::timestamp(std::ostream &outStream) const
{
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    struct tm nowInTm;
#ifdef __linux__
    localtime_r(&time, &nowInTm); // Linux
#else
    localtime_s(&nowInTm, &time); // Windows
#endif

    long long timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::string result;

    outStream << std::put_time(&nowInTm, "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << timestamp % 1000 << " | "s;
}

LogStopwatch::LogStopwatch(Logger *logger, const std::string &description)
    : logger(logger)
    , description(description)
{
    timerStart = std::chrono::system_clock::now();
    lapStart = timerStart;
}

LogStopwatch::~LogStopwatch()
{
    logger->log(description + " [ "s + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - timerStart).count()) + "ms ]");
}

void LogStopwatch::lap(const std::string lapDescription)
{
    auto now = std::chrono::system_clock::now();
    logger->log(lapDescription + " [ "s + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now - lapStart).count()) + "ms ]");
    lapStart = now;
}
