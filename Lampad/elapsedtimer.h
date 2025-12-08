#ifndef ELAPSEDTIMER_H
#define ELAPSEDTIMER_H

#include <chrono>

template <typename T>
class ElapsedTimer
{
public:
    ElapsedTimer();
    void start();
    std::chrono::nanoseconds elapsed();
    std::chrono::nanoseconds restart();

private:
    std::chrono::time_point<T> started;
};

#endif // ELAPSEDTIMER_H
