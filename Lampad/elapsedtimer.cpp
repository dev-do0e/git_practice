#include "elapsedtimer.h"

template<typename T> ElapsedTimer<T>::ElapsedTimer()
{
    // do nothing yet
}

template<typename T> void ElapsedTimer<T>::start()
{
    started = T::now();
}

template<typename T> std::chrono::nanoseconds ElapsedTimer<T>::elapsed()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(T::now() - started);
}

template<typename T> std::chrono::nanoseconds ElapsedTimer<T>::restart()
{
    std::chrono::time_point<T> current = T::now();
    auto result = current - started;
    started = current;

    return std::chrono::duration_cast<std::chrono::nanoseconds>(result);
}

template class ElapsedTimer<std::chrono::system_clock>;
