#ifndef EVENTS_H
#define EVENTS_H

#include <stdint.h>
#include <string>

namespace Event {

struct Notification {
    int32_t second;
    enum Type: uint16_t {
        // counts / accumulations
        BPS,
        PPS,
        RTT, // average, actually
        TCPTIMEOUTS,
        TCPREQUESTS,
        UDPHITS,
        TCPRSTS,
        TCPZEROWINDOWS,
        HTTP4XXS,
        HTTP5XXS,
        TCPDUPACKS,
        TCPRETRANSMISSIONS,
        // check existence
        TCPSPURIOUSRETRANSMISSION,
        TCPPORTREUSED,
        HOPLIMITLOW,
        DUPLICATEIP
    } type;
    enum Severity: uint8_t {
        MINOR, MAJOR, CRITICAL
    } severity;
    int8_t isPercentile; // 1=true, 0=false
    int64_t threshold, duration, notificationBase/* base number of hits to show notification */, hits/* number of occurrences value is over threshold */;
    uint32_t tagSize, eventNameSize; // after this, actual tag name and event name follow
};
constexpr int notificationSize=sizeof(Notification);

}

#endif // EVENTS_H
