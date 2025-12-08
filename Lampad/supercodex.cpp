#include "supercodex.h"
#include "fnvhash.h"

#ifdef COMPENSATESESSIONDIRECTION
#include "spin7/tcpservicemanager.h"
#endif

#include <vector>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <filesystem>

#include <lz4.h>

// static variables
int SuperCodex::compressionLevel = 2;
ankerl::unordered_dense::set<std::string> SuperCodex::Loader::globalExclusionSingleIp, SuperCodex::Loader::globalExclusionPair;

using namespace std::string_literals;

// helper stuff. :P
static const char *hexTable[256] = {"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af", "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf", "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf", "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df", "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef", "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff"};

void SuperCodex::IpFilter::registerNetwork(const std::string &raw, const uint16_t port, const std::string &alias)
{
    // if raw data is hexadecimal string, try to convert to its original
    const size_t rawSize = raw.size();
    std::string temp;
    std::string_view raw2(raw);
    if ((rawSize == 8 || rawSize == 10 || rawSize == 32 || rawSize == 34)) {
        temp = stringFromHex(raw);
        raw2 = std::string_view(temp);
    }
    if (raw2.empty()) // failed to convert hexadecimal value to corresponding binary data
        return;

    switch (raw2.size()) {
    // IPv4
    case 5:
        if (registerV4WithMask(raw2, port, alias))
            isEmpty = false;
        break;
    case 4: // single IP: push directly
        v4Filters.push_back(IpStore<uint32_t>{*(uint32_t *) raw2.data(), UINT32_MAX, port, alias});
        isEmpty = false;
        break;

    // IPv6
    case 17:
        if (registerV6WithMask(raw2, port, alias))
            isEmpty = false;
        break;
    case 16: // single IP: push directly
        v6Filters.push_back(IpStore<std::pair<uint64_t, uint64_t>>{std::make_pair(*(uint64_t *) raw2.data(), *(uint64_t *) (raw2.data() + 8)), std::make_pair(UINT64_MAX, UINT64_MAX), port, alias});
        isEmpty = false;
        break;
    }
}

uint32_t SuperCodex::IpFilter::signature()
{
    uint32_t result = 0;

    // remove overlapping CIDRs
    auto v4Copied = v4Filters; // IPv4
    for (auto i = v4Copied.begin(); i != v4Copied.end();) {
        bool removeElement = false;
        for (const auto &filter : v4Filters)
            if (filter.ip == (i->ip & filter.netmask) && filter.netmask != i->netmask) {
                removeElement = true;
                break;
            }
        if (removeElement)
            i = v4Copied.erase(i);
        else
            ++i;
    }
    v4Filters = v4Copied;
    auto v6Copied = v6Filters; // IPv6
    for (auto i = v6Copied.begin(); i != v6Copied.end();) {
        bool removeElement = false;
        for (const auto &filter : v6Filters)
            if (filter.ip.first == (i->ip.first & filter.netmask.first) && filter.ip.second == (i->ip.second & filter.netmask.second) && filter.netmask != i->netmask) {
                removeElement = true;
                break;
            }
        if (removeElement)
            i = v6Copied.erase(i);
        else
            ++i;
    }
    v6Filters = v6Copied;

    // sort filters to get consistent value
    std::sort(v4Filters.begin(), v4Filters.end(), [](const IpStore<uint32_t> &a, const IpStore<uint32_t> &b) -> bool { return a.ip < b.ip; });
    std::sort(v6Filters.begin(), v6Filters.end(), [](const IpStore<std::pair<uint64_t, uint64_t>> &a, const IpStore<std::pair<uint64_t, uint64_t>> &b) -> bool { return a.ip.first > b.ip.first || (a.ip.first == b.ip.first && a.ip.second > b.ip.second); });

    // build signature from IPv4 addresses
    for (const auto &store : v4Filters) {
        result = fnv32a(&store.ip, 4, result);
        result = fnv32a(&store.netmask, 4, result);
    }

    // add "separator" value which can distinguish IPv4 and v6 byte sequence to prevent from signature overlap(e.g. some 4 IPv4 addresses could overlap following one IPv6 address)
    result = fnv32a("\x7f\x80\x81\x82", 4, result); // 127.128.129.130, which is in IPv4 localhost that won't be seen in our IP gatherings

    // build signature from IPv6 addresses
    for (const auto &store : v6Filters) {
        result = fnv32a(&store.ip.first, 8, result);
        result = fnv32a(&store.ip.second, 8, result);
        result = fnv32a(&store.netmask.first, 8, result);
        result = fnv32a(&store.netmask.second, 8, result);
    }

    return result;
}

std::pair<size_t, size_t> SuperCodex::IpFilter::registeredAddresses() const
{
    return std::make_pair(v4Filters.size(), v6Filters.size());
}

bool SuperCodex::IpFilter::registerV4WithMask(const std::string_view &ip, const uint16_t port, const std::string &alias)
{
    // determine mask length
    uint8_t maskLength = ip.back();

    // build up mask
    uint8_t netmaskRaw[4]{};
    size_t fullBits = maskLength / 8, remainingBits = maskLength % 8;
    for (size_t i = 0; i < fullBits; ++i)
        netmaskRaw[i] = UINT8_MAX;
    if (remainingBits)
        netmaskRaw[fullBits] = lastByte(remainingBits);

    // verify and push back data
    uint32_t ip1 = *(const uint32_t *) ip.data();
    if ((ip1 & *(const uint32_t *) netmaskRaw) == ip1) {
        v4Filters.push_back(IpStore<uint32_t>{*(const uint32_t *) ip.data(), *(const uint32_t *) netmaskRaw, port, alias});
        return true;
    } else
        return false;
}

bool SuperCodex::IpFilter::registerV6WithMask(const std::string_view &ip, const uint16_t port, const std::string &alias)
{
    // determine mask length
    uint8_t maskLength = ip.back();

    // build up mask
    std::pair<uint64_t, uint64_t> netmaskRaw{0ULL, 0ULL};
    size_t fullBits = maskLength / 8, remainingBits = maskLength % 8;
    uint8_t tail[8]{};
    if (fullBits >= 8) {
        netmaskRaw.first = UINT64_MAX;
        size_t iEnd = fullBits - 8;
        for (size_t i = 0; i < iEnd; ++i)
            tail[i] = UINT8_MAX;
        if (remainingBits)
            tail[iEnd] = lastByte(remainingBits);
        netmaskRaw.second = *(uint64_t *) tail;
    } else {
        for (size_t i = 0; i < fullBits; ++i)
            tail[i] = UINT8_MAX;
        if (remainingBits)
            tail[fullBits] = lastByte(remainingBits);
        netmaskRaw.first = *(uint64_t *) tail;
    }

    // verify and push back data
    const char *cursor = ip.data();
    uint64_t upper = *(const uint64_t *) cursor, lower = *(const uint64_t *) (cursor + 8);
    if ((upper & netmaskRaw.first) == upper && (lower & netmaskRaw.second) == lower) {
        v6Filters.push_back(IpStore<std::pair<uint64_t, uint64_t>>{std::make_pair(upper, lower), std::move(netmaskRaw), port, alias});
        return true;
    } else
        return false;
}

uint8_t SuperCodex::IpFilter::lastByte(const size_t bitCount)
{
    uint8_t result = 0;
    for (size_t i = 7, iEnd = 8 - bitCount % 8 - 1; i > iEnd; --i)
        result += 1 << i;

    return result;
}

bool SuperCodex::IpFilter::contains(const std::string_view &ip) const
{
    switch (ip.size()) {
    case 4:
        return isRegisteredV4(ip);
    case 16:
        return isRegisteredV6(ip);
    case 8:
        return isRegisteredV4(stringFromHex(std::string(ip)));
    case 32:
        return isRegisteredV6(stringFromHex(std::string(ip)));
    default:
        return false;
    }
}

std::string SuperCodex::IpFilter::getAlias(const std::string_view &ip, const uint16_t port) const
{
    switch (ip.size()) {
    case 4:
        return getAliasV4(ip, port);
    case 16:
        return getAliasV6(ip, port);
    case 8:
        return getAliasV4(stringFromHex(std::string(ip)), port);
    case 32:
        return getAliasV6(stringFromHex(std::string(ip)), port);
    default:
        return ""s;
    }
}
std::string SuperCodex::IpFilter::getAliasV4(const std::string_view &ip, const uint16_t port) const
{
    for (const auto &filter : v4Filters)
        if (filter.ip == ((*(uint32_t *) ip.data()) & filter.netmask)) {
            if (filter.port == port || filter.port == 0)
                return filter.alias;
        }
    return ""s;
}

std::string SuperCodex::IpFilter::getAliasV6(const std::string_view &ip, const uint16_t port) const
{
    for (const auto &filter : v6Filters) {
        if (filter.ip.first == ((*(uint64_t *) ip.data()) & filter.netmask.first) && // first 64 bits
            filter.ip.second == ((*(uint64_t *) (ip.data() + 8)) & filter.netmask.second)) {
            if (filter.port == port || filter.port == 0)
                return filter.alias;
        }
    }
    return ""s;
}

bool SuperCodex::IpFilter::isRegisteredV4(const std::string_view &ip) const
{
    for (const auto &filter : v4Filters)
        if (filter.ip == ((*(uint32_t *) ip.data()) & filter.netmask))
            return true;
    return false;
}

bool SuperCodex::IpFilter::isRegisteredV6(const std::string_view &ip) const
{
    for (const auto &filter : v6Filters) {
        if (filter.ip.first == ((*(uint64_t *) ip.data()) & filter.netmask.first) && // first 64 bits
            filter.ip.second == ((*(uint64_t *) (ip.data() + 8)) & filter.netmask.second))
            return true;
    }
    return false;
}

std::string SuperCodex::sourceIp(const Session &session)
{
    return std::string((const char *) session.ips, ipLength(session.etherType));
}

std::string SuperCodex::destinationIp(const Session &session)
{
    int length = ipLength(session.etherType);
    return std::string((const char *) (session.ips + length), length);
}

std::string SuperCodex::service(const SuperCodex::Session &session)
{
    std::string result = destinationIp(session);
    result.append((const char *) &session.destinationPort, 2);
    return result;
}

int SuperCodex::ipLength(const unsigned short etherType)
{
    switch (etherType) {
    case 0x0800: // IPv4
        return 4;
    case 0x86dd: // IPv6
        return 16;
    default:
        return 0;
    }
}

SuperCodex::CastType SuperCodex::castType(const SuperCodex::Session &session)
{
    int ipOffset = 0;
    switch (session.etherType) {
    case 0x0800: // IPv4
        if (session.payloadProtocol == 0x11) { // multicast and broadcast can be used only if the payload protocol is UDP
            if (session.sourceIsSmall)
                ipOffset = 4;
            if (session.ips[ipOffset] >= 224 && session.ips[ipOffset] <= 239)
                return MULTICAST; // IP multicast address(destination): 224.0.0.0~239.255.255.255
            else if (*(uint32_t *) &session.ips[ipOffset] == UINT32_MAX)
                return BROADCAST; // IP broadcast address(destination): 255.255.255.255
            else
                return UNICAST;
        } else // TCP, ICMP, ......
            return UNICAST;
    case 0x86dd: // IPv6
        if (session.payloadProtocol == 0x11) { // multicast and broadcast can be used only if the payload protocol is UDP
            if (session.sourceIsSmall)
                ipOffset = 16;
            if (session.ips[ipOffset] == 0xff && session.ips[ipOffset + 1] == 0x00)
                return MULTICAST; // IPv6 multicast address(destination): FF00::/8
            else
                return UNICAST; // IPv6 doesn't support broadcast
        }
    default:
        return UNKNOWN;
    }
}

bool SuperCodex::isValidHexadecimal(const std::string &stringInHex)
{
    for (const auto &ch : stringInHex)
        if (!((ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f') || (ch >= '0' && ch <= '9')))
            return false;

    return true;
}

bool SuperCodex::isPast(const uint32_t second1, const uint32_t nanosecond1, const uint32_t second2, const uint32_t nanosecond2)
{
    if (second1 < second2)
        return true;
    else if (second1 == second2 && nanosecond1 < nanosecond2)
        return true;
    else
        return false;
}

bool SuperCodex::isPastOrPresent(const uint32_t second1, const uint32_t nanosecond1, const uint32_t second2, const uint32_t nanosecond2)
{
    if (second1 < second2)
        return true;
    else if (second1 == second2 && nanosecond1 <= nanosecond2)
        return true;
    else
        return false;
}

void SuperCodex::swapIpPortPair(SuperCodex::Session &session)
{
    unsigned char realServerIp[16];
    int length = ipLength(session.etherType);
    memcpy(realServerIp, session.ips, length);
    memcpy(session.ips, session.ips + length, length);
    memcpy(session.ips + length, realServerIp, length);
    std::swap(session.sourcePort, session.destinationPort);
    if (session.sourceIsSmall == 1)
        session.sourceIsSmall = 0;
    else
        session.sourceIsSmall = 1;
}

std::string SuperCodex::humanReadableIp(const std::string_view &ipRaw)
{
    std::string result;
    if (ipRaw.size() == 4) { // IPv4
        result.reserve(16);
        for (const auto &ch : ipRaw)
            result.append(std::to_string((unsigned char) ch)).push_back('.');
        result.pop_back(); // remove redundant dot(.) in tail
    } else if (ipRaw.size() == 16) { // IPv6
        result.reserve(16);
        for (int i = 0; i < 16; i += 2)
            result.append(hexTable[(unsigned char) ipRaw[i]]).append(hexTable[(unsigned char) ipRaw[i + 1]]).push_back(':');
        result.pop_back(); // remove redundant colon in tail
    }

    return result;
}

std::string SuperCodex::computerReadableIp(const std::string &humanReadableIp)
{
    std::string result;
    std::istringstream splitter(humanReadableIp);
    if (humanReadableIp.find('.') != std::string::npos) { // IPv4 assumed
        for (std::string raw; std::getline(splitter, raw, '.');)
            try {
                result.push_back((char) static_cast<unsigned char>(std::stoi(raw)));
            } catch (...) {
                return result; // return empty string
            }
    } else if (humanReadableIp.find(':') != std::string::npos) { // IPv6 assumed
        try {
            result.reserve(16);
            if (humanReadableIp.size() == 39) { // full representation assumed: aaaa:bbbb:cccc:dddd:eeee:fffff:0123:4567 style
                for (int i = 0; i < 40; i += 5) {
                    result.push_back((char) static_cast<unsigned char>(std::stoi(humanReadableIp.substr(i, 2), nullptr, 16)));
                    result.push_back((char) static_cast<unsigned char>(std::stoi(humanReadableIp.substr(i + 2, 2), nullptr, 16)));
                }
            } else {
                std::function<std::string(const std::string &)> convert = [](const std::string &raw) -> std::string {
                    std::string result;
                    switch (raw.size()) {
                    case 4:
                        result.push_back((char) static_cast<unsigned char>(std::stoi(raw.substr(0, 2), nullptr, 16)));
                        result.push_back((char) static_cast<unsigned char>(std::stoi(raw.substr(2, 2), nullptr, 16)));
                        break;
                    case 3: // omitting leading first 0
                        result.push_back((char) static_cast<unsigned char>(std::stoi(raw.substr(0, 1), nullptr, 16)));
                        result.push_back((char) static_cast<unsigned char>(std::stoi(raw.substr(1, 2), nullptr, 16)));
                        break;
                    default: // 2 or 1
                        result.push_back((char) static_cast<unsigned char>(std::stoi(raw, nullptr, 16)));
                        break;
                    }
                    return result;
                };
                size_t cursorStart = 0, nextStart = humanReadableIp.find(':');
                while (nextStart != std::string::npos) {
                    // check double colon, which omits successive zeros
                    if (humanReadableIp[nextStart + 1] == ':') {
                        // count number of colons after double colon(::)
                        int remainingColons = 0;
                        for (int i = nextStart + 2, iEnd = humanReadableIp.size(); i < iEnd; ++i)
                            if (humanReadableIp[i] == ':')
                                ++remainingColons;

                        // add zeros as many as needed
                        for (int i = 0, iEnd = 16 - result.size() - ((remainingColons + 1 /* +1: last element */) * 2); i < iEnd; ++i)
                            result.push_back('\0');
                    } else {
                        // push
                        result.append(convert(humanReadableIp.substr(cursorStart, nextStart)));

                        // move cursor to next element
                        cursorStart = nextStart + 1;
                        nextStart = humanReadableIp.find(':', cursorStart);
                    }
                }

                // convert tail - the last 16 bits
                result.append(convert(humanReadableIp.substr(cursorStart, nextStart)));
            }
        } catch (...) {
            return ""s; // return empty string
        }

        // if the length doesn't match, declare failure:
        if (result.size() != 16)
            return ""s;
    }

    return result;
}

std::string SuperCodex::l7ProtocolToString(const SuperCodex::Session::L7Protocol protocol)
{
    switch (protocol) {
    case SuperCodex::Session::NOL7DETECTED:
        return "None"s;
    // base
    case SuperCodex::Session::DNS:
        return "DNS"s;
    case SuperCodex::Session::HTTP:
        return "HTTP"s;
    case SuperCodex::Session::TLS:
        return "TLS"s;
    case SuperCodex::Session::FTP:
        return "FTP"s;
    case SuperCodex::Session::SMTP:
        return "SMTP"s;
    case SuperCodex::Session::IMAP:
        return "IMAP"s;
    case SuperCodex::Session::POP3:
        return "POP3"s;
    // AV streaming
    case SuperCodex::Session::RTP:
        return "RTP"s;
    case SuperCodex::Session::RTCP:
        return "RTCP"s;
    case SuperCodex::Session::RTSP:
        return "RTSP"s;
    // VoIP and teleconference
    case SuperCodex::Session::SIP:
        return "SIP"s;
    default:
        return "Unknown"s;
    }
}

SuperCodex::Glyph SuperCodex::compress(const char *data, const size_t size)
{
    char *buffer = new char[size];
    int32_t compressedSize = LZ4_compress_fast(data, buffer, size, size, compressionLevel);

    // LZ4 returns zero legnth result on compression if length of source stream is less than 51 bytes. in such case, we'll write down uncompressed raw data instead
    if (compressedSize == 0 || compressedSize == size) {
        memcpy(buffer, data, size);
        compressedSize = size; // in case compressedSize is zero
    }
    return Glyph{buffer, compressedSize};
}

char *SuperCodex::decompress(const Glyph compressed, const int compressedSize, const int originalSize)
{
    // simple sanity check
    if (compressed.size != compressedSize)
        return nullptr;

    char *buffer = new char[originalSize];
    // LZ4 returns zero legnth result on compression if length of source stream is less than 51 bytes. in such case, compressed size and original size will be same
    if (compressedSize == originalSize)
        memcpy(buffer, compressed.data, originalSize);
    else
        LZ4_decompress_safe(compressed.data, buffer, compressedSize, originalSize);

    return buffer;
}

SuperCodex::Loader::Loader(const std::string &file, const SuperCodex::ChapterType chaptersToLoad, const SuperCodex::Conditions &filter)
    : fileName(file)
    , conditions(filter)
    , logger("SuperCodex: "s + fileName)
{
    // check file sanity
    std::filesystem::path path(fileName);
    if (!std::filesystem::exists(path)) {
        logger.log("File unavailable: "s + fileName);
        isSane = false;
        return;
    }
    if (std::filesystem::file_size(path) < 8) {
        logger.log("Codex too small. File size is "s + std::to_string(std::filesystem::file_size(path)));
        isSane = false;
        return;
    }

    // open file
    std::ifstream compressedFile(fileName, std::ifstream::binary);

    // get timestamps the codex covers
    compressedFile.seekg(0, compressedFile.beg); // first 8 bytes = timestamps covered by the codex
    char buffer[8];
    compressedFile.read(buffer, 8);
    memcpy(&secondStart, buffer, 4);
    memcpy(&secondEnd, buffer + 4, 4);
    if (secondStart > secondEnd) {
        logger.log("Corrupt timestamp: start of the codex is future of the end."s);
        isSane = false;
        return;
    }

    // decompress and load selected chapter
    try {
        // session and schrodinger chapter must be loaded anyway
        ChapterType chaptersToLoadFinal = static_cast<SuperCodex::ChapterType>(chaptersToLoad | SuperCodex::SESSIONS | SuperCodex::SCHRODINGER);

        while (!compressedFile.eof()) {
            // read chapter header
            char headerRaw[12];
            compressedFile.read(headerRaw, 12);
            if (compressedFile.gcount() != 12) {
                // show a warning message if ifstream didn't hit end of the file
                if (compressedFile.eof() && compressedFile.gcount() == 0)
                    break;
                else {
                    logger.log("Chapter header corrupt: it should be 12, but only "s + std::to_string(compressedFile.gcount()) + " bytes are read. Cancelling job. " + std::to_string(compressedFile.eof()));
                    return;
                }
            }
            ChapterHeader *header = (ChapterHeader *) headerRaw;
            if (header->compressedSize == 0)
                continue;

            if (header->type & chaptersToLoadFinal) { // load chapter
                // read data block
                Glyph rawStream;
                rawStream.data = new char[header->compressedSize];
                compressedFile.read(rawStream.data, header->compressedSize);
                if (header->compressedSize != compressedFile.gcount()) {
                    logger.log("Failed to read expected length of compressed data reading chapter type "s + std::to_string(header->type));
                }
                rawStream.size = compressedFile.gcount();
                char *temp = decompress(rawStream, header->compressedSize, header->originalSize);
                if (!temp) {
                    logger.log("Critical: failed to decompress chapter. Chapter type: "s + std::to_string(header->type));
                    return;
                }
                switch (header->type) {
                case PACKETS:
                    packetRaw.append(temp, header->originalSize);
                    packetStart = (const Packet *) packetRaw.data();
                    packetEnd = (const Packet *) (packetRaw.data() + packetRaw.size());
                    break;
                case SESSIONS:
                    sessionRaw.append(temp, header->originalSize);
                    sessionCursor = (Session *) sessionRaw.data();
                    sessionCursorEnd = (Session *) (sessionRaw.data() + sessionRaw.size());
                    break;
                case BPSPERSESSION:
                    bpsPerSessionRaw.append(temp, header->originalSize);
                    bpsPerSessionStart = (const BpsPpsItem *) bpsPerSessionRaw.data();
                    bpsPerSessionEnd = (const BpsPpsItem *) (bpsPerSessionRaw.data() + bpsPerSessionRaw.size());
                    break;
                case PPSPERSESSION:
                    ppsPerSessionRaw.append(temp, header->originalSize);
                    ppsPerSessionStart = (const BpsPpsItem *) ppsPerSessionRaw.data();
                    ppsPerSessionEnd = (const BpsPpsItem *) (ppsPerSessionRaw.data() + ppsPerSessionRaw.size());
                    break;
                case REMARKS:
                    remarksRaw.append(temp, header->originalSize);
                    remarksStart = remarksRaw.data();
                    remarksEnd = remarksStart + remarksRaw.size();
                    break;
                case RTTS:
                    rttRaw.append(temp, header->originalSize);
                    rttStart = (const PacketMarker *) rttRaw.data();
                    rttEnd = (const PacketMarker *) (rttRaw.data() + rttRaw.size());
                    break;
                case TIMEOUTS:
                    timeoutRaw.append(temp, header->originalSize);
                    timeoutStart = (Timeout *) timeoutRaw.data();
                    timeoutEnd = (Timeout *) (timeoutRaw.data() + timeoutRaw.size());
                    break;
                case TCPRSTS:
                    tcpRstRaw.append(temp, header->originalSize);
                    tcpRstStart = (const PacketMarker *) tcpRstRaw.data();
                    tcpRstEnd = (const PacketMarker *) (tcpRstRaw.data() + tcpRstRaw.size());
                    break;
                case TCPMISCANOMALIES:
                    tcpMiscAnomalyRaw.append(temp, header->originalSize);
                    tcpMiscAnomalyStart = (const PacketMarker *) tcpMiscAnomalyRaw.data();
                    tcpMiscAnomalyEnd = (const PacketMarker *) (tcpMiscAnomalyRaw.data() + tcpMiscAnomalyRaw.size());
                    break;
                case TCPDUPACKS:
                    tcpDupAckRaw.append(temp, header->originalSize);
                    tcpDupAckStart = (const PacketMarker *) tcpDupAckRaw.data();
                    tcpDupAckEnd = (const PacketMarker *) (tcpDupAckRaw.data() + tcpDupAckRaw.size());
                    break;
                case TCPSYNS:
                    tcpSynRaw.append(temp, header->originalSize);
                    tcpSynStart = (const PacketMarker *) tcpSynRaw.data();
                    tcpSynEnd = (const PacketMarker *) (tcpSynRaw.data() + tcpSynRaw.size());
                    break;
                case TCPRETRANSMISSIONS:
                    tcpRetransmissionRaw.append(temp, header->originalSize);
                    tcpRetransmissionStart = (const PacketMarker *) tcpRetransmissionRaw.data();
                    tcpRetransmissionEnd = (const PacketMarker *) (tcpRetransmissionRaw.data() + tcpRetransmissionRaw.size());
                    break;
                case SCHRODINGER:
                    fillSchrodinger(temp, header->originalSize);
                    break;
                }
                delete[] temp;
                delete[] rawStream.data; // free raw stream
            } else
                compressedFile.seekg(header->compressedSize, std::ifstream::cur); // skip and seek next chapter
        }
        filterSessions();

        // compensate 72 seconds to every timeouts, which is not done by Spin4
        for (auto i = timeoutStart; i < timeoutEnd; ++i) {
            i->marker.second += 72;
            i->session.last.second += 72;
        }
    } catch (std::exception &e) {
        logger.log("Encountered an exception: "s + e.what());
    }
}

SuperCodex::Loader::~Loader()
{
    // do nothing
}

const SuperCodex::Packet *SuperCodex::Loader::firstPacket() const
{
    return _nextPacket(packetStart);
}

const SuperCodex::Loader::BpsPpsItem *SuperCodex::Loader::firstBpsPerSession() const
{
    return _nextBpsPerSession(bpsPerSessionStart);
}

const SuperCodex::Loader::BpsPpsItem *SuperCodex::Loader::firstPpsPerSession() const
{
    return _nextPpsPerSession(ppsPerSessionStart);
}

const SuperCodex::Loader::Remarks SuperCodex::Loader::firstRemarks() const
{
    return _nextRemarks(remarksStart);
}

const SuperCodex::PacketMarker *SuperCodex::Loader::firstRtt() const
{
    return _nextRtt(rttStart);
}

const SuperCodex::Timeout *SuperCodex::Loader::firstTimeout() const
{
    return _nextTimeout(timeoutStart);
}

const SuperCodex::PacketMarker *SuperCodex::Loader::firstTcpRst() const
{
    return _nextTcpRst(tcpRstStart);
}

const SuperCodex::PacketMarker *SuperCodex::Loader::firstTcpMiscAnomaly() const
{
    return _nextTcpMiscAnomaly(tcpMiscAnomalyStart);
}

const SuperCodex::PacketMarker *SuperCodex::Loader::firstTcpSyn() const
{
    return _nextTcpSyn(tcpSynStart);
}

const SuperCodex::PacketMarker *SuperCodex::Loader::firstTcpRetransmission() const
{
    return _nextTcpRetransmission(tcpRetransmissionStart);
}

const SuperCodex::PacketMarker *SuperCodex::Loader::firstTcpDupAck() const
{
    return _nextTcpDupAck(tcpDupAckStart);
}

const SuperCodex::Packet *SuperCodex::Loader::nextPacket(const SuperCodex::Packet *packet) const
{
    return _nextPacket(++packet);
}

const SuperCodex::Loader::BpsPpsItem *SuperCodex::Loader::nextBpsPerSession(const SuperCodex::Loader::BpsPpsItem *bps) const
{
    return _nextBpsPerSession(++bps);
}

const SuperCodex::Loader::BpsPpsItem *SuperCodex::Loader::nextPpsPerSession(const SuperCodex::Loader::BpsPpsItem *pps) const
{
    return _nextPpsPerSession(++pps);
}

const SuperCodex::Loader::Remarks SuperCodex::Loader::nextRemarks(const SuperCodex::Loader::Remarks remarks) const
{
    return _nextRemarks(remarks.content + remarks.size);
}

const SuperCodex::PacketMarker *SuperCodex::Loader::nextRtt(const SuperCodex::PacketMarker *rtt) const
{
    return _nextRtt(++rtt);
}

const SuperCodex::Timeout *SuperCodex::Loader::nextTimeout(const SuperCodex::Timeout *timeout) const
{
    return _nextTimeout(++timeout);
}

const SuperCodex::PacketMarker *SuperCodex::Loader::nextTcpRst(const SuperCodex::PacketMarker *tcpRst) const
{
    return _nextTcpRst(++tcpRst);
}

const SuperCodex::PacketMarker *SuperCodex::Loader::nextTcpMiscAnomaly(const SuperCodex::PacketMarker *tcpMiscAnomaly) const
{
    return _nextTcpMiscAnomaly(++tcpMiscAnomaly);
}

const SuperCodex::PacketMarker *SuperCodex::Loader::nextTcpSyn(const SuperCodex::PacketMarker *tcpSyn) const
{
    return _nextTcpSyn(++tcpSyn);
}

const SuperCodex::PacketMarker *SuperCodex::Loader::nextTcpRetransmission(const SuperCodex::PacketMarker *tcpRetransmission) const
{
    return _nextTcpRetransmission(++tcpRetransmission);
}

const SuperCodex::PacketMarker *SuperCodex::Loader::nextTcpDupAck(const SuperCodex::PacketMarker *tcpDupAck) const
{
    return _nextTcpDupAck(++tcpDupAck);
}

const SuperCodex::Packet *SuperCodex::Loader::_nextPacket(const Packet *packet) const
{
    while (packet < packetEnd) {
        if (inDuration(packet->second) && sessions.contains(packet->sessionId))
            return packet;
        else
            packet++;
    }

    return nullptr; // index out of bound
}

const SuperCodex::Loader::BpsPpsItem *SuperCodex::Loader::_nextBpsPerSession(const BpsPpsItem *bps) const
{
    while (bps < bpsPerSessionEnd) {
        if (inDuration(bps->second) && sessions.contains(bps->sessionId))
            return bps;
        else
            bps++;
    }

    return nullptr; // index out of bound
}

const SuperCodex::Loader::BpsPpsItem *SuperCodex::Loader::_nextPpsPerSession(const BpsPpsItem *pps) const
{
    while (pps < ppsPerSessionEnd) {
        if (inDuration(pps->second) && sessions.contains(pps->sessionId))
            return pps;
        else
            pps++;
    }

    return nullptr; // index out of bound
}

const SuperCodex::Loader::Remarks SuperCodex::Loader::_nextRemarks(const char *cursor) const
{
    const Remarks *frame;
    Remarks result;
    while (cursor < remarksEnd) {
        frame = (const Remarks *) cursor;
        if (sessions.count(frame->sessionId)) {
            result = *frame;
            cursor += 12;
            result.content = cursor;
            break;
        } else
            cursor += 12 + frame->size;
    }

    return result;
}

const SuperCodex::PacketMarker *SuperCodex::Loader::_nextRtt(const PacketMarker *rtt) const
{
    while (rtt < rttEnd) {
        if (inDuration(rtt->second) && sessions.contains(rtt->sessionId))
            return rtt;
        else
            rtt++;
    }

    return nullptr; // index out of bound
}

const SuperCodex::Timeout *SuperCodex::Loader::_nextTimeout(const Timeout *timeout) const
{
    while (timeout < timeoutEnd) {
        if (inDuration(timeout->marker.second) && sessionAccepted(&timeout->session))
            return timeout;
        else
            timeout++;
    }

    return nullptr; // index out of bound
}

const SuperCodex::PacketMarker *SuperCodex::Loader::_nextTcpRst(const PacketMarker *tcpRst) const
{
    while (tcpRst < tcpRstEnd) {
        if (inDuration(tcpRst->second) && sessions.contains(tcpRst->sessionId))
            return tcpRst;
        else
            tcpRst++;
    }

    return nullptr; // index out of bound
}

const SuperCodex::PacketMarker *SuperCodex::Loader::_nextTcpMiscAnomaly(const PacketMarker *tcpMiscAnomaly) const
{
    while (tcpMiscAnomaly < tcpMiscAnomalyEnd) {
        if (inDuration(tcpMiscAnomaly->second) && sessions.contains(tcpMiscAnomaly->sessionId))
            return tcpMiscAnomaly;
        else
            tcpMiscAnomaly++;
    }

    return nullptr; // index out of bound
}

const SuperCodex::PacketMarker *SuperCodex::Loader::_nextTcpSyn(const PacketMarker *tcpSyn) const
{
    while (tcpSyn < tcpSynEnd) {
        if (inDuration(tcpSyn->second) && sessions.contains(tcpSyn->sessionId))
            return tcpSyn;
        else
            tcpSyn++;
    }

    return nullptr; // index out of bound
}

const SuperCodex::PacketMarker *SuperCodex::Loader::_nextTcpRetransmission(const PacketMarker *tcpRetransmission) const
{
    while (tcpRetransmission < tcpRetransmissionEnd) {
        if (inDuration(tcpRetransmission->second) && sessions.contains(tcpRetransmission->sessionId))
            return tcpRetransmission++;
        else
            tcpRetransmission++;
    }

    return nullptr; // index out of bound
}

const SuperCodex::PacketMarker *SuperCodex::Loader::_nextTcpDupAck(const PacketMarker *tcpDupAck) const
{
    while (tcpDupAck < tcpDupAckEnd) {
        if (inDuration(tcpDupAck->second) && sessions.contains(tcpDupAck->sessionId))
            return tcpDupAck++;
        else
            tcpDupAck++;
    }

    return nullptr; // index out of bound
}

bool SuperCodex::Loader::sessionAccepted(const SuperCodex::Session *session) const
{
    // check global exclusion
    if (!globalExclusionSingleIp.empty() && (globalExclusionSingleIp.contains(SuperCodex::destinationIp(*session)) || globalExclusionSingleIp.contains(SuperCodex::sourceIp(*session))))
        return false;
    auto ipLength = SuperCodex::ipLength(session->etherType);
    if (!globalExclusionPair.empty() && (globalExclusionPair.contains(std::string((const char *) session->ips, ipLength * 2))))
        return false;

    // completely out of target timeframe, except directed otherwise
    if (session->last.second < conditions.from || // session before lookback window
        session->first.second > conditions.to || // session after lookback window
        (conditions.cacheFrom && session->first.second >= conditions.cacheFrom && session->last.second <= conditions.cacheTo)) // session completely inside cache duration
        return false;

    // IP
    const std::string sourceIpExtracted = sourceIp(*session), destinationIpExtracted = destinationIp(*session);
    if (!conditions.allowedIps.isEmpty) {
        if (((!conditions.includeExternalTransfer && (!conditions.allowedIps.contains(destinationIpExtracted) || !conditions.allowedIps.contains(sourceIpExtracted))) || // doesn't include external transfers
             (conditions.includeExternalTransfer && !conditions.allowedIps.contains(destinationIpExtracted) && !conditions.allowedIps.contains(sourceIpExtracted)))) // include external transfers
            return false;
    }

    // ports
    if (!conditions.ports.empty() && // we're interested in certain ports only
        (!conditions.ports.contains(session->sourcePort) && !conditions.ports.contains(session->destinationPort)))
        return false;

    // payload protocol
    if (conditions.payloadProtocol && session->payloadProtocol != conditions.payloadProtocol)
        return false;

    // L7 protocol
    if (conditions.l7Protocol && session->detectedL7 != conditions.l7Protocol)
        return false;

    // Schrodinger
    if (!allowed8021qTags.empty() && !allowed8021qTags.contains(session->id))
        return false;
    if (!allowedMplsLabels.empty() && !allowedMplsLabels.contains(session->id))
        return false;

    return true;
}

void SuperCodex::Loader::filterSessions()
{
    // get a copy of currently recognized TCP services
#ifdef COMPENSATESESSIONDIRECTION
    TcpServiceManager::servicesMutex.lock_shared();
    auto services = TcpServiceManager::services;
    TcpServiceManager::servicesMutex.unlock_shared();
#endif

    auto from = conditions.from, to = conditions.to;
    bool timestampTwisted = false;
    for (Session *session = sessionCursor; session < sessionCursorEnd; ++session) {
        // check timestamp twist(this can happen because of NTP sync)
        if (session->first.second > secondEnd || session->last.second < secondStart) {
            // logger.oops("Session with twisted timestamp: "s + fileName + '(' + std::to_string(session->id) + ')' + " -> "s + std::to_string(from) + "..."s + std::to_string(session->first.second) + ".."s + std::to_string(session->last.second) + "..."s + std::to_string(to));
            timestampTwisted = true;
            continue;
        }

        // check acceptance of the session
        if (sessionAccepted(session)) {
            // compensate session direction if client-server looks reversed
#ifdef COMPENSATESESSIONDIRECTION
            if (((session->status & SuperCodex::Session::Status::HASTCPSYN) == 0) // session doesn't have SYN flag (it can be TCP, UDP, whatever......)
                || session->detectedL7 == SuperCodex::Session::NOL7DETECTED) { // no specific L7 protocol detected for this session
                // if it's TCP and source IP-port pair is already registered as server and the other side is not, swap pair
                if (session->payloadProtocol == 0x06 && services.contains(std::make_pair(SuperCodex::sourceIp(*session), session->sourcePort)) && !services.contains(std::make_pair(SuperCodex::destinationIp(*session), session->destinationPort))) {
                    SuperCodex::swapIpPortPair(*session);
                    continue;
                }

                // special rule: if the conditions has port numbers, those are treated as service ports
                const auto &ports = conditions.ports;
                if (!ports.empty() && ports.contains(session->sourcePort) && !ports.contains(session->destinationPort)) {
                    SuperCodex::swapIpPortPair(*session);
                    continue;
                }
            }
#endif
            // register session
            sessions[session->id] = session;
        }
    }
    if (timestampTwisted)
        logger.oops("There are sessions with twisted timestamp. NTP sync may have caused it."s);
}

ankerl::unordered_dense::map<uint64_t, SuperCodex::Session *> SuperCodex::Loader::allSessions()
{
    ankerl::unordered_dense::map<uint64_t, SuperCodex::Session *> result;
    for (Session *session = sessionCursor; session < sessionCursorEnd; ++session)
        result[session->id] = session;
    return result;
}

inline bool SuperCodex::Loader::inDuration(const int32_t timestamp) const
{
    if (timestamp >= secondStart && timestamp <= secondEnd) { // sometimes the timestamp can go beyond secondStart and secondEnd after system clock is adjusted (e.g. synced against NTP)
        if (conditions.cacheFrom)
            return (timestamp >= conditions.from && timestamp < conditions.cacheFrom) || (timestamp > conditions.cacheTo && timestamp <= conditions.to); // cache duration: cacheFrom <= timestamp <= cacheTo
        else
            return (timestamp >= conditions.from && timestamp <= conditions.to);
    }

    return false;
}

std::string SuperCodex::stringToHex(const std::string_view &source)
{
    std::string result;
    result.reserve(source.size() * 2);
    for (const auto &ch : source)
        result.append(hexTable[(const unsigned char) ch]);

    return result;
}

std::string SuperCodex::stringFromHex(const std::string &source)
{
    std::string result;

    try {
        if (source.size() % 2 == 0)
            for (int i = 0, iEnd = source.size(); i < iEnd; i += 2) { // convert only when size of the source is even
                result.push_back((char) static_cast<unsigned char>(std::stoi(source.substr(i, 2), nullptr, 16)));
            }
    } catch (...) {
        return std::string();
    }

    return result;
}

bool SuperCodex::Glyph::startsWith(const std::string &compareTo) const
{
    // compare size
    if (size < compareTo.size())
        return false;

    // compare memory
    return (memcmp(data, compareTo.data(), compareTo.size()) == 0);
}

unsigned int SuperCodex::conditionsId(SuperCodex::Conditions &conditions)
{
    // lookback window
    unsigned int hash = fnv32a(&conditions.to, 4, fnv32a(&conditions.from, 4));

    // IPs
    uint32_t ipSignature = conditions.allowedIps.signature();
    hash = fnv32a(&ipSignature, 4, hash);

    // ports
    for (const auto &port : conditions.ports)
        hash = fnv32a(&port, 2, hash);

    // payload protocol, status flags, Layer 7 protocol, include external transfer flag
    hash = fnv32a(conditions.includeExternalTransfer, fnv32a(conditions.l7Protocol, fnv32a(conditions.payloadProtocol, hash)));

    // optional: schrodinger
    if (!conditions.vlanQTags.empty())
        for (const auto &tag : conditions.vlanQTags)
            hash = fnv32a(&tag, 2, hash);
    if (!conditions.mplsLabels.empty())
        for (const auto &label : conditions.mplsLabels)
            hash = fnv32a(&label, 2, hash);

    return hash;
}

std::pair<uint32_t, uint32_t> SuperCodex::durationContained(const std::string &file)
{
    if (std::filesystem::file_size(file) < 8)
        return std::pair<uint32_t, uint32_t>();

    uint32_t timestamps[2];
    std::ifstream fileStream(file, std::ios::binary);
    fileStream.seekg(std::ios::beg);
    fileStream.read((char *) timestamps, 8);
    fileStream.close();
    return std::make_pair(timestamps[0], timestamps[1]);
}

void SuperCodex::Loader::addToExclusion(const std::string &condition)
{
    switch (condition.size()) {
    case 4: // IPv4, single
        globalExclusionSingleIp.insert(condition);
        break;
    case 8: // IPv4, pair
        globalExclusionPair.insert(condition); // default direction
        globalExclusionPair.insert(condition.substr(4, 4) + condition.substr(0, 4)); // reverse direction
        break;
    }
}

std::vector<const SuperCodex::Packet *> SuperCodex::Loader::allPackets()
{
    std::vector<const SuperCodex::Packet *> results;
    results.reserve((packetEnd - packetStart) / packetSize);
    auto packet = packetStart;
    while (packet < packetEnd)
        results.push_back(packet++);

    return results;
}

SuperCodex::Loader::SchrodingerSummary SuperCodex::Loader::schrodingerSummary(const std::string &file)
{
    SchrodingerSummary result;
    Logger logger("SchrodingerSummary"s);

    // check file sanity
    std::filesystem::path path(file);
    if (!std::filesystem::exists(path)) {
        logger.log("File unavailable: "s + file);
        return SchrodingerSummary{};
    }
    if (std::filesystem::file_size(path) < 8) {
        logger.log("Codex too small. File size is "s + std::to_string(std::filesystem::file_size(path)));
        return SchrodingerSummary{};
    }

    // search for SuperCodex::SCHRODINGER
    std::ifstream compressedFile(file, std::ifstream::binary);
    compressedFile.seekg(8, compressedFile.beg); // skip timestamps

    // decompress and load selected chapter
    try {
        char headerRaw[12];
        while (!compressedFile.eof()) {
            // read chapter header
            compressedFile.read(headerRaw, 12);
            if (compressedFile.gcount() != 12) {
                // show a warning message if ifstream didn't hit end of the file
                if (compressedFile.eof() && compressedFile.gcount() == 0)
                    break;
                else {
                    logger.log("Chapter header corrupt: it should be 12, but only "s + std::to_string(compressedFile.gcount()) + " bytes are read. Cancelling job. " + std::to_string(compressedFile.eof()));
                    return SchrodingerSummary{};
                }
            }
            const ChapterHeader *header = (ChapterHeader *) headerRaw;
            if (header->compressedSize == 0)
                continue;

            if (header->type & SuperCodex::SCHRODINGER) { // load Schrodinger
                // calculate position for end of the chapter
                auto chapterEnd = compressedFile.tellg();
                chapterEnd += header->compressedSize;
                while (compressedFile.tellg() < chapterEnd) {
                    compressedFile.read(headerRaw, 12);
                    const SchrodingerHeader *partHeader = (const SchrodingerHeader *) headerRaw;
                    // find Schrodinger part named "SUMMARY"
                    if (partHeader->type == SuperCodex::SCHRODINGERSUMMARY) {
                        // decompress part
                        Glyph rawStream;
                        rawStream.data = new char[partHeader->compressedSize];
                        compressedFile.read(rawStream.data, partHeader->compressedSize);
                        if (partHeader->compressedSize != compressedFile.gcount()) {
                            logger.log("Failed to read compressed data for "s + std::to_string(partHeader->type));
                            continue;
                        }
                        rawStream.size = compressedFile.gcount();
                        char *decompressed = decompress(rawStream, partHeader->compressedSize, partHeader->originalSize), *decompressedEnd = decompressed + rawStream.size, *cursor = decompressed, *partEnd;

                        // read each part in summary
                        while (cursor < decompressedEnd) {
                            // determine type and offset for the end of this type
                            const SchrodingerPart *typeInSummary = (const SchrodingerPart *) cursor;
                            cursor += 4;
                            const int32_t partSize = *(const int32_t *) cursor;
                            cursor += 4;
                            partEnd = cursor + partSize;

                            // push data
                            switch (*typeInSummary) { // SCHRODINGERSUMMARY is NOT used
                            case VLANQ:
                                while (cursor < partEnd) {
                                    result.vlanQs.push_back(*(const uint16_t *) cursor);
                                    cursor += 2;
                                }
                                break;
                            case MPLS:
                                while (cursor < partEnd) {
                                    result.mplsLabels.push_back(*(const uint16_t *) cursor);
                                    cursor += 2;
                                }
                                break;
                            default:
                                logger.log("Unknown part type: "s + std::to_string(*typeInSummary));
                                break;
                            }
                        }

                        delete[] decompressed;
                    } else
                        compressedFile.seekg(partHeader->compressedSize, std::ifstream::cur); // skip to next Schrodinger record
                }
            } else // skip to next chapter
                compressedFile.seekg(header->compressedSize, std::ifstream::cur);
        }

    } catch (std::exception &e) {
        logger.log("Exception occurred. Details: "s + e.what());
        return {};
    } catch (...) {
        logger.log("Exception occurred. Reason unknown."s);
        return {};
    }

    return result;
}

SuperCodex::Loader::SchrodingerDump SuperCodex::Loader::dumpSchrodinger(const std::string &file)
{
    SchrodingerDump result;

    Logger logger("SchrodingerDump"s);

    // check file sanity
    std::filesystem::path path(file);
    if (!std::filesystem::exists(path)) {
        logger.log("File unavailable: "s + file);
        return {};
    }
    if (std::filesystem::file_size(path) < 8) {
        logger.log("Codex too small. File size is "s + std::to_string(std::filesystem::file_size(path)));
        return {};
    }

    // search for SuperCodex::SCHRODINGER
    std::ifstream compressedFile(file, std::ifstream::binary);
    compressedFile.seekg(8, compressedFile.beg); // skip timestamps

    // decompress and load selected chapter
    try {
        char headerRaw[12];
        while (!compressedFile.eof()) {
            // read chapter header
            compressedFile.read(headerRaw, 12);
            if (compressedFile.gcount() != 12) {
                // show a warning message if ifstream didn't hit end of the file
                if (compressedFile.eof() && compressedFile.gcount() == 0)
                    break;
                else {
                    logger.log("Chapter header corrupt: it should be 12, but only "s + std::to_string(compressedFile.gcount()) + " bytes are read. Cancelling job. " + std::to_string(compressedFile.eof()));
                    return {};
                }
            }
            const ChapterHeader *header = (ChapterHeader *) headerRaw;
            if (header->compressedSize == 0)
                continue;

            if (header->type & SuperCodex::SCHRODINGER) { // load chapter Schrodinger
                // calculate position for end of the chapter
                auto chapterEnd = compressedFile.tellg();
                chapterEnd += header->compressedSize;
                while (compressedFile.tellg() < chapterEnd) {
                    compressedFile.read(headerRaw, 12);
                    const SchrodingerHeader *partHeader = (const SchrodingerHeader *) headerRaw;
                    // find Schrodinger part named "SUMMARY"
                    if (partHeader->type != SuperCodex::SCHRODINGERSUMMARY) {
                        // decompress part
                        Glyph partStream;
                        partStream.data = new char[partHeader->compressedSize];
                        compressedFile.read(partStream.data, partHeader->compressedSize);
                        if (partHeader->compressedSize != compressedFile.gcount()) {
                            logger.log("Failed to read compressed data for "s + std::to_string(partHeader->type));
                            continue;
                        }
                        partStream.size = compressedFile.gcount();
                        char *decompressed = decompress(partStream, partHeader->compressedSize, partHeader->originalSize), *decompressedEnd = decompressed + partHeader->originalSize, *decompressedCursor = decompressed;

                        // load
                        while (decompressedCursor < decompressedEnd) {
                            switch (partHeader->type) {
                            case VLANQ:
                                while (decompressedCursor < decompressedEnd) {
                                    // read header for given tag
                                    uint16_t tag = *(uint16_t *) decompressedCursor;
                                    decompressedCursor += 2;
                                    uint32_t numberOfSessions = *(uint32_t *) decompressedCursor;
                                    decompressedCursor += 4;

                                    // add sessions
                                    std::vector<uint64_t> sessionIds;
                                    sessionIds.reserve(numberOfSessions);
                                    for (int i = 0; i < numberOfSessions; ++i) {
                                        sessionIds.push_back(*(uint64_t *) decompressedCursor);
                                        decompressedCursor += 8;
                                    }
                                    result.vlanQTags.push_back(std::make_pair(tag, sessionIds));
                                }
                                break;
                            case MPLS:
                                while (decompressedCursor < decompressedEnd) {
                                    // read header for given label
                                    uint16_t label = *(uint16_t *) decompressedCursor;
                                    decompressedCursor += 2;
                                    uint32_t numberOfSessions = *(uint32_t *) decompressedCursor;
                                    decompressedCursor += 4;

                                    // add sessions
                                    std::vector<uint64_t> sessionIds;
                                    sessionIds.reserve(numberOfSessions);
                                    for (int i = 0; i < numberOfSessions; ++i) {
                                        sessionIds.push_back(*(uint64_t *) decompressedCursor);
                                        decompressedCursor += 8;
                                    }
                                    result.mplsLabels.push_back(std::make_pair(label, sessionIds));
                                }
                                break;

                            // anything else
                            default:
                                logger.log("Unknown part type: "s + std::to_string(partHeader->type));
                                break;
                            }
                        }

                        delete[] decompressed;
                    } else
                        compressedFile.seekg(partHeader->compressedSize, std::ifstream::cur); // skip to next Schrodinger record
                }
            } else // skip to next chapter
                compressedFile.seekg(header->compressedSize, std::ifstream::cur);
        }

    } catch (std::exception &e) {
        logger.log("Exception occurred. Details: "s + e.what());
        return {};
    } catch (...) {
        logger.log("Exception occurred. Reason unknown."s);
        return {};
    }

    return result;
}

void SuperCodex::Loader::fillSchrodinger(char *data, const size_t size)
{
    // no filter at all: just ignore
    if (conditions.vlanQTags.empty() && conditions.mplsLabels.empty())
        return;

    // read part(s)
    char *cursor = data, *cursorEnd = cursor + size, *decompressed, *decompressedCursor, *decompressedEnd;
    const SuperCodex::Loader::SchrodingerHeader *header;
    while (cursor < cursorEnd) {
        header = (const SuperCodex::Loader::SchrodingerHeader *) cursor;
        cursor += 12;
        if (header->type != SuperCodex::SCHRODINGERSUMMARY) {
            // decompress part data
            decompressed = decompress(Glyph{cursor, header->compressedSize}, header->compressedSize, header->originalSize);
            decompressedCursor = decompressed;
            decompressedEnd = decompressed + header->originalSize;

            // push
            switch (header->type) {
            case VLANQ:
                if (!conditions.vlanQTags.empty())
                    while (decompressedCursor < decompressedEnd) {
                        // read header for given tag
                        uint16_t tag = *(uint16_t *) decompressedCursor;
                        decompressedCursor += 2;
                        uint32_t numberOfSessions = *(uint32_t *) decompressedCursor;
                        decompressedCursor += 4;

                        // push sessions if the tag is asked
                        if (conditions.vlanQTags.contains(tag))
                            for (int i = 0; i < numberOfSessions; ++i) {
                                allowed8021qTags.insert(*(uint64_t *) decompressedCursor);
                                decompressedCursor += 8;
                            }
                        else
                            decompressedCursor += numberOfSessions * 8;
                    }
                break;
            case MPLS:
                if (!conditions.mplsLabels.empty())
                    while (decompressedCursor < decompressedEnd) {
                        // read header for given label
                        uint16_t label = *(uint16_t *) decompressedCursor;
                        decompressedCursor += 2;
                        uint32_t numberOfSessions = *(uint32_t *) decompressedCursor;
                        decompressedCursor += 4;

                        // push sessions if the tag is asked
                        if (conditions.mplsLabels.contains(label))
                            for (int i = 0; i < numberOfSessions; ++i) {
                                allowedMplsLabels.insert(*(uint64_t *) decompressedCursor);
                                decompressedCursor += 8;
                            }
                        else
                            decompressedCursor += numberOfSessions * 8;
                    }
                break;

            // anything else
            default:
                logger.log("Unknown part type: "s + std::to_string(header->type));
                break;
            }

            // free memory
            delete[] decompressed;
        }
        cursor += header->compressedSize;
    }
}
