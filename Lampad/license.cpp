#include "license.h"
#include "supercodex.h"
#include <iomanip>
#include <iostream>
#include <sstream>

// MAC address enumeration
#ifdef __linux__
#include <ifaddrs.h>
#include <netpacket/packet.h>
#else
#include <malloc.h>
#include <winsock2.h>

#include <iphlpapi.h> // this must come after winsock2.h
#pragma comment(lib, "IPHLPAPI.lib")
#endif

using namespace std::string_literals;

std::string coreLicenseKeyFull(const nlohmann::json &input)
{
    // extract components from JSON input
    std::string country = input["country"s].get<std::string>(), expiration = input["expiration"s].get<std::string>(), macs = input["macs"].get<std::string>();

    // parse throttling
    uint64_t throttle = 124800000; // default: 1Gbps
    const auto &throttleRaw = input.at("throttle"s);
    if (throttleRaw.is_number()) // throttle is raw number
        throttle = throttleRaw.get<uint64_t>();
    else { // throttle should be Gbps description
        const std::string description = throttleRaw.get<std::string>();
        if (description == "1G"s)
            throttle = 124800000;
        else if (description == "5G"s)
            throttle = 624000000;
        else if (description == "10G"s)
            throttle = 1248000000;
        else if (description == "25G"s)
            throttle = 3120000000;
        else if (description == "40G"s)
            throttle = 4992000000;
        else
            return "WARNING: CAN'T PARSE THROTTLE. It should be raw number or one of the following STRING values: 1G / 5G / 10G / 25G / 40G.";
    }

    // make sure that country code and MAC address(es) are all uppercases
    for (auto &c : country)
        c = toupper(c);
    adjustMacAddressRepresentation(macs);

    // build tail and return result
    std::string tail = country + '|' + expiration + '|' + std::to_string(throttle) + '|' + macs;
    return coreLicenseKey(tail) + '|' + tail;
}

std::string coreLicenseKey(const std::string &tail)
{
    std::string input(tail);
    input.append(" this shall be U+03B1 and U+03A9 for the time being, but who knows? :P"s);
    std::string digest = SuperCodex::stringToHex(buildDigest(input, EVP_sha512()));
    for (auto &c : digest)
        c = toupper(c);

    return digest;
}

bool isValidCoreLicense(const std::string &licenseKey)
{
    // split actual key and tail
    size_t firstSeparator = licenseKey.find('|');
    if (firstSeparator == std::string::npos)
        return false;
    std::string key = licenseKey.substr(0, firstSeparator), tail = licenseKey.substr(firstSeparator + 1);

    // check license integrity
    if (key != coreLicenseKey(tail))
        return false;
    if (!containsAllMacs(splitPipes(tail).back()))
        return false;

    // check license validity against current clock
    try { // std::stoi() can faif if it doesn't have anything
        struct tm expirationRaw;
        expirationRaw.tm_year = std::stoi(tail.substr(3, 4)) - 1900;
        expirationRaw.tm_mon = std::stoi(tail.substr(8, 2)) - 1;
        expirationRaw.tm_mday = std::stoi(tail.substr(11, 2));
        expirationRaw.tm_hour = 23;
        expirationRaw.tm_min = 59;
        expirationRaw.tm_sec = 59;
        expirationRaw.tm_isdst = 0;

        return time(nullptr) < mktime(&expirationRaw);
    } catch (...) {
        return false;
    }
}

std::string activeMonitorsLicenseKey(const std::string macAddress, const uint32_t allowedUnits)
{
    std::string input = macAddress + "Your eyes are broadened with limited senses"s + std::string((const char *) &allowedUnits, 4);
    std::string digest = SuperCodex::stringToHex(buildDigest(input, EVP_sha512()));
    for (auto &c : digest)
        c = toupper(c);

    return digest + '|' + std::to_string(allowedUnits);
}

std::string kurabitLicenseKey(const std::string macAddress)
{
    std::string input = macAddress + "You want to manually control all by yourself?"s;
    std::string digest = SuperCodex::stringToHex(buildDigest(input, EVP_sha512()));
    for (auto &c : digest)
        c = toupper(c);

    return digest;
}

std::string spin7PasswordHashed(const std::string &username, const std::string &password)
{
    std::string digest = buildDigest(username + "the least protection"s + password, EVP_sha3_256());
    return SuperCodex::stringToHex(digest);
}

std::string spin7RoleHashed(const std::string &username, const std::string &hashedPassword, char role)
{
    std::string digest = buildDigest(username + "we tried to protect"s + hashedPassword + role, EVP_sha3_256());
    return SuperCodex::stringToHex(digest);
}

char spin7Role(const std::string &username, const std::string &hashedPassword, const std::string &hashedRole)
{
    if (hashedRole == spin7RoleHashed(username, hashedPassword, '0'))
        return '0';
    else if (hashedRole == spin7RoleHashed(username, hashedPassword, '1'))
        return '1';
    else
        return '\0';
}

std::vector<std::pair<std::string, std::string>> networkInterfaces()
{
    // prepare for containter to store result
    std::vector<std::pair<std::string, std::string>> devices;

#ifdef __linux__
    struct ifaddrs *ifaddr = nullptr, *ifa = nullptr;
    int i = 0;

    if (getifaddrs(&ifaddr) == -1)
        return devices;
    else {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET)) {
                // build human readable physical address(we expect MAC address)
                std::stringstream physicalAddressStream;
                struct sockaddr_ll *s = (struct sockaddr_ll *) ifa->ifa_addr;
                for (int i = 0, iEnd = s->sll_halen - 1; i < iEnd; ++i)
                    physicalAddressStream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(s->sll_addr[i]) << ':';
                physicalAddressStream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(s->sll_addr[s->sll_halen - 1]);

                devices.push_back(std::make_pair(std::string(ifa->ifa_name), physicalAddressStream.str()));
            }
        }
        freeifaddrs(ifaddr);
    }
#else // Windows
    // initialize variables
    DWORD errorCode = 0;
    PIP_ADAPTER_ADDRESSES adapters = nullptr;
    ULONG adapterBufferSize = 1048576; // 1024*1024=1MB

    // allocate buffer
    adapters = (IP_ADAPTER_ADDRESSES *) malloc(adapterBufferSize);
    if (adapters == nullptr) {
        printf("Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
        return devices;
    }

    // get address information
    errorCode = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &adapterBufferSize);
    if (errorCode == ERROR_SUCCESS) {
        for (; adapters->Next; adapters = adapters->Next)
            if (adapters->PhysicalAddressLength) { // successfully received interface information
                // build human readable physical address(we expect MAC address)
                std::stringstream physicalAddressStream;
                for (int i = 0, iEnd = adapters->PhysicalAddressLength - 1; i < iEnd; ++i)
                    physicalAddressStream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(adapters->PhysicalAddress[i]) << ':';
                physicalAddressStream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(adapters->PhysicalAddress[adapters->PhysicalAddressLength - 1]);
                devices.push_back(std::make_pair(std::string(adapters->AdapterName), physicalAddressStream.str())); // maybe we can use adapters->FriendlyName but I can't handle well PWCHAR with std::wcout (no output at all)
            }
    }

    // finalize
    // free(adapters); // by doing this Windows Spin4 crashes. And I have no idea why
#endif

    // return result
    return devices;
}

void adjustMacAddressRepresentation(std::string &macs)
{
    for (auto &c : macs) {
        if (c == '-')
            c = ':'; // on Windows dash is used instead to separate each MAC address byte
        else
            c = toupper(c);
    }
}

std::string buildDigest(const std::string &input, const EVP_MD *md)
{
    // initialize variables
    EVP_MD_CTX *context;
    std::string result;

    // prepare for context
    context = EVP_MD_CTX_new();
    if (!context)
        return result;
    if (EVP_DigestInit_ex(context, md, nullptr) != 1)
        return result;
    if (EVP_DigestUpdate(context, input.data(), input.size()) != 1)
        return result;

    // build digest
    result.resize(EVP_MD_size(md));
    unsigned int size;
    EVP_DigestFinal_ex(context, (unsigned char *) &result[0], &size);

    // finalize
    EVP_MD_CTX_free(context);
    return result;
}

std::vector<std::string> splitPipes(const std::string &piped)
{
    std::vector<std::string> result;
    std::istringstream splitter(piped);
    for (std::string line; std::getline(splitter, line, '|');)
        result.push_back(line);

    return result;
}

bool containsAllMacs(const std::string &macAddresses)
{
    const auto deviceMacs = networkInterfaces();
    std::istringstream splitter(macAddresses);
    for (std::string mac; std::getline(splitter, mac, ' ');) {
        bool foundMac = false;
        for (const auto &deviceMac : deviceMacs)
            if (deviceMac.second == mac) {
                foundMac = true;
                break;
            }
        if (!foundMac)
            return false;
    }

    return true;
}
