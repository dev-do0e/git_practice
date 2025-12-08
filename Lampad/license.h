#ifndef LICENSE_H
#define LICENSE_H

#include <openssl/evp.h>
#include <nlohmann/json.hpp>

#include <string>
#include <utility>
#include <vector>

// license key generator: core
std::string coreLicenseKeyFull(const nlohmann::json &input);
std::string coreLicenseKey(const std::string &tail);
bool isValidCoreLicense(const std::string &licenseKey);

// license key generator: optional
std::string activeMonitorsLicenseKey(const std::string macAddress, const uint32_t allowedUnits);
std::string kurabitLicenseKey(const std::string macAddress);;

// Spin7 specific keys
std::string spin7PasswordHashed(const std::string &username, const std::string &password);
std::string spin7RoleHashed(const std::string &username, const std::string &hashedPassword, char role);
char spin7Role(const std::string &username, const std::string &hashedPassword, const std::string &hashedRole);

// utilities
void adjustMacAddressRepresentation(std::string &macs);
std::vector<std::string> splitPipes(const std::string &piped);
bool containsAllMacs(const std::string &macAddresses);
std::vector<std::pair<std::string, std::string>> networkInterfaces(); // NIC name + MAC address in AA:BB:CC:DD:EE:FF style
std::string buildDigest(const std::string &stream, const EVP_MD *md);

#endif // LICENSE_H
