#ifndef CURLWRAPPER_H
#define CURLWRAPPER_H

#include <curl/curl.h>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace std::string_literals;

class CurlWrapper
{
public:
    // constructor and destructor
    CurlWrapper();
    ~CurlWrapper();

    // configuring CURL
    void setHttpBasicAuthentication(const std::string &username, const std::string &password);
    void initializeCookieJar(const std::string &cookieJarFile);
    void setCustomOption(const CURLoption option, void *value);
    void setCustomOption(const CURLoption option, long value);
    void reset();

    // configure custom HTTP headers
    void addDisableExpect100();
    void resetCustomHeaders();
    void addCusomHeader(const std::string &header); // "header" should contain full line, e.g. "Content-Type: application/octet-stream"

    // transfer
    void uploadHttp(const std::string &url, const std::string &buffer, std::ostream *respBuffer = nullptr, const bool viaFile = false, const bool isPost=true);
    void getHttp(const std::string &url, std::ostream *writeStream);

    // result
    CURLcode result = CURLE_OK;
    long httpStatusCode = 0; // containing last connection result
    const char *errorString();

private:
    // CURL management
    CURL *curl;
    std::string cookieJarPath;
    curl_slist *httpHeaders = nullptr; // custom HTTP headers

    // callbacks for upload and download
    static size_t downloadCallback(char *buffer, size_t size, size_t nmemb, std::ostream *stream);
    static size_t uploadCallback(char *buffer, size_t size, size_t nitems, std::istream *stream);
};

#endif // CURLWRAPPER_H
