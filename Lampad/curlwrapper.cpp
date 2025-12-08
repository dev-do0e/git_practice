#include "curlwrapper.h"
#include <memory.h>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <sstream>

using namespace std::string_literals;

CurlWrapper::CurlWrapper()
{
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
}

CurlWrapper::~CurlWrapper()
{
    if (httpHeaders)
        curl_slist_free_all(httpHeaders);
    curl_easy_cleanup(curl);
    // curl_global_cleanup();
}

void CurlWrapper::setHttpBasicAuthentication(const std::string &username, const std::string &password)
{
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_USERNAME, username.data());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, password.data());
}

void CurlWrapper::initializeCookieJar(const std::string &cookieJarFile)
{
    cookieJarPath = cookieJarFile;

    // disable cookie if file path is empty
    if (cookieJarPath.empty())
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, nullptr);
    else {
        // create new empty file if there's cookie file does not exist
        if (!std::filesystem::exists(cookieJarPath))
            std::ofstream emptyFile(cookieJarPath, std::ios::binary);
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, cookieJarPath.c_str());
    }
}

void CurlWrapper::setCustomOption(const CURLoption option, void *value)
{
    curl_easy_setopt(curl, option, value);
}

void CurlWrapper::setCustomOption(const CURLoption option, long value)
{
    curl_easy_setopt(curl, option, value);
}

void CurlWrapper::reset()
{
    curl_easy_reset(curl);
}

void CurlWrapper::addDisableExpect100()
{
    curl_slist_append(httpHeaders, "Expect:");
}

void CurlWrapper::resetCustomHeaders()
{
    if (httpHeaders) {
        curl_slist_free_all(httpHeaders);
        httpHeaders = nullptr;
    }
}

void CurlWrapper::addCusomHeader(const std::string &header)
{
    httpHeaders = curl_slist_append(httpHeaders, header.data());
}

void CurlWrapper::uploadHttp(const std::string &url, const std::string &buffer, std::ostream *respBuffer, const bool viaFile, const bool isPost)
{
    // set HTTP method
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    if (isPost) { // HTTP POST
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, nullptr);
    } else // HTTP PUT
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    // set basic options: cookies, custom HTTP headers, ......
    if (!cookieJarPath.empty())
        curl_easy_setopt(curl, CURLOPT_COOKIEJAR, cookieJarPath.c_str()); // cookie jar
    if (httpHeaders)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, httpHeaders);

    // determine data reader
    std::istream *readStream;
    if (viaFile) { // buffer is actually file name
        readStream = new std::ifstream(buffer, std::ios::binary);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(std::filesystem::file_size(buffer)));
    } else { // buffer is request body itself
        readStream = new std::istringstream(buffer);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(buffer.size()));
    }
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, uploadCallback);
    curl_easy_setopt(curl, CURLOPT_READDATA, readStream);

    // set buffer for response
    if (respBuffer) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, downloadCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, respBuffer);
    }

    // start upload
    result = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpStatusCode); // set HTTP status code

    // finalize
    delete readStream;
}

void CurlWrapper::getHttp(const std::string &url, std::ostream *writeStream)
{
    curl_easy_setopt(curl, CURLOPT_URL, url.data());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    // set basic options: cookies, custom HTTP headers, ......
    if (!cookieJarPath.empty())
        curl_easy_setopt(curl, CURLOPT_COOKIEJAR, cookieJarPath.c_str()); // cookie jar
    if (httpHeaders)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, httpHeaders);

    // determine data writer
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, downloadCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, writeStream);

    // start download
    result = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpStatusCode); // read HTTP status code
}

const char *CurlWrapper::errorString()
{
    return curl_easy_strerror(result);
}

size_t CurlWrapper::downloadCallback(char *buffer, size_t size, size_t nmemb, std::ostream *stream)
{
    size_t bytesWritten = size * nmemb;
    stream->write(buffer, bytesWritten);
    return bytesWritten;
}

size_t CurlWrapper::uploadCallback(char *buffer, size_t size, size_t nitems, std::istream *stream)
{
    if (!stream || stream->eof() || stream->fail())
        return 0;

    stream->read(buffer, size * nitems);
    return stream->gcount();
}
