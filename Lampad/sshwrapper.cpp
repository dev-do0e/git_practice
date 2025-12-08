#include "sshwrapper.h"

#ifdef _WIN32
#define S_IRWXU 0700
#define O_CREAT _O_CREAT
#define O_WRONLY _O_WRONLY
#define O_TRUNC _O_TRUNC
#else
#include <sys/types.h>
#include <sys/stat.h>
#endif

#include <fcntl.h> // O_WRONLY
#include <iostream>
#include <chrono>
#include <thread>

using namespace std::string_literals;

SshWrapper::SshWrapper()
{
    ssh_init();

    // initialization
    lastErrorCode = SSH_OK;
    session = ssh_new();
    if (session == NULL) {
        logError();
        return;
    }
}

SshWrapper::~SshWrapper()
{
    // deactivate subsystems as needed
    if (sftpSession)
        sftp_free(sftpSession);
    if (scpSession)
        ssh_scp_free(scpSession);

    // deactivate SSH sessions
    ssh_disconnect(session);
    ssh_free(session);

    ssh_finalize();
}

bool SshWrapper::connect(const std::string &server, const int port)
{
    ssh_options_set(session, SSH_OPTIONS_HOST, server.data());
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    if (ssh_connect(session) != SSH_OK) {
        logError();
        return false;
    }

    return true;
}

bool SshWrapper::login(const std::string &username, const std::string &password)
{
    ssh_options_set(session, SSH_OPTIONS_USER, username.data());
    if (ssh_userauth_password(session, username.data(), password.data()) != SSH_AUTH_SUCCESS) {
        logError();
        return false;
    }

    // open a channel
    channel = ssh_channel_new(session);
    if (channel == NULL) {
        logError();
        return false;
    }
    if (ssh_channel_open_session(channel) != SSH_OK) {
        logError();
        return false;
    }

    return true;
}

bool SshWrapper::openInteractiveShell(const int width, const int height)
{
    // open (interactive) shell
    if (width > 0 && height > 0) {
        if (ssh_channel_request_pty(channel) != SSH_OK) {
            logError();
            return false;
        }
        if (ssh_channel_change_pty_size(channel, width, height) != SSH_OK) {
            logError();
            return false;
        }
    }
    //if(ssh_channel_request_shell(channel)!=SSH_OK) { logError(); return; } // if I call this function, application hangs

    return true;
}

std::string SshWrapper::read(const int pipe, const int timeout_ms)
{
    std::string result;
    ssize_t dataRead;
    char buffer[32768];
    do {
        dataRead = ssh_channel_read_timeout(channel, buffer, 32768, pipe, timeout_ms);
        if (dataRead == SSH_ERROR) {
            logError();
            result.append("Error occurred on reading pipe.");
            break;
        }
        result.append(buffer, dataRead);
    } while (dataRead > 0);

    return result;
}

bool SshWrapper::write(const char *message, const unsigned int messageSize)
{
    if (ssh_channel_write(channel, message, messageSize) != messageSize) {
        logError();
        return false;
    } else
        return true;
}

bool SshWrapper::execute(const char *command)
{
    if (ssh_channel_request_exec(channel, command) == SSH_ERROR) {
        logError();
        return false;
    } else
        return true;
}

sftp_file SshWrapper::prepareSftp(const std::string &destination, const bool isUpload)
{
    // remove any previous SFTP session
    if (sftpSession) {
        sftp_free(sftpSession);
        sftpSession = nullptr;
    }

    // activate SFTP subsystem and create new session
    sftpSession = sftp_new(session);
    if (sftpSession == nullptr)
        return nullptr;
    if (sftp_init(sftpSession) != SSH_OK)
        return nullptr;

    sftp_file result;
    if (isUpload)
        result = sftp_open(sftpSession, destination.data(), O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
    else
        result = sftp_open(sftpSession, destination.data(), O_RDONLY, 0);
    if (result == nullptr)
        logError();
    return result;
}

bool SshWrapper::prepareScp(const std::string &path, const long long uploadSize)
{
    // remove any previous SCP session
    if (scpSession) {
        ssh_scp_free(scpSession);
        scpSession = nullptr;
    }

    // create a SCP session
    if (uploadSize)
        scpSession = ssh_scp_new(session, SSH_SCP_WRITE, path.substr(0, path.find_last_of('/')).data());
    else
        scpSession = ssh_scp_new(session, SSH_SCP_READ, path.data());
    if (!scpSession) {
        logError();
        return false;
    }

    // initialize transfer
    if (ssh_scp_init(scpSession) != SSH_OK) {
        logError();
        return false;
    }
    if (uploadSize) { // initialize file upload
        if (ssh_scp_push_file(scpSession, path.substr(path.find_last_of('/') + 1).data(), uploadSize, S_IRWXU) != SSH_OK) {
            logError();
            return false;
        }
    } else { // initialize file download
        if (ssh_scp_pull_request(scpSession) != SSH_SCP_REQUEST_NEWFILE) {
            logError();
            return false;
        }
        if (ssh_scp_accept_request(scpSession) != SSH_OK) {
            logError();
            return false;
        }
    }

    return true;
}

long long SshWrapper::upload(std::istream &source, const long long streamSize, const long long throttlePerSecond, sftp_file remoteFile)
{
    // upload stream
    ssize_t bufferSize = 204800; // 200KB
    char *buffer = new char[bufferSize];
    long long remainingTotal = streamSize, remainingPerSecond = throttlePerSecond < remainingTotal ? throttlePerSecond : remainingTotal, bytesWritten;
    auto sleepUntil = std::chrono::high_resolution_clock::now() + std::chrono::seconds(1);
    do {
        // read data from stream to buffer
        long long bytesToSend = bufferSize < remainingPerSecond ? bufferSize : remainingPerSecond;
        source.read(buffer, bytesToSend);

        // write buffer to remote handle
        if (remoteFile) { // SFTP
            bytesWritten = sftp_write(remoteFile, buffer, bytesToSend);
            if (bytesWritten != bytesToSend) { // if bytes are NOT fully written(=error)
                logError();
                delete[] buffer;
                return 0;
            };
        } else { // SCP
            bytesWritten = ssh_scp_write(scpSession, buffer, bytesToSend);
            if (bytesWritten != SSH_OK) { // NOT OK
                logError();
                delete[] buffer;
                return 0;
            }
            bytesWritten = bytesToSend;
        }

        // calculate bytes
        remainingTotal -= bytesWritten;
        remainingPerSecond -= bytesWritten;

        // wait until next second if the transferred data hits threshold
        if (remainingPerSecond <= 0) {
            remainingPerSecond = throttlePerSecond < remainingTotal ? throttlePerSecond : remainingTotal;
            std::this_thread::sleep_until(sleepUntil);
            sleepUntil = std::chrono::high_resolution_clock::now() + std::chrono::seconds(1);
        }
    } while (remainingTotal > 0);

    // finalize
    if (remoteFile)
        sftp_close(remoteFile);
    delete[] buffer;
    return streamSize;
}

long long SshWrapper::uploadDummy(const long long dummySize, const long long throttlePerSecond, sftp_file remoteFile)
{
    // prepare for garbage data
    ssize_t bufferSize = 204800; // 200KB
    char *buffer = new char[bufferSize];

    // start loop
    long long remainingTotal = dummySize, remainingPerSecond = throttlePerSecond < remainingTotal ? throttlePerSecond : remainingTotal, bytesWritten;
    auto sleepUntil = std::chrono::high_resolution_clock::now() + std::chrono::seconds(1);
    do {
        // determine size to upload
        long long bytesToSend = bufferSize < remainingPerSecond ? bufferSize : remainingPerSecond;

        // write buffer to remote handle
        if (remoteFile) { // SFTP
            bytesWritten = sftp_write(remoteFile, buffer, bytesToSend);
            if (bytesWritten != bytesToSend) { // if bytes are NOT fully written(=error)
                logError();
                delete[] buffer;
                return 0;
            };
        } else { // SCP
            bytesWritten = ssh_scp_write(scpSession, buffer, bytesToSend);
            if (bytesWritten != SSH_OK) { // NOT OK
                logError();
                delete[] buffer;
                return 0;
            }
            bytesWritten = bytesToSend;
        }

        // calculate bytes
        remainingTotal -= bytesWritten;
        remainingPerSecond -= bytesWritten;

        // wait until next second if the transferred data hits threshold
        if (remainingPerSecond <= 0) {
            remainingPerSecond = throttlePerSecond < remainingTotal ? throttlePerSecond : remainingTotal;
            std::this_thread::sleep_until(sleepUntil);
            sleepUntil = std::chrono::high_resolution_clock::now() + std::chrono::seconds(1);
        }
    } while (remainingTotal);

    // finalize
    if (remoteFile)
        sftp_close(remoteFile);
    delete[] buffer;
    return dummySize;
}

long long SshWrapper::download(const long long throttlePerSecond, sftp_file remoteHandle, std::ostream *localStore)
{
    // download file via buffer
    ssize_t bufferSize = 204800; // 200KB
    char *writeBuffer = new char[bufferSize];
    long long remainingPerSecond = throttlePerSecond, receivedTotal = 0, bytesRead;
    auto sleepUntil = std::chrono::high_resolution_clock::now() + std::chrono::seconds(1);
    do {
        // read from remote handle
        auto sizeToRead = bufferSize < throttlePerSecond ? bufferSize : throttlePerSecond;
        if (remoteHandle) {
            bytesRead = sftp_read(remoteHandle, writeBuffer, sizeToRead);
            if (bytesRead < 0) {
                logError();
                return 0;
            }
        } else {
            // check whether the remote side hit EOF for given file
            auto pullResult = ssh_scp_pull_request(scpSession);
            if (pullResult == SSH_SCP_REQUEST_EOF)
                break;
            bytesRead = ssh_scp_read(scpSession, writeBuffer, sizeToRead);
            if (bytesRead < 0) {
                logError();
                return 0;
            }
        }

        // calculate bytes and optionally save data to file
        remainingPerSecond -= bytesRead;
        receivedTotal += bytesRead;
        if (localStore)
            localStore->write(writeBuffer, bytesRead);

        // throttle handling(per second)
        if (remainingPerSecond <= 0) {
            remainingPerSecond = throttlePerSecond;
            std::this_thread::sleep_until(sleepUntil);
            sleepUntil = std::chrono::high_resolution_clock::now() + std::chrono::seconds(1);
        }
    } while (bytesRead > 0);

    // finalize
    if (remoteHandle)
        sftp_close(remoteHandle);
    return receivedTotal;
}

void SshWrapper::logError()
{
    lastErrorCode = ssh_get_error_code(session);
    lastError = ssh_get_error(session);
    // std::cerr << "ERROR: " << lastErrorCode << ' ' << lastError << std::endl;
}