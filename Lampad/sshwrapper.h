#ifndef SSH2INTERFACE_H
#define SSH2INTERFACE_H

#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <string>
#include <iostream>
#include <functional>

class SshWrapper
{
public:
    // constructor and destructor
    SshWrapper();
    ~SshWrapper();

    // connect and login
    bool connect(const std::string &server, const int port);
    bool login(const std::string &username, const std::string &password);

    // SSH shell
    bool openInteractiveShell(const int width, const int height);
    // read functions: read until there's nothing more to read
    std::string read(const int pipe, const int timeout_ms); // pipe: 0 for stdout, 1 for stderr
    // write and execute
    bool write(const char *message, const unsigned int messageSize);
    bool execute(const char *command);

    // file transfer subsystem activation
    sftp_file prepareSftp(const std::string &destination, const bool isUpload);
    bool prepareScp(const std::string &path, const long long uploadSize);
    long long upload(std::istream &source, const long long streamSize, const long long throttlePerSecond, sftp_file remoteFile = nullptr);
    long long uploadDummy(const long long dummySize, const long long throttlePerSecond, sftp_file remoteFile = nullptr); // upload garbage value in RAM. :P
    long long download(const long long throttlePerSecond, sftp_file remoteHandle = nullptr, std::ostream *localStore = nullptr); // set localStore as nullptr to make it dummy(download but don't save)

    // error log
    int lastErrorCode;
    std::string lastError;

private:
    // SSH control
    ssh_session session;
    ssh_channel channel;

    // file transfer subsystems: SCP & SFTP
    sftp_session sftpSession = nullptr;
    ssh_scp scpSession = nullptr;
    std::function<ssize_t()> transferStream;

    void logError();
};

#endif // SSH2INTERFACE_H
