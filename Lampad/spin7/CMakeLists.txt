cmake_minimum_required(VERSION 3.16.0)
add_definitions("-DCOMPENSATESESSIONDIRECTION")
#add_definitions("-DRANDOMIZELATESTX")

if(WIN32)
    add_definitions("-DNOMINMAX") # disable WinDef.h min() and max() macros
    link_libraries("iphlpapi" "ws2_32") # to use ntohs() and ntohl() in Windows
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:10485760")
elseif(UNIX)
    add_definitions("-DNO_SSL_DL") # link against system OpenSSL if enabled
    add_definitions("-DTBB_PREVIEW_CONCURRENT_ORDERED_CONTAINERS") # Ubuntu only - to use tbb::concurrent_set
    include(../../openssl.cmake) # for OpenSSL support
    link_libraries("dl" "pthread" "stdc++fs")
endif()

project(spin7 VERSION 0.1)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)

include(../../json.cmake) # for general settings
include(../../lz4.cmake)
include(../../static.cmake)
include(../../unordered_dense.cmake)
include(../../libcurl.cmake)
include(../../zlib.cmake)
include(../../oneTBB.cmake)
include(../../openssl.cmake)
include(../../sqlite.cmake)
include(../../libssh.cmake)

add_executable(${PROJECT_NAME} "main.cpp")
include(../../civetweb.cmake)
include(../../yyjson.cmake)

target_sources(${PROJECT_NAME}
    PRIVATE
    civet7.hpp civet7.cpp
    user.h user.cpp
    codexindex.h codexindex.cpp
    datafeed.h datafeed.cpp
    datafeedrefinery.h datafeedrefinery.cpp
    feedrefinerabstract.h feedrefinerabstract.cpp
    feedrefinerbasic.h feedrefinerbasic.cpp
    feedrefinertopn.h feedrefinertopn.cpp
    feedrefinermain.h feedrefinermain.cpp
    feedrefinertrackers.h feedrefinertrackers.cpp
    feedrefinerspecialized.h feedrefinerspecialized.cpp
    tcpservicemanager.h tcpservicemanager.cpp
    supercache.h supercache.cpp
    svcd.h svcd.cpp
    supercache0.h supercache0.cpp
    event7.h event7.cpp
    paradox.h paradox.cpp
    paranoia.h paranoia.cpp
    reportmanager.h reportmanager.cpp
    subsystems.h subsystems.cpp
    miscellany.h miscellany.cpp
    ailampadxanomaly.h ailampadxanomaly.cpp
    ../featherlite.h ../featherlite.cpp
    ../loghandler.h ../loghandler.cpp
    ../supercodex.h ../supercodex.cpp
    ../fnvhash.h ../fnvhash.cpp
    ../license.h ../license.cpp
    ../sshwrapper.h ../sshwrapper.cpp
    ../events.h
)
