# https://curl.se/
# cmd
# set ZLIB_PATH=C:\Components\zlib
# rem set OPENSSL_PATH=C:\Components\openssl
# mingw32-make -s -j16 mingw32-winssl-zlib

# change winbuild\MakefileBuild.vc
# jom doesn't work due to some macros
# nmake /f Makefile.vc mode=static WITH_ZLIB=static ZLIB_PATH=C:\Components\zlib-1.2.11

# cmake
# use Windows TLS instead of OpenSSL: CURL_USE_SCHANNEL=true
# build static library: BUILD_SHARED_LIBS=false

if(WIN32)
    add_definitions("-DCURL_STATICLIB")
    include_directories("C:/Components/curl-8.0.1/installed/include")
    link_directories("C:/Components/curl-8.0.1/installed/lib")
    link_libraries("libcurl_imp" "ws2_32" "advapi32" "wldap32" "crypt32" "Normaliz")
else()
    link_libraries("curl")
endif()
