# https://www.openssl.org/
# msys2
# ./Configure zlib --with-zlib-include="/c/Components/zlib" --with-zlib-lib="/c/Components/zlib" mingw64
# after ./Configure edit Makefile to change compiler to clang
# make -s

if(WIN32)
	include_directories("C:/Components/openssl-1.1.1t/include")
	link_directories("C:/Components/openssl-1.1.1t")
	link_libraries("libcrypto_static" "libssl_static" "ws2_32" "gdi32")
else()
	link_libraries("crypto" "ssl")
endif()

#include(zlib.cmake)
