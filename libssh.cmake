# https://www.libssh.org/
# cmake
# OPENSSL_ROOT_DIR
# OPENSSL_INCLUDE_DIR

if(WIN32)
        include_directories("C:/Components/libssh-0.10.6/include" "C:/Components/libssh-0.10.6/build/include")
        link_directories("C:/Components/libssh-0.10.6/build/src")
endif()

link_libraries("ssh")

if(WIN32)
	link_libraries("gdi32")
endif()
