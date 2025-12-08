# https://lz4.github.io/lz4/
# for MSVC++ only solution for VS2017(v141) is provided
# msbuild lz4.sln -p:Configuration=Release -p:PlatformToolset=v142
# cmake is also provided at /build/cmake
# msys2
# CC=gcc make

if(WIN32)
    include_directories("C:/Components/lz4-1.9.4/lib")
    link_directories("C:/Components/lz4-1.9.4/build")
endif()
link_libraries("lz4")