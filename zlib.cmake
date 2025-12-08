# http://www.zlib.net/
# change compiler to clang-cl in win32\Makefile.msc
# mingw32-make -s -j16 -f win32\Makefile.gcc

if(WIN32)
        include_directories("C:/Components/zlib-1.2.13")
	link_directories("C:/Components/zlib-1.2.13")
	link_libraries("zlib")
else()
	link_libraries("z")
endif()
