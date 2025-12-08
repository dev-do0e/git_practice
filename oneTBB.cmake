# https://github.com/oneapi-src/oneTBB
# cmake

add_definitions("-DQT_NO_KEYWORDS")

if(WIN32)
    include_directories("C:/Components/oneTBB-2021.9.0/include")
    link_directories("C:/Components/oneTBB-2021.9.0/build/msvc_19.35_cxx_64_md_release")
    link_libraries("tbb12")
else()
    link_libraries("tbb")
endif()
