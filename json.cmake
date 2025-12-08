# https://github.com/nlohmann/json
# header only

if(WIN32)
	include_directories("C:/Components/json-3.12.0/single_include")
else()
        include_directories("/Components/json-3.12.0/single_include")
endif()
