# https://github.com/ibireme/yyjson
# no compilation

# yyjson 경로를 캐시 변수로 노출 (C/D 어디든 -D로 덮어쓰기 가능)
if (WIN32)
    set(YYJSON_ROOT "C:/Components/yyjson-0.11.1" CACHE PATH "Path to yyjson root")
else()
    set(YYJSON_ROOT "/Components/yyjson-0.11.1" CACHE PATH "Path to yyjson root")
endif()

# 포함/소스 경로를 모두 YYJSON_ROOT 기준으로
target_include_directories(${PROJECT_NAME} PRIVATE
    "${YYJSON_ROOT}/src"
)

target_sources(${PROJECT_NAME} PRIVATE
    "${YYJSON_ROOT}/src/yyjson.c"
)


#if(WIN32)
#        include_directories("C:/Components/yyjson-0.11.1/src")
#else()
#        include_directories("/Components/yyjson-0.11.1/src")
#endif()

#target_sources(${PROJECT_NAME}
#    PRIVATE
#   /Components/yyjson-0.11.1/src/yyjson.c
#   )
