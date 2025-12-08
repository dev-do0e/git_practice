# https://github.com/civetweb/civetweb
# no compilation

# civetweb 루트 경로를 캐시 변수로 노출 (필요하면 -D로 덮어쓰기)
if (WIN32)
    set(CIVETWEB_ROOT "C:/Components/civetweb-1.16" CACHE PATH "Path to civetweb root")
else()
    set(CIVETWEB_ROOT "/Components/civetweb-1.16" CACHE PATH "Path to civetweb root")
endif()

# include / sources 를 모두 CIVETWEB_ROOT 기준으로
target_include_directories(${PROJECT_NAME} PRIVATE
    "${CIVETWEB_ROOT}/include"
)

target_sources(${PROJECT_NAME} PRIVATE
    "${CIVETWEB_ROOT}/src/civetweb.c"
)

# 전역 add_definitions 대신 타겟 한정 매크로 권장
target_compile_definitions(${PROJECT_NAME} PRIVATE
    OPENSSL_API_1_1
    SSL_ALREADY_INITIALIZED
)

#if(WIN32)
#       include_directories("C:/Components/civetweb-1.16/include")
#else()
#       include_directories("/Components/civetweb-1.16/include")
#endif()

#target_sources(${PROJECT_NAME}
#    PRIVATE
#    /Components/civetweb-1.16/src/civetweb.c
#   )
#add_definitions("-DOPENSSL_API_1_1")
#add_definitions("-DSSL_ALREADY_INITIALIZED")
