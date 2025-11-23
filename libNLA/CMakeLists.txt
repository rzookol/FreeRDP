cmake_minimum_required(VERSION 3.13)
project(libnla C)

add_library(libnla STATIC
    src/nla.c
    src/credssp_auth.c
)

target_link_libraries(libnla PUBLIC
    winpr
)

target_compile_definitions(libnla PUBLIC WITH_LIBNLA)

target_include_directories(libnla PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../winpr/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../libfreerdp/core>
)

target_compile_features(libnla PUBLIC c_std_99)

install(TARGETS libnla
        ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
