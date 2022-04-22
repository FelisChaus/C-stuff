cmake_minimum_required(VERSION 3.22.0)

include(CMakePrintHelpers)

set(APP_VERSION_MAJOR 0)
set(APP_VERSION_MINOR 0)
set(APP_VERSION_PATCH 1)
set(APP_VERSION ${APP_VERSION_MAJOR}.${APP_VERSION_MINOR}.${APP_VERSION_PATCH})

project(OPEN_SSL_TRAINING VERSION ${APP_VERSION} LANGUAGES C CXX)

message("CMAKE_SYSTEM_NAME=" ${CMAKE_SYSTEM_NAME})
#[==[
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake -DCMAKE_BUILD_TYPE=Release ..
#]==]
message("CMAKE_BUILD_TYPE=" ${CMAKE_BUILD_TYPE})
#[==[
cmake -G "Unix Makefiles" ..
#]==]
message("CMAKE_GENERATOR=" ${CMAKE_GENERATOR})
#[==[
cmare read-only variables
#]==]
message("CMAKE_SOURCE_DIR=" ${CMAKE_SOURCE_DIR})
message("CMAKE_BINARY_DIR=" ${CMAKE_BINARY_DIR})
message("CMAKE_CURRENT_SOURCE_DIR=" ${CMAKE_CURRENT_SOURCE_DIR})
message("CMAKE_CURRENT_BINARY_DIR=" ${CMAKE_BINARY_DIR})

cmake_print_variables(CMAKE_HOST_SYSTEM_NAME)
cmake_print_variables(CMAKE_SYSTEM_NAME)
cmake_print_variables(CMAKE_CXX_COMPILER)

#[==[
Find OpenSSL library from brew setup.
OPENSSL_ROOT_DIR must be set to the root of distributive.
Note: see cmake/version/share/cmake/Modules/Find*.cmake for particular implementation details.
#]==]
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(OPENSSL_ROOT_DIR $ENV{HOMEBREW_PREFIX}/opt/openssl)
    execute_process(COMMAND brew --prefix openssl@1.1 OUTPUT_VARIABLE o1)
    message("homebrew_openssl@1.1=" ${o1})
    execute_process(COMMAND brew --prefix openssl@3 OUTPUT_VARIABLE o2)
    message("homebrew_openssl@3=" ${o2})
endif()
find_package(OpenSSL REQUIRED)
#[==[ 
Instead of 
get_property(var TARGET OpenSSL::SSL PROPERTY LOCATION)
#]==]
cmake_print_variables(OPENSSL_VERSION)
cmake_print_properties(TARGETS OpenSSL::SSL PROPERTIES 
    LOCATION 
    INTERFACE_INCLUDE_DIRECTORIES
    IMPORTED_LINK_INTERFACE_LANGUAGES
)
cmake_print_properties(TARGETS OpenSSL::Crypto PROPERTIES 
    LOCATION 
    INTERFACE_INCLUDE_DIRECTORIES
    IMPORTED_LINK_INTERFACE_LANGUAGES
)

#[==[
Find Xerces-C library from brew setup.
#]==]
find_package(XercesC REQUIRED)
cmake_print_variables(XercesC_VERSION)
cmake_print_properties(TARGETS XercesC::XercesC PROPERTIES 
    LOCATION 
    INTERFACE_INCLUDE_DIRECTORIES
    IMPORTED_LINK_INTERFACE_LANGUAGES
)

add_executable(tcpsrv 
    tcpsrv.cpp
    getlistener.cpp
)
target_compile_definitions(tcpsrv PRIVATE 
    APP_VERSION="${APP_VERSION}"
)
target_compile_features(tcpsrv PRIVATE cxx_std_20)
target_link_libraries(tcpsrv PRIVATE 
    OpenSSL::SSL
    XercesC::XercesC
)
set_target_properties(tcpsrv PROPERTIES OUTPUT_NAME tcpsrv1)

add_executable(tlsclient 
    tlsclient.cpp
)
target_compile_definitions(tlsclient PRIVATE 
    APP_VERSION="${APP_VERSION}"
)
target_compile_features(tlsclient PRIVATE cxx_std_20)
target_link_libraries(tlsclient PRIVATE 
    OpenSSL::SSL
    XercesC::XercesC
)
set_target_properties(tlsclient PROPERTIES OUTPUT_NAME tlsclient1)

add_executable(tlssrv
    tlssrv.cpp
    getlistener.cpp
)
target_compile_definitions(tlssrv PRIVATE 
    APP_VERSION="${APP_VERSION}"
    CMAKE_CURRENT_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
)
target_compile_features(tlssrv PRIVATE cxx_std_20)
target_link_libraries(tlssrv PRIVATE 
    OpenSSL::SSL
    XercesC::XercesC
)
set_target_properties(tlssrv PROPERTIES OUTPUT_NAME tlssrv1)

#[==[
# Print out compiler features.
foreach(entry ${CMAKE_CXX_COMPILE_FEATURES})
    message(${entry})
endforeach()
#]==]