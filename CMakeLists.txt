cmake_minimum_required(VERSION 3.22.0)

set(APP_VERSION_MAJOR 0)
set(APP_VERSION_MINOR 0)
set(APP_VERSION_PATCH 1)
set(APP_VERSION ${APP_VERSION_MAJOR}.${APP_VERSION_MINOR}.${APP_VERSION_PATCH})

project(OPEN_SSL_TRAINING VERSION ${APP_VERSION} LANGUAGES C CXX)

message("CMAKE_SYSTEM_NAME=" ${CMAKE_SYSTEM_NAME})
message("CMAKE_BUILD_TYPE=" ${CMAKE_BUILD_TYPE})
message("CMAKE_GENERATOR=" ${CMAKE_GENERATOR})
message("CMAKE_GENERATOR_PLATFORM=" ${CMAKE_GENERATOR_PLATFORM})
message("CMAKE_GENERATOR_TOOLSET=" ${CMAKE_GENERATOR_TOOLSET})
message("CMAKE_GENERATOR_INSTANCE=" ${CMAKE_GENERATOR_INSTANCE})

#
# Find OpenSSL library from brew setup.
#
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
    message("OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}")
endif()
find_package(OpenSSL REQUIRED)
message("OPENSSL_FOUND=" ${OPENSSL_FOUND})
message("OPENSSL_FOUND=${OPENSSL_FOUND}")
message("OPENSSL_INCLUDE_DIR=" ${OPENSSL_INCLUDE_DIR})
message("OPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}")
message("OPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}")
message("OPENSSL_SSL_LIBRARY=${OPENSSL_SSL_LIBRARY}")
message("OPENSSL_SSL_LIBRARIES=${OPENSSL_SSL_LIBRARIES}")
message("OPENSSL_LIBRARIES=${OPENSSL_LIBRARIES}")
message("OPENSSL_VERSION=${OPENSSL_VERSION}")
message("OPENSSL_APPLINK_SOURCE=${OPENSSL_APPLINK_SOURCE}")
get_property(V1 TARGET OpenSSL::SSL PROPERTY LOCATION)
message("Target OpenSSL::SSL=${V1}")
get_property(V2 TARGET OpenSSL::SSL PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
message("Target OpenSSL::SSL=${V2}")
get_property(V3 TARGET OpenSSL::Crypto PROPERTY LOCATION)
message("Target OpenSSL::Crypto=${V3}")
get_property(V4 TARGET OpenSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
message("Target OpenSSL::Crypto=${V4}")
#get_property(V5 TARGET OpenSSL::applink PROPERTY LOCATION)
#message("Target OpenSSL::applink=${V5}")
#get_property(V6 TARGET OpenSSL::applink PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
#message("Target OpenSSL::applink=${V6}")

#
# Find Xerces-C library from brew setup.
#
find_package(XercesC REQUIRED)
message("XercesC_FOUND=${XercesC_FOUND}")
message("XercesC_VERSION=${XercesC_VERSION}")
message("XercesC_INCLUDE_DIRS=${XercesC_INCLUDE_DIRS}")
message("XercesC_LIBRARIES=${XercesC_LIBRARIES}")
message("XercesC_INCLUDE_DIR=${XercesC_INCLUDE_DIR}")
message("XercesC_LIBRARY=${XercesC_LIBRARY}")
get_property(V7 TARGET XercesC::XercesC PROPERTY LOCATION)
message("Target XercesC::XercesC=${V7}")
get_property(V8 TARGET XercesC::XercesC PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
message("Target XercesC::XercesC=${V8}")

add_executable(tcpsrv 
    tcpsrv.cpp
    getlistener.cpp
)
target_compile_definitions(tcpsrv PRIVATE 
    APP_VERSION="${APP_VERSION}"
)
target_compile_features(tcpsrv PRIVATE cxx_std_20)
message("CMAKE_CURRENT_SOURCE_DIR=" ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(tcpsrv PRIVATE 
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/.
)
target_link_libraries(tcpsrv PRIVATE 
    ${OPENSSL_LIBRARIES} 
    ${XercesC_LIBRARIES}
)
set_target_properties(tcpsrv PROPERTIES OUTPUT_NAME tcpsrv1)

add_executable(tlsclient 
    tlsclient.cpp
)
target_compile_definitions(tlsclient PRIVATE 
    APP_VERSION="${APP_VERSION}"
)
target_compile_features(tlsclient PRIVATE cxx_std_20)
target_include_directories(tlsclient PRIVATE 
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/.
)
target_link_libraries(tlsclient PRIVATE 
    ${OPENSSL_LIBRARIES} 
    ${XercesC_LIBRARIES}
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
target_include_directories(tlssrv PRIVATE 
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/.
)
target_link_libraries(tlssrv PRIVATE 
    ${OPENSSL_LIBRARIES} 
    ${XercesC_LIBRARIES}
)
set_target_properties(tlssrv PROPERTIES OUTPUT_NAME tlssrv1)

# Print out compiler features.
#foreach(entry ${CMAKE_CXX_COMPILE_FEATURES})
#    message(${entry})
#endforeach()