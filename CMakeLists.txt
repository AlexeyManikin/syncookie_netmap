cmake_minimum_required(VERSION 2.8)
project(synfloodprotect)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

set (HEADER_FILES
        lib/protocol_helpers/tcp.h
        lib/protocol_helpers/ip.h
        lib/protocol_helpers/icmp.h
        lib/parser/parcer.h
        lib/parser/packet_parser.h
        lib/parser/parcer_helper.h
        lib/parser/be_byteshift.h
        lib/logger/logger.h)

set(SOURCE_FILES
        main.cpp
        lib/protocol_helpers/tcp.cpp
        lib/protocol_helpers/ip.cpp
        lib/protocol_helpers/icmp.cpp
        lib/parser/parcer.cpp
        lib/parser/packet_parser.cpp
        lib/parser/parcer_helper.cpp
        lib/logger/logger.cpp)

set(SOURCE_LIB_SYNC lib/syncookie/sha1.c
        lib/syncookie/be_byteshift.h
        lib/syncookie/cryptohash.h
        lib/syncookie/div64.h
        lib/syncookie/synproxy.cpp
        lib/syncookie/synproxy.h)

add_executable(synfloodprotect ${HEADER_FILES} ${SOURCE_LIB_SYNC} ${SOURCE_FILES})

include_directories(".")

set(LOG4CPP_CUSTOM_INSTALL_PATH "/opt/log4cpp1.1.1")

# Try to find log4cpp includes path
find_path(LOG4CPP_INCLUDES_FOLDER NAMES log4cpp/Appender.hh PATHS "${LOG4CPP_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)
find_library(LOG4CPP_LIBRARY_PATH NAMES log4cpp PATHS "${LOG4CPP_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

if (LOG4CPP_INCLUDES_FOLDER AND LOG4CPP_LIBRARY_PATH)
    include_directories(${LOG4CPP_INCLUDES_FOLDER})
    target_link_libraries(logger ${LOG4CPP_LIBRARY_PATH})
    target_link_libraries(synfloodprotect ${LOG4CPP_LIBRARY_PATH})
    message(STATUS "We have found log4cpp and will build project")
else()
    message(FATAL_ERROR "We can't find log4cpp. We can't build project")
endif()

set (Boost_USE_STATIC_LIBS ON)
set (Boost_USE_MULTITHREADED ON)

find_package(Boost COMPONENTS thread regex program_options system atomic REQUIRED)
message(${Boost_INCLUDE_DIRS})
if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(synfloodprotect ${Boost_LIBRARIES})
endif()

# Specify config for deb package
# http://www.cmake.org/Wiki/CMake:CPackPackageGenerators#DEB_.28UNIX_only.29
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libboost-thread-dev, libboost-system-dev, libboost-regex-dev, libnuma-dev, liblog4cpp5-dev")
