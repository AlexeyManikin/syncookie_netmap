cmake_minimum_required(VERSION 2.8)
project(synfloodprotect)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

set(SOURCE_FILES main.cpp)
add_executable(synfloodprotect ${SOURCE_FILES})

add_executable(bridge bridge.cpp)

set(SOURCE_LIB_LOGGER lib/logger/logger.cpp)
add_library(logger STATIC ${SOURCE_LIB_LOGGER})
target_link_libraries(synfloodprotect logger)

set(SOURCE_LIB_PARCER lib/parser/parcer.cpp lib/parser/fastnetmon_packet_parser.c lib/parser/parcer.h lib/parser/fastnetmon_packet_parser.h)
add_library(parcer STATIC ${SOURCE_LIB_PARCER})
target_link_libraries(synfloodprotect parcer)

include_directories("/usr/src/linux-4.3.3/")
#include_directories("/usr/src/linux-4.3.3/include/uapi/")
#include_directories("/usr/src/linux-4.3.3/include")

set(SOURCE_LIB_SYNC  lib/syncookie/synproxy.cpp lib/syncookie/synproxy.h lib/syncookie/syncookies.c)
add_library(syncookie STATIC ${SOURCE_LIB_SYNC})
target_link_libraries(synfloodprotect syncookie)

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

find_package(Boost COMPONENTS thread regex program_options system REQUIRED)
message(${Boost_INCLUDE_DIRS})
if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(synfloodprotect ${Boost_LIBRARIES})
endif()



# Specify config for deb package
# http://www.cmake.org/Wiki/CMake:CPackPackageGenerators#DEB_.28UNIX_only.29
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libboost-thread-dev, libboost-system-dev, libboost-regex-dev, libnuma-dev, liblog4cpp5-dev")
