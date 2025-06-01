
#   This file is part of gbkf-core-cpp.
#
# Copyright (c) 2025 Rafael Senties Martinelli.
#
# Licensed under the Privative-Friendly Source-Shared License (PFSSL) v1.0.
# You may use, modify, and distribute this file under the terms of that license.
#
# This software is provided "as is", without warranty of any kind.
# The authors are not liable for any damages arising from its use.
#
# See the LICENSE file for more details.


cmake_minimum_required(VERSION 3.10)

project(GBKFCore)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)  # Optional, disables compiler-specific extensions

if(EMSCRIPTEN)
    message(STATUS "Detected Emscripten compiler")
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "Disabling shared libs for Emscripten" FORCE)
else()
    set(BUILD_SHARED_LIBS ON CACHE BOOL "Using shared libs for non-Emscripten targets" FORCE)
endif()

option(USE_OPEN_SSL "Use OpenSSL instead of PicoSha2" OFF)

#
# Open SSL
#

if(USE_OPEN_SSL)
    message(STATUS "Using OpenSSL to build the library.")
    find_package(OpenSSL REQUIRED)
else()
    message(STATUS "Using PicoSha2 to build the library.")
endif()


#
# GBKF Core Library
#

add_library(GBKFCore lib/Core.cpp)

target_include_directories(GBKFCore PUBLIC include)
set_target_properties(GBKFCore PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

if(USE_OPEN_SSL)
    target_link_libraries(GBKFCore PUBLIC OpenSSL::Crypto)
endif()

install(TARGETS GBKFCore
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/GBKF DESTINATION include)

#
# Test GBKFCore
#

add_executable(test_core tests/test_core.cpp)
target_link_libraries(test_core PRIVATE GBKFCore)
set_target_properties(test_core PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})