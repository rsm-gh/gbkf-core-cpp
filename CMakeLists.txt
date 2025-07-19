
#
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
#

cmake_minimum_required(VERSION 3.10)

project(GBKFCore)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)  # Optional, disables compiler-specific extensions

#
# Lib type / Emscripten
#

if(EMSCRIPTEN)
    message(STATUS "Detected Emscripten compiler")
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "Disabling shared libs for Emscripten" FORCE)
else()
    set(BUILD_SHARED_LIBS ON CACHE BOOL "Using shared libs for non-Emscripten targets" FORCE)
endif()

#
# Open SSL
#

option(USE_OPEN_SSL "Use OpenSSL instead of PicoSha2" OFF)

if(USE_OPEN_SSL)
    message(STATUS "Using OpenSSL to build the library.")
    find_package(OpenSSL REQUIRED)
else()
    message(STATUS "Using PicoSha2 to build the library.")
endif()


#
# GBKF Core Reader Library
#

add_library(GBKFCoreReader lib/GBKFCoreReader.cpp)

target_include_directories(GBKFCoreReader PUBLIC include)
set_target_properties(GBKFCoreReader PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

if(USE_OPEN_SSL)
    target_link_libraries(GBKFCoreReader PUBLIC OpenSSL::Crypto)
endif()

install(TARGETS GBKFCoreReader
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/GBKF DESTINATION include)


#
# GBKF Core Writer Library
#

add_library(GBKFCoreWriter lib/GBKFCoreWriter.cpp)

target_include_directories(GBKFCoreWriter PUBLIC include)
set_target_properties(GBKFCoreWriter PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

if(USE_OPEN_SSL)
    target_link_libraries(GBKFCoreWriter PUBLIC OpenSSL::Crypto)
endif()

install(TARGETS GBKFCoreWriter
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
)

install(DIRECTORY include/GBKF DESTINATION include)

#
# Test Reader and Writer
#

add_executable(test_gbkf tests/test_gbkf.cpp)
target_link_libraries(test_gbkf PRIVATE GBKFCoreReader)
target_link_libraries(test_gbkf PRIVATE GBKFCoreWriter)
set_target_properties(test_gbkf PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})