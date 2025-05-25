
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
project(GBKF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#
# Open SSL
#

#find_package(OpenSSL REQUIRED)


#
# Common GBKF
#

# This is for the header files. It is currently not necessary since all the header
# files are located with the .cpp.
#include_directories("${CMAKE_SOURCE_DIR}/src")

#
# GBKF Core Shared Library
#

add_library(GBKFCore SHARED "${CMAKE_SOURCE_DIR}/lib/Core.cpp")
target_include_directories(GBKFCore PUBLIC ${CMAKE_SOURCE_DIR}/include)
set_target_properties(GBKFCore PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
#target_link_libraries(GBKFCore PUBLIC OpenSSL::Crypto)

install(TARGETS GBKFCore
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)

# Core tests

add_executable(test_core "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_core.cpp")
target_link_libraries(test_core PRIVATE GBKFCore)
set_target_properties(test_core PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})


#
# INSTALL ALL FILES
#

install(DIRECTORY include/GBKF DESTINATION include)


#
# Test ALL
#
add_custom_target(test
        COMMAND test_core
        DEPENDS test_core
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
