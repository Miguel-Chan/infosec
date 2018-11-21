cmake_minimum_required(VERSION 3.10)
project(md5)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if (APPLE)
    add_executable(md5-mac
            main.cpp md5.cpp md5.h md5test.cpp md5test.h)
endif (APPLE)

if(UNIX AND NOT APPLE)
    add_executable(md5-linux
            main.cpp md5.cpp md5.h md5test.cpp md5test.h)
endif(UNIX AND NOT APPLE)

if (WIN32)
    add_executable(panorama
            main.cpp md5.cpp md5.h md5test.cpp md5test.h)
endif(WIN32)

include_directories(.)
