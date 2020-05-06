cmake_minimum_required(VERSION 2.8)
project(ppspp)

set(CMAKE_C_FLAGS "-Wall -std=c11 -D_DEFAULT_SOURCE")
add_library(ppspp SHARED mt.c ppspp_protocol.c net.c peer.c sha1.c)

add_executable(ppspp_exe main.c)
set_target_properties(ppspp_exe PROPERTIES OUTPUT_NAME ppspp)
#set(CMAKE_VERBOSE_MAKEFILE TRUE)
target_link_libraries(ppspp_exe pthread ppspp)
