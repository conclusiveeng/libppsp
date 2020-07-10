cmake_minimum_required(VERSION 2.8)
project(ppspp)

set(VERSION 0.2)
set(CMAKE_C_FLAGS "-Wall -ggdb3 -std=c11 -D_DEFAULT_SOURCE")

add_library(ppspp SHARED mt.c ppspp_protocol.c net.c net_swift.c peer.c sha1.c ppspp.c ppspp_swift.c)
add_executable(ppspp_exe main.c)

set_target_properties(ppspp_exe PROPERTIES OUTPUT_NAME ppspp)
set_target_properties(ppspp PROPERTIES PUBLIC_HEADER ppspp.h)
target_link_libraries(ppspp_exe pthread ppspp)

configure_file(libppspp.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libppspp.pc @ONLY)

install(TARGETS ppspp PUBLIC_HEADER DESTINATION include)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libppspp.pc
	DESTINATION /usr/share/pkgconfig)
