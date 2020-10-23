cmake_minimum_required(VERSION 2.8)
project(ppspp)

set(VERSION 0.3)
set(CMAKE_C_FLAGS "-Wall -ggdb3 -std=c11 -D_DEFAULT_SOURCE")
set(CMAKE_C_CLANG_TIDY clang-tidy -checks=-*,readability-*)

add_library(ppspp SHARED mt.c ppspp_protocol.c net.c net_swift.c peer.c sha1.c ppspp_swift.c wqueue.c)
add_executable(ppspp_exe main.c)

set_target_properties(ppspp_exe PROPERTIES OUTPUT_NAME ppspp)
set_target_properties(ppspp PROPERTIES PUBLIC_HEADER ppspp_protocol.h) # fixme this is not a real header
target_link_libraries(ppspp_exe pthread ppspp rt)

configure_file(libppspp.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libppspp.pc @ONLY)

install(TARGETS ppspp PUBLIC_HEADER DESTINATION include)
install(TARGETS ppspp_exe RUNTIME DESTINATION bin)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libppspp.pc
	DESTINATION /usr/share/pkgconfig)

set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Conclusive Engineering")
include(CPack)
