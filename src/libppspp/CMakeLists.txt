cmake_minimum_required(VERSION 3.2)
project(libppspp C)

get_filename_component(PARENT_DIR .. REALPATH DIRECTORY)
message(${PARENT_DIR}/debug.h)

set(SOURCE_FILES mt.c ppspp_protocol.c net.c net_swift.c peer.c sha1.c ppspp_swift.c wqueue.c)

add_library(ppspp SHARED ${SOURCE_FILES})

configure_file(libppspp.pc.in ${CMAKE_BINARY_DIR}/libppspp.pc @ONLY)
install(FILES  ${CMAKE_BINARY_DIR}/libppspp.pc DESTINATION /usr/share/pkgconfig)

install(TARGETS ppspp DESTINATION ${PPSPP_INSTALL_LIB_DIR})

#Here should be installed header file with the lib
install(FILES ppspp_swift.h DESTINATION ${PPSPP_INSTALL_INCLUDE_DIR})

