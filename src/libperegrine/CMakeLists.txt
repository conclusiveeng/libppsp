cmake_minimum_required(VERSION 3.2)
project(libperegrine C)

get_filename_component(PARENT_DIR .. REALPATH DIRECTORY)
message(${PARENT_DIR}/debug.h)

set(SOURCE_FILES mt.c ppspp_protocol.c net_swift.c peer.c sha1.c ppspp_swift.c wqueue.c)

add_library(peregrine SHARED ${SOURCE_FILES})

configure_file(libperegrine.pc.in ${CMAKE_BINARY_DIR}/libperegrine.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/libperegrine.pc DESTINATION /usr/share/pkgconfig)

install(TARGETS peregrine DESTINATION ${PEREGRINE_INSTALL_LIB_DIR})

#Here should be installed header file with the lib
install(FILES ppspp_swift.h DESTINATION ${PEREGRINE_INSTALL_INCLUDE_DIR})

