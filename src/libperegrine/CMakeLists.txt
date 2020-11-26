cmake_minimum_required(VERSION 3.2)
project(libperegrine C)

get_filename_component(PARENT_DIR .. REALPATH DIRECTORY)

include_directories(include)
set(SOURCE_FILES mt.c ppspp_protocol.c proto_helper.c net.c peer.c sha1.c peregrine_leecher.c peregrine_seeder.c wqueue.c log.c)

add_library(peregrine SHARED ${SOURCE_FILES})

configure_file(libperegrine.pc.in ${CMAKE_BINARY_DIR}/libperegrine.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/libperegrine.pc DESTINATION /usr/share/pkgconfig)

install(TARGETS peregrine DESTINATION ${PEREGRINE_INSTALL_LIB_DIR})

#Here should be installed header file with the lib
install(FILES include/peregrine_leecher.h include/peregrine_seeder.h DESTINATION ${PEREGRINE_INSTALL_INCLUDE_DIR})
