cmake_minimum_required(VERSION 3.2)
project(libperegrine_v2 C)

get_filename_component(PARENT_DIR .. REALPATH DIRECTORY)

include_directories(../include)
set(SOURCE_FILES log.c peregrine_socket.c peer_handler.c file.c sha1.c mt.c proto_helper.c)

add_library(peregrine_v2 SHARED ${SOURCE_FILES})

configure_file(libperegrine.pc.in ${CMAKE_BINARY_DIR}/libperegrine.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/libperegrine.pc DESTINATION /usr/share/pkgconfig)

install(TARGETS peregrine_v2 DESTINATION ${PEREGRINE_INSTALL_LIB_DIR})

#Here should be installed header file with the lib
install(FILES include/peregrine_socket.h DESTINATION ${PEREGRINE_INSTALL_INCLUDE_DIR})
