cmake_minimum_required(VERSION 3.2)

project(peregrine
        VERSION 0.4
        LANGUAGES C
        DESCRIPTION "Peregrine - a Peer-to-Peer Streaming Peer Protocol client-server")

option(BUILD_EXAMPLES "Build and install example programs" ON)
option(PACKAGE_DEB "Generate DEB package" OFF)
option(BUILD_DOCS "Generate docs using Doxygen" OFF)
option(BUILD_STATIC "Build static libary and example app" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
add_compile_options(-O0 -Wall -Wextra -g -D_DEFAULT_SOURCE)

message(STATUS "CMake version   : " "${CMAKE_SYSTEM_VERSION}")
message(STATUS "Compiler        : " "${CMAKE_C_COMPILER}")
message(STATUS "Operating System: " "${CMAKE_SYSTEM_NAME}")
message(STATUS "Build type      : " "${CMAKE_BUILD_TYPE}")

find_package (Threads)

# Create compile_comands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS, 1)
set(PKGCONFIG_C_FLAGS ${CMAKE_C_FLAGS})
set(PKGCONFIG_VERSION ${CMAKE_PROJECT_VERSION})

get_filename_component(PARENT_DIR .. REALPATH DIRECTORY)
include(GNUInstallDirs)

include_directories(include)
set(MAIN_SOURCES
        src/internal.h
        src/buffer.c
        src/log.c
        src/socket.c
        src/peer.c
        src/file.c
        src/sha1.c
        src/swarm.c
        src/mt.c
        src/utils.c
        src/proto.c
        src/bitmap.c
        src/hashtable.c)

set(LINUX_SOURCES
        src/eventloop/epoll.c)

set(BSD_SOURCES
        src/eventloop/kqueue.c)

# Handle build for Linux/FreeBSD
if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(EVENTLOOP_SOURCES ${LINUX_SOURCES})
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
    set(EVENTLOOP_SOURCES ${BSD_SOURCES})
endif()

# Generate .deb package
if (PACKAGE_DEB)
    set(CPACK_GENERATOR "DEB")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Conclusive Engineering")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.3.1)")
    include(CPack)
endif()

# Generate Doxygen docs
if(BUILD_DOCS)
    find_package(Doxygen OPTIONAL_COMPONENTS dot)
    if(NOT DOXYGEN_FOUND)
        message(WARNING "Doxygen is needed to build the documentation.")
    else()
        file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/doxygen)
        configure_file(${CMAKE_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
        add_custom_target( doc ALL COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/doxygen COMMENT "Generating API documentation with Doxygen" VERBATIM )
    endif()
endif()

# Build dynamic libary by default, provide option for static
if (BUILD_STATIC)
    add_library(libperegrine STATIC ${MAIN_SOURCES} ${EVENTLOOP_SOURCES})
else()
    add_library(libperegrine SHARED ${MAIN_SOURCES} ${EVENTLOOP_SOURCES})
endif()
set_target_properties(libperegrine PROPERTIES PREFIX "")
target_link_libraries(libperegrine m ${CMAKE_THREAD_LIBS_INIT})

# Prepare library
configure_file(libperegrine.pc.in ${CMAKE_BINARY_DIR}/libperegrine.pc @ONLY)
install(TARGETS libperegrine DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
# Handle build for Linux/FreeBSD
if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libperegrine.pc DESTINATION ${CMAKE_INSTALL_PREFIX}/share/pkgconfig)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libperegrine.pc DESTINATION ${CMAKE_INSTALL_PREFIX}/libdata/pkgconfig)
endif()

if(BUILD_EXAMPLES)
    add_subdirectory(examples/app)
endif()
