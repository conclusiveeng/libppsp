cmake_minimum_required(VERSION 3.2)

project(libperegrine
        VERSION 0.4
        LANGUAGES C
        DESCRIPTION "Peregrine - a Peer-to-Peer Streaming Peer Protocol client-server")

option(BUILD_EXAMPLES "Build and install example programs" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
add_compile_options(-O0 -Wall -Wextra -g -D_DEFAULT_SOURCE)

message(STATUS "CMake version   : " "${CMAKE_SYSTEM_VERSION}")
message(STATUS "Compiler        : " "${CMAKE_C_COMPILER}"    )
message(STATUS "Operating System: " "${CMAKE_SYSTEM}"        )
message(STATUS "I am building   : " "${PROJECT_NAME}"        )

# Setup code check using clang-tidy
# set(CMAKE_C_CLANG_TIDY clang-tidy)

# Create compile_comands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS, 1)
set(PKGCONFIG_C_FLAGS ${CMAKE_C_FLAGS})
set(PKGCONFIG_VERSION ${CMAKE_PROJECT_VERSION})

# Geneatre .deb package
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Conclusive Engineering")
include(CPack)

# Generate documentation
find_package(Doxygen OPTIONAL_COMPONENTS dot)
if (DOXYGEN_FOUND)
#set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "${CMAKE_SOURCE_DIR}/README.md")
doxygen_add_docs(docs ALL ${CMAKE_SOURCE_DIR})
endif(DOXYGEN_FOUND)

get_filename_component(PARENT_DIR .. REALPATH DIRECTORY)

include_directories(include)
set(SOURCE_FILES
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
        src/bitmap.c)

add_library(libperegrine SHARED ${SOURCE_FILES})

configure_file(libperegrine.pc.in ${CMAKE_BINARY_DIR}/libperegrine.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/libperegrine.pc DESTINATION /usr/share/pkgconfig)

install(TARGETS libperegrine DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
install(DIRECTORY ${CMAKE_BINARY_DIR}/include/ DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/librpc.pc DESTINATION ${CMAKE_INSTALL_PREFIX}/share/pkgconfig)

if(BUILD_EXAMPLES)
    add_subdirectory(examples/app)
endif()
