cmake_minimum_required(VERSION 3.2)

project(ppspp
        VERSION 0.4
        LANGUAGES C
        DESCRIPTION "Peer-to-Peer Streaming Peer Protocol")

# gcovr coverage make flags
# set(GCOV_LINK_FLAGS "-lgcov --coverage")
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${GCOV_LINK_FLAGS}")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g --coverage -fprofile-arcs -ftest-coverage")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
add_compile_options(-O0 -Wall -Wextra -g -D_DEFAULT_SOURCE)
# -ggdb3

message(STATUS "CMake version   : " "${CMAKE_SYSTEM_VERSION}")
message(STATUS "Compiler        : " "${CMAKE_C_COMPILER}"    )
message(STATUS "Operating System: " "${CMAKE_SYSTEM}"        )
message(STATUS "I am building   : " "${PROJECT_NAME}"        )

# Setup code check using clang-tidy
set(CMAKE_C_CLANG_TIDY clang-tidy)

# Create compile_comands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS, 1)

# Set for changing prefix for installation directory
# set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR}/_install)

# Set this if .deb file should be build into different directory
# set(CPACK_OUTPUT_FILE_PREFIX ${CMAKE_INSTALL_PREFIX}/pkg)

set(PPSPP_INSTALL_INCLUDE_DIR include)
set(PPSPP_INSTALL_BIN_DIR bin)
set(PPSPP_INSTALL_LIB_DIR lib)

set(PPSPP_HEADERS_DIR include/ppspp)

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

include_directories(${PPSPP_INSTALL_INCLUDE_DIR})

add_subdirectory(src)
