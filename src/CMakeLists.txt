cmake_minimum_required(VERSION 3.2)
project(ppspp_bin)

add_subdirectory(libppspp)
set(SOURCE_FILES main.c)
include_directories(libppspp)

add_executable(ppspp_bin ${SOURCE_FILES})
set_target_properties(ppspp_bin PROPERTIES OUTPUT_NAME ppspp)
target_link_libraries(ppspp_bin ppspp pthread rt)
install(TARGETS ppspp_bin DESTINATION ${PPSPP_INSTALL_BIN_DIR})
