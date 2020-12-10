cmake_minimum_required(VERSION 3.2)
project(peregrine_demo)

add_subdirectory(libperegrine)
add_subdirectory(libperegrine/v2)
set(SOURCE_FILES main.c)
include_directories(libperegrine/include)

add_executable(peregrine_demo ${SOURCE_FILES})
set_target_properties(peregrine_demo PROPERTIES OUTPUT_NAME peregrine_old)
target_link_libraries(peregrine_demo peregrine pthread rt)
install(TARGETS peregrine_demo DESTINATION ${PEREGRINE_INSTALL_BIN_DIR})


add_executable(peregrine_peer peregrine.c)
set_target_properties(peregrine_peer PROPERTIES OUTPUT_NAME peregrine)
target_link_libraries(peregrine_peer peregrine_v2)
install(TARGETS peregrine_peer DESTINATION ${PEREGRINE_INSTALL_BIN_DIR})
