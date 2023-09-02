list(APPEND SOURCES
    ${SRC_DIR}/modules/net/module_net.c)
include_directories(
    ${SRC_DIR}/modules/pico_cyw43
    ${CMAKE_SOURCE_DIR}/lib/dhcpserver)
