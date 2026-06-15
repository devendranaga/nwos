cmake_minimum_required(VERSION 3.12)
project(netos)

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(LINK_SEARCH_START_STATIC ON)
set(LINK_SEARCH_END_STATIC ON)

#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc")

if(COMPILER_CLANG)
set(CMAKE_C_COMPILER "clang")
elseif(COMPILER_GCC)
set(CMAKE_C_COMPILER "gcc")
endif()

set(CMAKE_C_FLAGS "-Wall -Wno-unused-parameter -Werror -Wextra")

if(DEBUG)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -ggdb")
endif()

SET(PROTOCOL_SRC
    ./protocols/eth.c
    ./protocols/arp.c
    ./protocols/vlan.c
    ./protocols/macsec.c
    ./protocols/ipv4.c
    ./protocols/ipv6.c
    ./protocols/tcp.c
    ./protocols/udp.c)

SET(SWITCHING_SRC
    ./switching/atu.c)

SET(PLATFORM_SRC
    ./platform/lib/raw_socket.c
    ./platform/lib/net_ioctl.c
    ./platform/lib/pthread_intf.c
    ./platform/lib/mmap_intf.c
    ./common/hash_tables.c
    ./common/pkt_buffer.c
    ./common/buffer_pool.c
    ./common/list.c
    ./common/queue.c
    ./common/common.c
    ./logging/netos_log.c)

SET(EVENT_SRC
    ./events/event_intf.c
    ./events/event_mgr.c
    ./events/event_buffer.c)

SET(LIB_SRC
    ${PROTOCOL_SRC}
    ${SWITCHING_SRC}
    ${PLATFORM_SRC}
    ${EVENT_SRC})

SET(NETWORK_SRC
    ./networking/main.c
    ./networking/packet_parser.c
    ./networking/network_config.c
    ./egress/egress_controller.c
    ./egress/egress_sp.c
    ./egress/egress_rr.c)

set(TOOL_PGEN_SRC
    ./tools/pgen/pgen.c)

include_directories(
                ./protocols/
                ./common/
                ./platform/lib/
                ./logging/
                ./events/
                ./egress/
                ./statistics/
                ./networking/
                ./switching/
                /usr/include/libxml2/
                ./tools/pgen/)

add_library(netos STATIC ${LIB_SRC})

set(TEST_DLL_SRC
    ./tests/test_dll.c)

set(TEST_QUEUE_SRC
    ./tests/test_queue.c)

set(TEST_HASH_TABLE_SRC
    ./tests/test_hash_table.c)

add_executable(netos_test_dll ${TEST_DLL_SRC})
target_link_libraries(netos_test_dll PRIVATE netos)

add_executable(netos_test_queue ${TEST_QUEUE_SRC})
target_link_libraries(netos_test_queue PRIVATE netos)

add_executable(netos_test_hash_table ${TEST_HASH_TABLE_SRC})
target_link_libraries(netos_test_hash_table PRIVATE netos)

add_executable(netos_pgen ${TOOL_PGEN_SRC})
target_link_libraries(netos_pgen PRIVATE pthread netos)

add_executable(netosd ${NETWORK_SRC})
target_link_libraries(netosd PRIVATE netos xml2 m z lzma icuuc)

