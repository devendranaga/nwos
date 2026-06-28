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
elseif(COMPILER_ARM)
    set(CMAKE_C_COMPILER "aarch64-linux-gnu-gcc")
endif()

set(CMAKE_C_FLAGS "-Wall -Werror -Wextra -Wno-unused-parameter -Os")

if(DEBUG)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -ggdb")
endif()

SET(PROTOCOL_SRC
    ./protocols/eth.c
    ./protocols/arp_parse.c
    ./protocols/vlan.c
    ./protocols/macsec.c
    ./protocols/ipv4_parse.c
    ./protocols/ipv6_parse.c
    ./protocols/tcp_parse.c
    ./protocols/udp_parse.c
    ./protocols/checksum.c
    ./protocols/icmp_parse.c
    ./protocols/icmp.c
    ./protocols/icmp6_parse.c)

SET(SWITCHING_SRC
    ./switching/atu.c)

SET(PLATFORM_SRC
    ./platform/lib/raw_socket.c
    ./platform/lib/net_ioctl.c
    ./platform/lib/pthread_intf.c
    ./platform/lib/mmap_intf.c
    ./platform/gcd/gcd.c
    ./common/hash_tables.c
    ./common/pkt_buffer.c
    ./common/buffer_pool.c
    ./common/list.c
    ./common/queue.c
    ./common/ring.c
    ./common/common.c
    ./logging/netos_log.c)

set(CRYPTO_SRC
    ./crypto/crypto_intf.c)

if(WITH_WOLFSSL)
    set(CRYPTO_SRC
        ${CRYPTO_SRC}
        ./crypto/crypto_wolfssl_intf.c)
    set(CRYPTO_LINKER_FLAGS "wolfssl")
endif()

SET(EVENT_SRC
    ./events/event_mgr.c
    ./events/event_buffer.c)

SET(LIB_SRC
    ${PROTOCOL_SRC}
    ${SWITCHING_SRC}
    ${PLATFORM_SRC}
    ${EVENT_SRC})

SET(NETOS_SRC
    ./core/main.c
    ./core/packet_parser.c
    ./core/netos_config.c
    ./protocols/arp.c
    ./egress/egress_controller.c
    ./egress/egress_sp.c
    ./egress/egress_rr.c)

set(TOOL_PGEN_SRC
    ./tools/pgen/pgen.c)

include_directories(
                ./protocols/
                ./common/
                ./platform/lib/
                ./platform/gcd/
                ./logging/
                ./events/
                ./egress/
                ./statistics/
                ./core/
                ./switching/
                ./crypto/
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

if(STATIC_BUILD)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

add_library(netos_crypto STATIC ${CRYPTO_SRC})

add_executable(netos_pgen ${TOOL_PGEN_SRC})
target_link_libraries(netos_pgen PRIVATE pthread netos netos_crypto ${CRYPTO_LINKER_FLAGS})

add_executable(netosd ${NETOS_SRC})

if(COMPILER_ARM)
    target_link_directories(netosd PRIVATE /usr/lib/aarch64-linux-gnu/)
endif()

target_link_libraries(netosd PRIVATE netos xml2 m z lzma icuuc)

