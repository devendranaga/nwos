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
else() # production build options
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNDEBUG")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -fstack-clash-protection")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=3 -fPIE")
endif()

SET(PROTOCOL_SRC
    ./protocols/eth.c
    ./protocols/arp_parse.c
    ./protocols/vlan.c
    ./protocols/macsec_parse.c
    ./protocols/ipv4_parse.c
    ./protocols/ipv6_parse.c
    ./protocols/tcp_parse.c
    ./protocols/udp_parse.c
    ./protocols/checksum.c
    ./protocols/icmp_parse.c
    ./protocols/icmp6_parse.c
    ./protocols/mka_parse.c
    ./protocols/mka.c
    ./protocols/mqtt_parse.c)

SET(SWITCHING_SRC
    ./switching/atu.c
    ./switching/vlan_conv.c)

SET(PLATFORM_SRC
    ./platform/lib/raw_socket.c
    ./platform/lib/net_ioctl.c
    ./platform/lib/pthread_intf.c
    ./platform/lib/cpu_affinity.c
    ./platform/lib/mmap_intf.c
    ./platform/gcd/gcd.c
    ./platform/lib/pcap_intf.c
    ./platform/lib/pcapng.c
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
    ./core/rules_config.c
    ./protocols/arp.c
    ./protocols/macsec.c
    ./protocols/icmp.c
    ./protocols/ipv4.c
    ./egress/egress_controller.c
    ./egress/egress_sp.c
    ./egress/egress_rr.c
    ./egress/egress_pfifo.c
    ./egress/egress_bfifo.c
    ./egress/egress_sfq.c
    ./egress/egress_drr.c
    ./egress/egress_pfifo_fast.c
    ./statistics/statistics.c)

set(TOOL_PGEN_SRC
    ./tools/pgen/pgen.c
    ./tools/pgen/pgen_arp_ops.c)

set(TEST_PCAPNG
    ./tests/test_pcapng.c)

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
target_link_libraries(netos_pgen PRIVATE netos netos_crypto ${CRYPTO_LINKER_FLAGS} readline tinfo ncurses pthread)

add_executable(netosd ${NETOS_SRC})

add_executable(netos_pcapng_test ${TEST_PCAPNG})
target_link_libraries(netos_pcapng_test PRIVATE netos)

if(COMPILER_ARM)
    target_link_directories(netosd PRIVATE /usr/lib/aarch64-linux-gnu/)
endif()

if(STATIC_BUILD)
    target_link_libraries(netosd PRIVATE netos xml2 icui18n icuuc icudata z lzma m pthread stdc++ dl)
else()
    target_link_libraries(netosd PRIVATE netos xml2 m z lzma icuuc)
endif()

add_custom_target(pcapng_rust ALL
    COMMAND cargo build --manifest-path ${CMAKE_SOURCE_DIR}/rust/pcapng/Cargo.toml
    COMMENT "Building Rust pcapng library")

add_custom_target(protocols_rust ALL
    COMMAND cargo build --manifest-path ${CMAKE_SOURCE_DIR}/rust/protocols/Cargo.toml
    COMMENT "Build Rust Network Protocols library")

add_custom_target(pktdump_rust ALL
    COMMAND cargo build --manifest-path ${CMAKE_SOURCE_DIR}/rust/pktdump/Cargo.toml
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_SOURCE_DIR}/rust/pktdump/target/debug/pktdump
    ${CMAKE_BINARY_DIR}/
    COMMENT "Build Rust Packet dump tool")

add_custom_target(linux_abs ALL
    COMMAND cargo build --manifest-path ${CMAKE_SOURCE_DIR}/rust/linux_abs/Cargo.toml
    COMMENT "Build rust Linux abstraction")

set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES
    ${CMAKE_SOURCE_DIR}/rust/pcapng/target
    ${CMAKE_SOURCE_DIR}/rust/protocols/target
    ${CMAKE_SOURCE_DIR}/rust/pktdump/target
    ${CMAKE_SOURCE_DIR}/rust/linux_abs/target)

