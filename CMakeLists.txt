cmake_minimum_required(VERSION 3.12)

project(netos)

find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)
#find_package(jsoncpp REQUIRED)

set(PLATFORM_SRC
    platform/lib/linux/raw_socket.cc
    platform/lib/linux/udp_socket.cc
    platform/lib/linux/rng_linux.c
    platform/lib/linux/ioctl_nw.c
    platform/lib/logging/logging.c
    platform/lib/helpers/conversion.cc
    platform/lib/algorithms/queue.c
    platform/lib/linux/pcap_lib.cc
    platform/lib/gcd/gcd.cc
    platform/lib/linux/socket_helper.c
    platform/lib/linux/perf_linux.cc
    platform/lib/linux/fileio_mem.c)

set(LOGGER_SRC
    logger/src/logger.cc)

set(IDS_COMMON_SRC
    pkt/packet_buf.cc
    protocols/l2/eth.cc
    protocols/l2/arp_hdr.cc
    protocols/l2/vlan.cc
    protocols/l2/vlan_membership.cc
    protocols/l2/macsec_hdr.cc
    protocols/l2/mka.cc
    protocols/l2/avtp.cc
    protocols/l2/ieee8021br.cc
    protocols/l2/lldp_hdr.cc
    protocols/l3/ipv4.cc
    protocols/l3/ipv6.cc
    protocols/l4/udp.cc
    protocols/l4/tcp.cc
    protocols/l4/icmp.cc
    protocols/l4/icmpv6.cc
    protocols/app/dlt_header.cc
    protocols/checksum/checksum.cc
    event/event_mgr.cc
    pkt/parsed_pkt_pool.cc)

set(NETOS_PROTOCOLS_SRC
    protocols/l2/arp.cc
    protocols/l2/macsec.cc)

set(STATISTICS_SRC
    statistics/statistics.cc)

set(IDS_PKT_GEN_SRC
    ${IDS_COMMON_SRC}
    pktgen/pktgen.cc
    pktgen/pktgen_config.cc)

set(CLOUD_INTERFACE_SRC
    cloud_interface/stats_interface_tx.cc
    cloud_interface/events_interface_tx.cc
    cloud_interface/cloud_interface_tx.cc)

set(NETWORKING_SRC
    ${IDS_COMMON_SRC}
    ${NETOS_PROTOCOLS_SRC}
    networking/network_main.cc
    networking/network_config.cc
    networking/pkt_parser.cc
    networking/network_egress_intf.cc
    networking/pcap.cc
    networking/egress_queue.cc
    ${STATISTICS_SRC}
    ${CLOUD_INTERFACE_SRC})

set(CRYPTOGRAPHY_SRC
    cryptography/openssl/openssl_hash.cc
    cryptography/openssl/openssl_rsa.cc
    cryptography/wolfssl/wolfssl_hash.cc
    cryptography/wolfssl/wolfssl_gcm.cc
    cryptography/interface/cryptography_methods.cc)

set(CRYPTO_SRV_SRC
    cryptography/srv/crypto_srv.cc
    cryptography/srv/crypto_srv_op.cc)

set(CRYPTO_CLI_SRC
    cryptography/cli/crypto_cli.cc)

set(ENCODING_CBOR_SRC
    encoding/cbor/cbor_enc_dec.cc)

set(TOOL_REPLAY_SRC
    replay/replay.cc)

set(TOOL_TCPDUMP_SRC
    tcpdump/tcpdump.cc)

set(TEST_CBOR_SRC
    test/test_cbor.cc)

set(TEST_QUEUE_SRC
    test/test_queue.c)

set(TEST_DLL_SRC
    test/test_dll.cc)

set(TEST_HASH_TABLE_SRC
    test/test_hash_table.cc)

set(INCL_DIR
    platform/lib/helpers/
    platform/lib/linux/
    platform/lib/algorithms/
    platform/lib/error/
    platform/lib/logging/
    platform/lib/gcd/
    platform/lib/allocator/
    pkt/
    protocols/
    protocols/macros/
    protocols/l2/
    protocols/l3/
    protocols/l4/
    protocols/app/
    protocols/checksum/
    event/
    networking/
    statistics/
    cryptography/interface/
    cryptography/openssl/
    cryptography/wolfssl/
    cryptography/srv/
    cryptography/cli_interface/
    cryptography/cli/
    logger/src/
    cloud_interface/
    encoding/cbor/
    replay/
    tcpdump/)

include_directories(${INCL_DIR} ${JSONCPP_INCLUDE_DIRS})

## command line options
#  -D NETOS_DEBUG_PKT_DECODE - packet decode debugging
#  -D NETOS_PERF_TIME - perf counters for base level statistics reporting
set(CMAKE_DEBUG_OPT "-fsanitize=address -DNETOS_DEBUG_PKT_DECODE -DNETOS_PERF_TIME")

if(CMAKE_DEBUG_BIN)
set(NETOS_BIN_OPT "-g -ggdb")
else()
set(NETOS_BIN_OPT "-O2 -flto -fPIC -Wl,-z,noexecstack -Wno-unused-command-line-argument")
endif()

if(STATIC_BUILD)
set(BUILD_FLAGS "-static")
else()
set(BUILD_FLAGS "")
endif()

set(CMAKE_C_FLAGS "${BUILD_FLAGS} -fstack-protector -D_FORTIFY_SOURCE=2 -Wall -Wextra -Wno-unused-parameter ${NETOS_BIN_OPT} -DWC_NO_HARDEN")
set(CMAKE_CXX_FLAGS "${BUILD_FLAGS} -fstack-protector -D_FORTIFY_SOURCE=2 -Wall -Wextra -Wno-unused-parameter ${NETOS_BIN_OPT} -DWC_NO_HARDEN")

## Use clang compiler

if(CLANG_COMPILER)
set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")

## Use gcc compiler
elseif(GCC_COMPILER)
set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")
endif()

add_library(netos_platform ${PLATFORM_SRC})

#set(JSONCPP_LIBRARIES JsonCpp::JsonCpp)

# build network daemon
add_executable(netos_netwd ${NETWORKING_SRC})
target_link_libraries(netos_netwd netos_platform pthread ${JSONCPP_LIBRARIES} netos_cryptography ssl crypto wolfssl zstd z)

# build logger daemon
add_executable(netos_logger ${LOGGER_SRC})
target_link_libraries(netos_logger netos_platform pthread ${JSONCPP_LIBRARIES})

# build packet generator
add_executable(netos_pktgen ${IDS_PKT_GEN_SRC})
target_link_libraries(netos_pktgen netos_platform pthread ${JSONCPP_LIBRARIES})

# build crypto library
add_library(netos_cryptography ${CRYPTOGRAPHY_SRC})
target_link_libraries(netos_cryptography netos_platform pthread)

# build crypto service
add_executable(netos_crypto_srv ${CRYPTO_SRV_SRC})
target_link_libraries(netos_crypto_srv netos_platform pthread netos_cryptography ssl crypto wolfssl)

# build crypto cli
add_executable(netos_crypto_cli ${CRYPTO_CLI_SRC})
target_link_libraries(netos_crypto_cli netos_platform pthread netos_cryptography ssl crypto wolfssl)

# build cbor library
add_library(netos_cbor ${ENCODING_CBOR_SRC})
target_link_libraries(netos_cbor netos_platform pthread)

# build test tool for cbor
add_executable(netos_test_cbor ${TEST_CBOR_SRC})
target_link_libraries(netos_test_cbor netos_platform pthread netos_cbor)

# build test tool for queueing
add_executable(netos_test_queue ${TEST_QUEUE_SRC})
target_link_libraries(netos_test_queue netos_platform pthread)

# build test tool for doubly linked lists
add_executable(netos_test_dll ${TEST_DLL_SRC})
target_link_libraries(netos_test_dll netos_platform pthread)

# build test tool for the hash tables
add_executable(netos_test_hash_table ${TEST_HASH_TABLE_SRC})
target_link_libraries(netos_test_hash_table netos_platform pthread)

# build test tool for packet replay
add_executable(netos_replay ${TOOL_REPLAY_SRC})
target_link_libraries(netos_replay netos_platform pthread)

