cmake_minimum_required(VERSION 3.9)

project(netos)

set(PLATFORM_SRC
	platform/lib/linux/raw_socket.cc
	platform/lib/linux/udp_socket.cc
	platform/lib/linux/rng_linux.c
	platform/lib/linux/ioctl_nw.c
	platform/lib/logging/logging.c
	platform/lib/helpers/conversion.cc
	platform/lib/algorithms/hash_table.c
	platform/lib/linux/pcap_lib.cc
	platform/lib/gcd/gcd.cc)

set(LOGGER_SRC
	logger/src/logger.cc)

set(IDS_COMMON_SRC
	pkt/packet_buf.cc
	protocols/l2/eth.cc
	protocols/l2/arp.cc
	protocols/l2/vlan.cc
	protocols/l2/macsec.cc
	protocols/l2/mka.cc
	protocols/l3/ipv4.cc
	protocols/l3/ipv6.cc
	protocols/l4/udp.cc
	protocols/l4/tcp.cc
	protocols/l4/icmp.cc
	protocols/l4/icmpv6.cc
	event/event_mgr.cc
	networking/network_egress_intf.cc)

set(STATISTICS_SRC
	statistics/statistics.cc)

set(IDS_PKT_GEN_SRC
	${IDS_COMMON_SRC}
	pktgen/pktgen.cc
	pktgen/pktgen_config.cc)

set(NETWORKING_SRC
	${IDS_COMMON_SRC}
	networking/network_main.cc
	networking/network_config.cc
	networking/pkt_parser.cc
	networking/network_egress_intf.cc
	networking/pcap.cc
	${STATISTICS_SRC})

set(CRYPTOGRAPHY_SRC
	cryptography/openssl/openssl_hash.cc
	cryptography/wolfssl/wolfssl_hash.cc
	cryptography/interface/cryptography_methods.cc)

set(CRYPTO_SRV_SRC
	cryptography/srv/crypto_srv.cc)

include_directories(
	platform/lib/helpers/
	platform/lib/linux/
	platform/lib/algorithms/
	platform/lib/error/
	platform/lib/logging/
	pkt/
	protocols/
	protocols/macros/
	protocols/l2/
	protocols/l3/
	protocols/l4/
	event/
	networking/
	statistics/
	cryptography/interface/
	cryptography/openssl/
	cryptography/wolfssl/
	cryptography/srv/
	logger/src/)

## command line options
#  -D NETOS_DEBUG_PKT_DECODE
set(CMAKE_C_FLAGS "-Wall -Wextra -Wno-unused-parameter -g -DNETOS_DEBUG_PKT_DECODE")
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wno-unused-parameter -DNETOS_DEBUG_PKT_DECODE -g")

add_library(netos_platform ${PLATFORM_SRC})

add_executable(netos_netwd ${NETWORKING_SRC})
target_link_libraries(netos_netwd netos_platform pthread jsoncpp netos_cryptography ssl crypto wolfssl)

add_executable(netos_logger ${LOGGER_SRC})
target_link_libraries(netos_logger netos_platform pthread jsoncpp)

add_executable(netos_pktgen ${IDS_PKT_GEN_SRC})
target_link_libraries(netos_pktgen netos_platform pthread jsoncpp)

add_library(netos_cryptography ${CRYPTOGRAPHY_SRC})
target_link_libraries(netos_cryptography netos_platform pthread)

add_executable(netos_crypto_srv ${CRYPTO_SRV_SRC})
target_link_libraries(netos_crypto_srv netos_platform pthread netos_cryptography ssl crypto wolfssl)

