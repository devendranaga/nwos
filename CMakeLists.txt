cmake_minimum_required(VERSION 3.9)

project(netos)

set(PLATFORM_SRC
	platform/lib/linux/raw_socket.cc
	platform/lib/linux/rng_linux.c
	platform/lib/linux/ioctl_nw.c
	platform/lib/logging/logging.c
	platform/lib/helpers/conversion.cc)

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
	ids/src/event/event_mgr.cc)

set(IDS_SRV_SRC
	${IDS_COMMON_SRC}
	ids/src/core/ids_main.cc)

set(IDS_PKT_GEN_SRC
	${IDS_COMMON_SRC}
	pktgen/pktgen.cc
	pktgen/pktgen_config.cc)

set(NETWORKING_SRC
	${IDS_COMMON_SRC}
	networking/network_main.cc
	networking/network_config.cc
	networking/pkt_parser.cc)

include_directories(
	platform/lib/helpers/
	platform/lib/linux/
	platform/lib/error/
	platform/lib/logging/
	ids/src/
	pkt/
	protocols/
	protocols/macros/
	protocols/l2/
	protocols/l3/
	protocols/l4/
	ids/src/core/
	ids/src/event/
	networking/)

set(CMAKE_C_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS "-Wall -Wextra")

add_library(netos_platform ${PLATFORM_SRC})

add_executable(netos_netwd ${NETWORKING_SRC})
target_link_libraries(netos_netwd netos_platform pthread jsoncpp)

add_executable(netos_logger ${LOGGER_SRC})
target_link_libraries(netos_logger netos_platform pthread)

add_executable(netos_ids ${IDS_SRV_SRC})
target_link_libraries(netos_ids netos_platform pthread jsoncpp)

add_executable(netos_pktgen ${IDS_PKT_GEN_SRC})
target_link_libraries(netos_pktgen netos_platform pthread jsoncpp)


