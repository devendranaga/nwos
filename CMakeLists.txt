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
	ids/src/packet_buf.cc
	ids/src/protocols/l2/eth.cc)

set(IDS_PKT_GEN_SRC
	${IDS_COMMON_SRC}
	ids/src/pktgen/pktgen.cc
	ids/src/pktgen/pktgen_config.cc)

include_directories(
	platform/lib/helpers/
	platform/lib/linux/
	platform/lib/error/
	platform/lib/logging/
	ids/src/
	ids/src/macros/
	ids/src/protocols/
	ids/src/protocols/l2/)

set(CMAKE_C_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS "-Wall -Wextra")

add_library(netos_platform ${PLATFORM_SRC})

add_executable(netos_logger ${LOGGER_SRC})
target_link_libraries(netos_logger netos_platform pthread)

add_executable(netos_pktgen ${IDS_PKT_GEN_SRC})
target_link_libraries(netos_pktgen netos_platform pthread jsoncpp)


