cmake_minimum_required(VERSION 3.9)

project(netos)

set(PLATFORM_SRC
	platform/lib/linux/raw_socket.c
	platform/lib/linux/rng_linux.c
	platform/lib/linux/ioctl_nw.c
	platform/lib/logging/logging.c)

set(LOGGER_SRC
	logger/src/logger.cc)

set(CMAKE_C_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS "-Wall -Wextra")

add_library(netos_platform ${PLATFORM_SRC})

add_executable(netos_logger ${LOGGER_SRC})
target_link_libraries(netos_logger netos_platform pthread)


