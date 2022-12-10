#
# Copyright (C) 2021, Xilinx Inc - All rights reserved
# Xilinx Lookahead XMA Plugin
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

cmake_minimum_required(VERSION 2.8.11)
include (CMakeDependentOption)
set(XLOOKAHEAD_PROJ "xilinx-u30-xlookahead")
set(LOOKAHEAD_LIBNAME "xlookahead")
set(XLOOKAHEAD_PROJ_VERSION "1.2.0")

find_program(UNAME_EXEC uname)
find_program(LSB_RELEASE_EXEC lsb_release)

execute_process(COMMAND ${LSB_RELEASE_EXEC} -is
    OUTPUT_VARIABLE LINUX_FLAVOR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if (${LINUX_FLAVOR} MATCHES "^(Ubuntu|Debian)")
        # amd64
        execute_process(
        COMMAND dpkg --print-architecture
        OUTPUT_VARIABLE CPACK_ARCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )
elseif (${LINUX_FLAVOR} MATCHES "^(RedHat|CentOS|Amazon|Fedora|SUSE)")
        # x86_64
        execute_process(
        COMMAND uname -m
        OUTPUT_VARIABLE CPACK_ARCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )
else()
        message( SEND_ERROR "Trying to build on incompatible system \"${LINUX_FLAVOR}\"." )
endif()

# Grab OS release short name
execute_process(COMMAND ${LSB_RELEASE_EXEC} -rs
        OUTPUT_VARIABLE LSB_RELEASE_REL_SHORT
        OUTPUT_STRIP_TRAILING_WHITESPACE)

if (${LINUX_FLAVOR} MATCHES "^Amazon")
        set(LSB_RELEASE_REL_SHORT "amzn${LSB_RELEASE_REL_SHORT}")
endif()

set(XLOOKAHEAD_PROJ_NAME "${XLOOKAHEAD_PROJ}_${XLOOKAHEAD_PROJ_VERSION}_${LSB_RELEASE_REL_SHORT}-${CPACK_ARCH}")

project(${XLOOKAHEAD_PROJ})
set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:/usr/lib/pkgconfig")

# Linking variables
find_package(PkgConfig REQUIRED)
pkg_check_modules(XRT REQUIRED	xrt)
pkg_check_modules(XMA REQUIRED libxma2api)
pkg_check_modules(XVBM REQUIRED xvbm)
pkg_check_modules(THREADS required)

add_library(XVBM_STATIC_LIB	STATIC IMPORTED GLOBAL)
set_target_properties(XVBM_STATIC_LIB
					PROPERTIES
					IMPORTED_LOCATION "/opt/xilinx/xvbm/lib/libxvbm.a")
set_target_properties(XVBM_STATIC_LIB
					PROPERTIES
					INTERFACE_INCLUDE_DIRECTORIES "/opt/xilinx/xvbm/include/")

if(THREADS_HAVE_PTHREAD_ARG)
  target_compile_options(${LOOKAHEAD_LIBNAME} PUBLIC "-pthread")
endif()


# Bring the headers into the project
include_directories(xlnx_utils)

# Generate the shared library from the sources
add_library(${LOOKAHEAD_LIBNAME} SHARED
    xlnx_utils/xlnx_queue.c
    xlnx_utils/xlnx_thread.c
    xlnx_utils/xlnx_ts_queue.c
    xlnx_la_xma.c
    xlnx_aq_core.c
    xlnx_rc_aq.c
    xlnx_spatial_aq.c
)

#set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_FLAGS	"${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -DDSA64 -fpermissive")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_FILE_LICENSE_PATH "/usr/share/doc/xilinx/u30")

target_compile_options(${LOOKAHEAD_LIBNAME}
	PUBLIC	${XRT_CFLAGS}
	PUBLIC	${XMA_CFLAGS}
	PUBLIC	${XVBM_CFLAGS}
)

target_include_directories(${LOOKAHEAD_LIBNAME}
	PUBLIC ${XRT_INCLUDE_DIRS}/xma2
	PUBLIC ${XRT_INCLUDE_DIRS}
	PUBLIC ${XVBM_INCLUDE_DIRS}
)

target_link_libraries(${LOOKAHEAD_LIBNAME} XVBM_STATIC_LIB)

if(CMAKE_THREAD_LIBS_INIT)
	target_link_libraries(${LOOKAHEAD_LIBNAME} ${CMAKE_THREAD_LIBS_INIT})
endif()

set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${XVBM_LDFLAGS} ${XRT_LDFLAGS} --stats -Bsymbolic")

# Set the location for library installation
install(TARGETS ${LOOKAHEAD_LIBNAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/xma_plugins)
install(FILES ${CPACK_RESOURCE_FILE_LICENSE} CONFIGURATIONS Release RUNTIME DESTINATION ${CPACK_FILE_LICENSE_PATH}/${XLOOKAHEAD_PROJ})

# Packaging section
set(CPACK_PACKAGE_NAME "${XLOOKAHEAD_PROJ}")
set(CPACK_PACKAGE_FILE_NAME "${XLOOKAHEAD_PROJ_NAME}")
set(CPACK_PACKAGE_VERSION "${XLOOKAHEAD_PROJ_VERSION}")
set(CPACK_PACKAGE_CONTACT "Rohit Athavale <rohit.athavale@xilinx.com>")
set(CPACK_PACKAGE_VENDOR "Xilinx")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Xilinx Lookahead Plugin")
set(CPACK_PACKAGE_DESCRIPTION "The Xilinx MPSoC based Lookahead Plugin controls
                               the accelerated FPGA lookahead kernel used to perform
                               spacial and temporal video quantization to aid video encoding.")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "xrt (>= 2.11), xilinx-xvbm (>= 1.0.2)")
set(CPACK_RPM_PACKAGE_REQUIRES "xrt >= 2.11, xilinx-xvbm >= 1.0.2")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/opt" "/opt/xilinx" "/usr/lib" "/usr/lib/pkgconfig" "/usr/share/doc/xilinx" "/usr/share/doc/xilinx/u30")
include(CPack)
