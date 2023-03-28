cmake_minimum_required(VERSION 3.0.0)
project(${CMAKE_SYSTEM_NAME}_dyn_offset VERSION 0.1.0)

set(DYNOFFSET_CFLAGS "")
set(INCLUDE_LIST
    ${ANDROID_TOOL_BASE}/common/local_util
    ${ANDROID_TOOL_BASE}/common/bgrep_c
    ${ANDROID_TOOL_BASE}/common/c_reginst
    ${ANDROID_TOOL_BASE}/common/kern_img/common
    ${ANDROID_TOOL_BASE}/common/kern_img/linux
    ${ANDROID_TOOL_BASE}/linux/include
    ${ANDROID_TOOL_BASE}/linux/helpers/tools/parseandroidkernrel/parseAndKern
    ${ANDROID_TOOL_BASE}/linux/rwDrv/include
    ${CMAKE_CURRENT_BINARY_DIR}
    )
if (ARCH MATCHES "arm64" OR ARCH MATCHES "arm64e" OR ARCH MATCHES "aarch64")
    list(APPEND INCLUDE_LIST ${ANDROID_TOOL_BASE}/common/hde_armv8)
elseif(ARCH MATCHES "AMD64" OR ARCH MATCHES "i386" OR ARCH MATCHES "x86_64")
    list(APPEND INCLUDE_LIST ${ANDROID_TOOL_BASE}/common/hde_x86)
endif()

# dynamic circumstances, add krw_util
list(APPEND INCLUDE_LIST
    ${ANDROID_TOOL_BASE}/common/krw_util/krw_util)

set(SOURCES_LIST
    common/finddyn.cpp
    common/kdlsym.cpp
    common/sections.cpp
    common/structs.cpp)

if (${CMAKE_SYSTEM_NAME} MATCHES "Android")
    list(APPEND SOURCES_LIST ${CMAKE_SYSTEM_NAME}/android_sections.cpp)
    if (${LINUX_FAMILY} MATCHES "Sargo")
        set(LINUX_FAMILY_FLAG "-DSARGO=1 ")
    endif()
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    if (NOT DEFINED LINUX_FAMILY)
        set(LINUX_FAMILY "Debian")
        message("-- LINUX_FAMILY not specified, using ${LINUX_FAMILY}")
    endif()
    if (NOT DEFINED RELEASE_VERSION)
        set(RELEASE_VERSION 10)
        message("-- RELEASE_VERSION not specified, using ${RELEASE_VERSION}")
    endif()
    if (NOT DEFINED KERNEL_VERSION)
        set(KERNEL_VERSION "4.19")
        message("-- KERNEL_VERSION not specified, using ${KERNEL_VERSION}")
    endif()

    list(APPEND SOURCES_LIST ${CMAKE_SYSTEM_NAME}/Linux_dyn_offset.cpp)
    if (${LINUX_FAMILY} MATCHES "Debian")
        set(LINUX_FAMILY_FLAG "-DDEBIAN=1 ")
    endif()
endif()

string(APPEND DYNOFFSET_CFLAGS ${LINUX_FAMILY_FLAG})

# generate our header file to be used for ordering the heuristics
execute_process(
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/generateParse.py ${LINUX_FAMILY} ${RELEASE_VERSION} ${KERNEL_VERSION} ${CMAKE_CURRENT_SOURCE_DIR}/heuristic_list.json ${CMAKE_CURRENT_BINARY_DIR}/finddyn.h
)

add_library(${PROJECT_NAME} SHARED ${SOURCES_LIST})
target_compile_definitions(${PROJECT_NAME} PRIVATE ${DYNOFFSET_CFLAGS})

target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_LIST})
