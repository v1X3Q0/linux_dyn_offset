cmake_minimum_required(VERSION 3.0.0)
project(${CMAKE_SYSTEM_NAME}_dyn_offset VERSION 0.1.0)

if(NOT DEFINED ANDROID_TOOL_BASE)
    message(FATAL_ERROR "need ANDROID_TOOL_BASE")
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Android")
    set(SOURCES_LIST
        ${CMAKE_SYSTEM_NAME}/android_sections.cpp
        ${CMAKE_SYSTEM_NAME}/android_sections_gen.cpp
        ${CMAKE_SYSTEM_NAME}/android_variables.cpp)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(SOURCES_LIST
        ${CMAKE_SYSTEM_NAME}/${CMAKE_SYSTEM_NAME}_dyn_offset.cpp)
endif()

add_library(${PROJECT_NAME} STATIC ${SOURCES_LIST})

set(INCLUDE_LIST
    ${ANDROID_TOOL_BASE}/common/local_util
    ${ANDROID_TOOL_BASE}/common/bgrep_c
    ${ANDROID_TOOL_BASE}/common/c_reginst
    ${ANDROID_TOOL_BASE}/common/kern_img/common
    ${ANDROID_TOOL_BASE}/common/kern_img/linux
    ${ANDROID_TOOL_BASE}/linux/include
    ${ANDROID_TOOL_BASE}/linux/helpers/tools/parseandroidkernrel/parseAndKern
    ${ANDROID_TOOL_BASE}/linux/rwDrv/include
    )

if (ARCH MATCHES "arm64" OR ARCH MATCHES "arm64e")
    list(APPEND INCLUDE_LIST ${ANDROID_TOOL_BASE}/common/hde_armv8)
elseif(ARCH MATCHES "AMD64" OR ARCH MATCHES "i386" OR ARCH MATCHES "x86_64")
    list(APPEND INCLUDE_LIST ${ANDROID_TOOL_BASE}/common/hde_x86)
endif()

target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_LIST})
