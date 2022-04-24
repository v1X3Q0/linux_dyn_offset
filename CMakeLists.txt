cmake_minimum_required(VERSION 3.0.0)
project(parseandroidkernel VERSION 0.1.0)

if(NOT DEFINED ANDROID_TOOL_BASE)
    message(FATAL_ERROR "need ANDROID_TOOL_BASE")
endif()

add_library(android_family SHARED android_sections.cpp
    android_sections_gen.cpp android_variables.cpp)
target_include_directories(android_family PRIVATE ${ANDROID_TOOL_BASE}/common/local_util
    ${ANDROID_TOOL_BASE}/common/bgrep_c
    ${ANDROID_TOOL_BASE}/common/c_reginst
    ${ANDROID_TOOL_BASE}/common/hde_armv8
    ${ANDROID_TOOL_BASE}/linux/include
    ${ANDROID_TOOL_BASE}/common/kern_img/common
    ${ANDROID_TOOL_BASE}/common/kern_img/linux
    ${ANDROID_TOOL_BASE}/linux/helpers/tools/parseandroidkernrel/parseAndKern
    ${ANDROID_TOOL_BASE}/linux/rwDrv/include)
target_compile_definitions(android_family PRIVATE DYN_DISASM)
