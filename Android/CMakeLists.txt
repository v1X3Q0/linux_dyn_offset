project(${CMAKE_SYSTEM_NAME}_dyn_offset VERSION 0.1.0)

set(SOURCES_LIST
    android_sections.cpp
    android_sections_gen.cpp
    android_variables.cpp)


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

if (ARCH MATCHES "arm64" OR ARCH MATCHES "arm64e" OR ARCH MATCHES "aarch64")
    list(APPEND INCLUDE_LIST ${ANDROID_TOOL_BASE}/common/hde_armv8)
elseif(ARCH MATCHES "AMD64" OR ARCH MATCHES "i386" OR ARCH MATCHES "x86_64")
    list(APPEND INCLUDE_LIST ${ANDROID_TOOL_BASE}/common/hde_x86)
endif()

target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_LIST})
