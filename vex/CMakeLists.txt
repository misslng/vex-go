cmake_minimum_required(VERSION 3.10)
project(vex C)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 添加编译选项
add_compile_definitions(DPYVEX)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g)
else()
    add_compile_options(-O2)
endif()

# 添加包含目录
include_directories(pub priv)

# 生成 libvex_guest_offsets.h
add_executable(genoffsets auxprogs/genoffsets.c)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/pub/libvex_guest_offsets.h
    COMMAND genoffsets > ${CMAKE_CURRENT_SOURCE_DIR}/pub/libvex_guest_offsets.h
    DEPENDS genoffsets
)

# 添加所有源文件
set(VEX_SOURCES
    priv/ir_defs.c
    priv/ir_match.c
    priv/ir_opt.c
    priv/ir_inject.c
    priv/main_globals.c
    priv/main_util.c
    priv/s390_disasm.c
    priv/host_x86_defs.c
    priv/host_amd64_defs.c
    priv/host_arm_defs.c
    priv/host_arm64_defs.c
    priv/host_ppc_defs.c
    priv/host_riscv64_defs.c
    priv/host_s390_defs.c
    priv/host_mips_defs.c
    priv/host_x86_isel.c
    priv/host_amd64_isel.c
    priv/host_arm_isel.c
    priv/host_arm64_isel.c
    priv/host_ppc_isel.c
    priv/host_riscv64_isel.c
    priv/host_s390_isel.c
    priv/host_mips_isel.c
    priv/host_generic_maddf.c
    priv/host_generic_regs.c
    priv/host_generic_simd64.c
    priv/host_generic_simd128.c
    priv/host_generic_simd256.c
    priv/host_generic_reg_alloc2.c
    priv/host_generic_reg_alloc3.c
    priv/guest_generic_x87.c
    priv/guest_generic_bb_to_IR.c
    priv/guest_x86_helpers.c
    priv/guest_amd64_helpers.c
    priv/guest_arm_helpers.c
    priv/guest_arm64_helpers.c
    priv/guest_ppc_helpers.c
    priv/guest_riscv64_helpers.c
    priv/guest_s390_helpers.c
    priv/guest_mips_helpers.c
    priv/guest_x86_toIR.c
    priv/guest_amd64_toIR.c
    priv/guest_arm_toIR.c
    priv/guest_arm64_toIR.c
    priv/guest_ppc_toIR.c
    priv/guest_riscv64_toIR.c
    priv/guest_s390_toIR.c
    priv/guest_mips_toIR.c
)

if(MULTIARCH)
    list(APPEND VEX_SOURCES priv/multiarch_main_main.c)
else()
    list(APPEND VEX_SOURCES priv/main_main.c)
endif()

# 创建静态库和动态库
add_library(vex_static STATIC ${VEX_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/pub/libvex_guest_offsets.h)
add_library(vex SHARED ${VEX_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/pub/libvex_guest_offsets.h)

# 设置输出名称
set_target_properties(vex_static PROPERTIES OUTPUT_NAME vex)
set_target_properties(vex PROPERTIES OUTPUT_NAME vex)

# 如果是 MinGW，添加导出所有符号的选项
if(MINGW)
    set_target_properties(vex PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
endif()
