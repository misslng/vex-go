cmake_minimum_required(VERSION 3.10)
project(pyvex C)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 添加源文件
set(SOURCES
    pyvex.c
    postprocess.c
    analysis.c
    logging.c
)

# 创建共享库
add_library(pyvex SHARED ${SOURCES})

# 添加头文件路径
target_include_directories(pyvex PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ../vex/pub
)
add_definitions(-DVEXMULTIARCH)
# 链接 libvex.a
target_link_libraries(pyvex PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/libvex.a
)

# 生成导出库
add_custom_command(TARGET pyvex PRE_LINK
    COMMAND dlltool -d "${CMAKE_CURRENT_SOURCE_DIR}/pyvex.def" 
                    -l "${CMAKE_CURRENT_BINARY_DIR}/libpyvex.a"
    COMMENT "Generating import library from def file"
)

# 添加链接选项
target_link_options(pyvex PRIVATE
    "-Wl,--enable-stdcall-fixup"
    "-Wl,--kill-at"
    "${CMAKE_CURRENT_BINARY_DIR}/libpyvex.a"
)

# 设置输出名称
set_target_properties(pyvex PROPERTIES
    PREFIX ""
    OUTPUT_NAME "pyvex")
