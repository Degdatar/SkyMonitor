cmake_minimum_required(VERSION 3.24)
project(SkyMonitor VERSION 0.1.0 LANGUAGES CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Keep in sync with the CommonLibSSE-NG branch used by the SkyOS source tree.
FetchContent_Declare(
    CommonLibSSE
    GIT_REPOSITORY https://github.com/alandtse/CommonLibSSE-NG.git
    GIT_TAG ng
    GIT_SUBMODULES ""
    GIT_SHALLOW TRUE
)

set(BUILD_TESTS OFF CACHE BOOL "Disable CommonLibSSE-NG tests" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "Disable CommonLibSSE-NG tests" FORCE)
set(ENABLE_SKYRIM_VR OFF CACHE BOOL "SkyMonitor supports Skyrim SE/AE, not VR" FORCE)

# CommonLib is a build dependency; its own install rules must not be copied into
# the deployable SkyMonitor package.
set(CMAKE_SKIP_INSTALL_RULES ON)
FetchContent_MakeAvailable(CommonLibSSE)
set(CMAKE_SKIP_INSTALL_RULES OFF)
include("${commonlibsse_SOURCE_DIR}/cmake/CommonLibSSE.cmake")

add_commonlibsse_plugin(SkyMonitor
    NAME "SkyMonitor"
    AUTHOR "SkyOS"
    VERSION ${PROJECT_VERSION}
    SOURCES
        src/monitor.cpp
        src/monitor_profiler.cpp
        src/app_module_entry.cpp
)

target_include_directories(SkyMonitor PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_features(SkyMonitor PRIVATE cxx_std_23)
target_compile_definitions(SkyMonitor PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    SKYOS_SKYMONITOR_EXPORTS
)
target_precompile_headers(SkyMonitor PRIVATE src/pch.h)
target_link_libraries(SkyMonitor PRIVATE Psapi Pdh Advapi32 Dbghelp Shell32)

# SkyOS owns the shared shell and calls the exported monitoring/profile API.
install(TARGETS SkyMonitor RUNTIME DESTINATION "Data/SKSE/Plugins")
install(DIRECTORY data/PrismaUI/views/SkyMonitor
    DESTINATION "Data/PrismaUI/views")
install(DIRECTORY data/SKSE/Plugins/SkyOS/Mods/SkyMonitor
    DESTINATION "Data/SKSE/Plugins/SkyOS/Mods")
install(DIRECTORY data/SKSE/Plugins/SkyOS/Mods/SkyViewer/SkyMonitor
    DESTINATION "Data/SKSE/Plugins/SkyOS/Mods/SkyViewer")

set(CPACK_PACKAGE_NAME "SkyMonitor")
set(CPACK_PACKAGE_VENDOR "SkyOS")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "SkyMonitor-${PROJECT_VERSION}-SkyrimSE-AE")
set(CPACK_GENERATOR "ZIP")
include(CPack)
