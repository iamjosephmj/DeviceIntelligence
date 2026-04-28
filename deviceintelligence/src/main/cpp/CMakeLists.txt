cmake_minimum_required(VERSION 3.22.1)
project(dicore CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(dicore SHARED
        dicore/syscalls.cpp
        dicore/sha256.cpp
        dicore/apkmap.cpp
        dicore/hex.cpp
        dicore/zip_parser.cpp
        dicore/sigblock_parser.cpp
        dicore/jni_bridge.cpp
        dicore/emu_probe_jni.cpp
        dicore/cloner_probe.cpp
        dicore/cloner_probe_jni.cpp
        dicore/runtime_probe_jni.cpp
)

# F12 emulator probe: per-ABI implementation. Each ABI build pulls
# in exactly one of these — emu_probe_arm64.cpp uses MRS asm that
# only the AArch64 toolchain accepts, emu_probe_x86_64.cpp uses
# __get_cpuid which is x86-only.
if (ANDROID_ABI STREQUAL "arm64-v8a")
    target_sources(dicore PRIVATE dicore/emu_probe_arm64.cpp)
elseif (ANDROID_ABI STREQUAL "x86_64")
    target_sources(dicore PRIVATE dicore/emu_probe_x86_64.cpp)
endif()

find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(dicore
        ${log-lib}
        ${android-lib}
        dl
)

target_include_directories(dicore PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(dicore PRIVATE
        -Wall
        -Wextra
        -Werror
        -Wno-unused-parameter
        -fvisibility=hidden
        -fvisibility-inlines-hidden
        -ffunction-sections
        -fdata-sections
        -fno-rtti
        -fno-exceptions
        -fstack-protector-strong
)

target_link_options(dicore PRIVATE
        -Wl,--gc-sections
        -Wl,--exclude-libs,ALL
        -Wl,-z,relro
        -Wl,-z,now
        # 16 KB ELF segment alignment. Required for Android 15+ on
        # devices that boot with the 16 KB page size kernel (Pixel 8a/9
        # and the API 35 / API 36 emulators); without this, the loader
        # rejects the .so with "ELF segment alignment less than page
        # size". The flag is harmless on 4 KB devices — the loader still
        # maps at 4 KB granularity, just with extra zero padding between
        # segments. Pairs with AGP's automatic `zipalign -p 16384` for
        # APK-side .so packaging (AGP 8.5+).
        -Wl,-z,max-page-size=16384
)
