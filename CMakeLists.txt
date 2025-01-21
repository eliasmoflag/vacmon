cmake_minimum_required(VERSION 3.28)

cmake_policy(SET CMP0091 NEW)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_GENERATOR_PLATFORM Win32)

project(vacmon
    LANGUAGES
        C
        CXX
        ASM_MASM
)

include(FetchContent)

message(STATUS "Fetching minhook (951d13cfe48ecb3a511a9783572df6cd37274f0b)...")
FetchContent_Declare(minhook
	GIT_REPOSITORY
		"https://github.com/TsudaKageyu/minhook.git"
	GIT_TAG
        951d13cfe48ecb3a511a9783572df6cd37274f0b
)
FetchContent_MakeAvailable(minhook)

message(STATUS "Fetching xscan (9daf95748277d56430ffaf5c3eccc1a4052a8339)...")
FetchContent_Declare(xscan
	GIT_REPOSITORY
		"https://github.com/eliasmoflag/xscan.git"
	GIT_TAG
        9daf95748277d56430ffaf5c3eccc1a4052a8339
)
FetchContent_MakeAvailable(xscan)

file(GLOB_RECURSE SOURCES
    ./src/*.hpp
    ./src/*.cpp
    ./src/*.inc
    ./src/*.asm
    ./src/*.lua
)

add_library(vacmon SHARED ${SOURCES})

target_sources(vacmon PRIVATE ${SOURCES})

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${SOURCES})

target_link_libraries(vacmon PRIVATE
    minhook
    xscan::xscan
)

target_compile_definitions(vacmon PRIVATE
    NOMINMAX
)

target_compile_features(vacmon PUBLIC
	cxx_std_23
)

target_compile_options(vacmon
    PRIVATE
        /bigobj
)

target_compile_options(vacmon
    PRIVATE
        /GR-
)
