cmake_minimum_required(VERSION 3.8)

project(
	wdpe 
	VERSION 1.0.0 
	DESCRIPTION "Library for writing data to signed PE files(exe/dll/etc...) \
		without authenticode digital signature invalidation."
	LANGUAGES CXX)

option(WDPE_BUILD_SHARED "Build shared library" OFF)

option(WDPE_BUILD_TESTS "Enable tests build" OFF)

add_library(wdpe_header_only INTERFACE)

target_include_directories(wdpe_header_only INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)

target_compile_features(wdpe_header_only INTERFACE cxx_std_11)

set(WDPE_SRCS src/wdpe.cpp)

if(WDPE_BUILD_SHARED OR BUILD_SHARED_LIBS)
	add_library(wdpe SHARED ${WDPE_SRCS})
else()
	add_library(wdpe STATIC ${WDPE_SRCS})
endif()

target_compile_definitions(wdpe PUBLIC WDPE_COMPILED_LIB)
target_include_directories(wdpe PUBLIC include)

if(WDPE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()