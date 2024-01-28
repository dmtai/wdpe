cmake_minimum_required(VERSION 3.12)
project(wdpe_tests)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR} ${CMAKE_MODULE_PATH})
set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR} ${CMAKE_PREFIX_PATH})

find_package(GTest REQUIRED)
find_package(LIEF REQUIRED)

file(GLOB_RECURSE SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wdpe/*_test.*pp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} 
  PRIVATE 
    ../include
)

target_link_libraries(${PROJECT_NAME} 
  PRIVATE 
    GTest::gtest_main
    LIEF::LIEF
)

add_test(NAME ${PROJECT_NAME} 
         COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME} ${FILES_FOR_TEST_PATHS})
set_tests_properties(${PROJECT_NAME} PROPERTIES TIMEOUT 10000)