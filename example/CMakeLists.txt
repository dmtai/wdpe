cmake_minimum_required(VERSION 3.12)
project(wdpe_example CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS OFF)

# set path to directory with wdpe library
add_subdirectory(third_party/wdpe)

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE wdpe)