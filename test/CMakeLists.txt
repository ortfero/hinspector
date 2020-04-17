cmake_minimum_required(VERSION 3.10)

project(hinspector)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(hinspector test.cpp)

target_include_directories(hinspector PUBLIC
    "${PROJECT_SOURCE_DIR}/../include"
    "${PROJECT_SOURCE_DIR}/../thirdparty/include"
)
