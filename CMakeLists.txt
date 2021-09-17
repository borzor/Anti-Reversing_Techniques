set(CMAKE_C_FLAGS "-Wall -Wextra -Wshadow -O3 -std=gnu11")

cmake_minimum_required(VERSION 3.16)
project(untitled)

set(CMAKE_CXX_STANDARD 17)

add_executable(untitled main.cpp)
