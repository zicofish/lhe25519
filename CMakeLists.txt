
#cmake_minimum_required(VERSION 3.12)
project(lhe_curve25519)

# Compilation flags
set(CMAKE_C_FLAGS "-pthread -Wall -march=native -O3")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11")

add_executable(lhe test.cpp)
#add_executable(lhe25519_unittest lhe25519_unittest.cpp)
