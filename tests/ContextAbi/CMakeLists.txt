cmake_minimum_required(VERSION 3.20)
project(ContextAbi LANGUAGES CXX)
add_executable(context_abi context_abi.cpp)
target_compile_features(context_abi PRIVATE cxx_std_17)
