cmake_minimum_required(VERSION 3.20)
project(MinHookThreads LANGUAGES CXX)
add_library(MinHookThreads SHARED thread_transaction.cpp thread_transaction.def)
set_target_properties(MinHookThreads PROPERTIES OUTPUT_NAME "MinHook.Threads"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
target_compile_features(MinHookThreads PRIVATE cxx_std_17)
target_compile_definitions(MinHookThreads PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(MinHookThreads PRIVATE /W4 /WX /GS)
