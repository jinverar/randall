cmake_minimum_required(VERSION 3.20)
project(RandfuzzDbg LANGUAGES CXX)

# Windows-only dbgeng extension. Configure with a kit that has dbgeng.h / dbgeng.lib
# (Debugging Tools for Windows / Windows SDK).
if(NOT WIN32)
  message(FATAL_ERROR "RandfuzzDbg builds on Windows only")
endif()

add_library(RandfuzzDbg SHARED src/RandfuzzDbg.cpp src/RandfuzzDbg.def)
target_compile_features(RandfuzzDbg PRIVATE cxx_std_17)
target_compile_definitions(RandfuzzDbg PRIVATE WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
target_link_libraries(RandfuzzDbg PRIVATE dbgeng)

# Optional: point at SDK if not on default include/lib path
# target_include_directories(RandfuzzDbg PRIVATE "$ENV{WindowsSdkDir}Include")
