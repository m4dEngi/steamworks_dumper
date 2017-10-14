cmake_minimum_required(VERSION 2.8)
project(swdumper)
include(CheckIncludeFileCXX)
check_include_file_cxx(cxxabi.h HAVE_CXXABI)

if(NOT HAVE_CXXABI)
  message(FATAL_ERROR "cxxabi.h not found")
endif(NOT HAVE_CXXABI)

add_executable(${PROJECT_NAME} "swdumper.cxx" "stuff.h" "util.h" "util.cxx" "machfile.h" "machfile.cxx" "include/hde/hde32.c")
