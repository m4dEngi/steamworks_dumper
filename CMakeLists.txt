cmake_minimum_required(VERSION 3.5)

project(steamworks_dumper LANGUAGES CXX)

include(FindPkgConfig)
pkg_check_modules (CAPSTONE REQUIRED capstone)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(external)

add_executable(steamworks_dumper
    src/main.cpp
    src/moduleimage.h
    src/moduleimage.cpp
    src/clientmodule.h
    src/clientmodule.cpp
    src/dumperbase.h
    src/dumperbase.cpp
    src/randomstack.cpp
    src/randomstack.h
    src/enumdumper.h
    src/enumdumper.cpp
    src/clientinterfacedumper.h
    src/clientinterfacedumper.cpp
    src/callbackdumper.h
    src/callbackdumper.cpp
    src/emsgdumper.h
    src/emsgdumper.cpp
)

target_link_libraries(steamworks_dumper ${CAPSTONE_LIBRARIES} argparse)
