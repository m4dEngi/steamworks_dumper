cmake_minimum_required(VERSION 3.5)

include(FindPkgConfig)
pkg_check_modules (CAPSTONE REQUIRED capstone)

project(steamworks_dumper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(steamworks_dumper
    main.cpp
    moduleimage.h
    moduleimage.cpp
    clientmodule.h
    clientmodule.cpp
    dumperbase.h
    dumperbase.cpp
    enumdumper.h
    enumdumper.cpp
    clientinterfacedumper.h
    clientinterfacedumper.cpp
    callbackdumper.h
    callbackdumper.cpp
)

target_link_libraries(steamworks_dumper ${CAPSTONE_LIBRARIES})
