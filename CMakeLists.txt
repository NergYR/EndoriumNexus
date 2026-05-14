cmake_minimum_required(VERSION 3.28)

project(EndoriumNexus VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

option(NEXUS_BUILD_TESTS "Build Endorium Nexus tests" ON)
option(NEXUS_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(NEXUS_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/backend/cmake")
include(Sanitizers)

add_subdirectory(backend)
