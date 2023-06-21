cmake_minimum_required(VERSION 3.4.3)
project(uncontained-passes)

set(CMAKE_CXX_STANDARD 11)

find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

if (${LLVM_VERSION_MAJOR} VERSION_GREATER_EQUAL 10)
    set(CMAKE_CXX_STANDARD 14)
endif ()
message(STATUS "Using LLVM version ${LLVM_PACKAGE_VERSION}")

add_subdirectory(DumpContainerOf)
add_subdirectory(DumpTypes)
add_subdirectory(ContainerOfSanitizer)
add_subdirectory(SimpleDataflowChecker)
