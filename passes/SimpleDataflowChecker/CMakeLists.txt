add_llvm_library(LLVMSimpleDataflowCheckerPass MODULE
SimpleDataflowChecker.cpp
DataflowRule.cpp
DataflowSanitizer.cpp
)

include_directories(../include)

include(FetchContent)
FetchContent_Declare(
  yaml-cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
  GIT_TAG        0579ae3d976091d7d664aa9d2527e0d0cff25763
)
FetchContent_MakeAvailable(yaml-cpp)

target_compile_options(yaml-cpp PRIVATE -Wno-shadow)
set_property(TARGET yaml-cpp PROPERTY POSITION_INDEPENDENT_CODE ON)
include_directories(${yaml-cpp_SOURCE_DIR}/include)

target_link_libraries(LLVMSimpleDataflowCheckerPass PRIVATE yaml-cpp)
