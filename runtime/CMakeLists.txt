cmake_minimum_required(VERSION 3.4.3)
project(uncontained-runtime)

set(CMAKE_CXX_STANDARD 11)

if(DEFINED ENV{ENABLE_KASAN}) # DEFINED ENABLE_KASAN

if(NOT DEFINED ENV{KERNEL})
  message(FATAL_ERROR "$KERNEL is not defined")
endif()

SET (OLD_PWD $ENV{PWD}) # just make sure that PWD is reset correctly
set(ENV{PWD} "$ENV{ROOT}")
execute_process(COMMAND task kernel:make -- print-NOSTDINC_FLAGS
  WORKING_DIRECTORY $ENV{ROOT}
  OUTPUT_VARIABLE NOSTDINC_FLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND task kernel:make -- print-LINUXINCLUDE
  WORKING_DIRECTORY $ENV{ROOT}
  OUTPUT_VARIABLE LINUXINCLUDE
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND task kernel:make -- print-KBUILD_CFLAGS
  WORKING_DIRECTORY $ENV{ROOT}
  OUTPUT_VARIABLE KBUILD_CFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
set(ENV{PWD} ${OLD_PWD})

string (REPLACE ./ $ENV{KERNEL}/ LINUXINCLUDE ${LINUXINCLUDE})

string (CONCAT CMAKE_C_FLAGS
                    "-D__KERNEL__ -Qunused-arguments -fmacro-prefix-map=./= "
                    "${NOSTDINC_FLAGS} ${LINUXINCLUDE} ${KBUILD_CFLAGS} "
                    "-fno-function-sections -fno-data-sections")

include_directories($ENV{KERNEL}/arch/x86/include)
include_directories($ENV{KERNEL}/arch/x86/include/generated)
include_directories($ENV{KERNEL}/include)
include_directories($ENV{KERNEL}/arch/x86/include/uapi)
include_directories($ENV{KERNEL}/arch/x86/include/uapi/generated)
include_directories($ENV{KERNEL}/include/uapi)
include_directories($ENV{KERNEL}/include/generated/uapi)

# look for kasan.h
include_directories($ENV{KERNEL}/mm/kasan)
# look for percpu-internal.h
include_directories($ENV{KERNEL}/mm/)

if(DEFINED ENV{DISABLE_PRINTING})
  add_definitions(-DDISABLE_PRINTING)
endif()

set(SOURCES
  uncontained_kasan.c
)

include_directories(./include)

# enable_language(ASM)

add_library(uncontained STATIC
  ${SOURCES}
)

endif() # DEFINED ENABLE_KASAN
