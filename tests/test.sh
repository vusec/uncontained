#!/bin/bash

set -e
set -u
# set -x

TESTS_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
BUILD_PATH="$TESTS_PATH/../build"

LLVM_DIR=${LLVM_DIR:-'/home/ubuntu/uncontained-llvm-project/build'}
export PATH="$LLVM_DIR/bin:$PATH"

# clang -O3 -emit-llvm -c $TESTS_PATH/test/test.c -o $TESTS_PATH/test/test.bc
# llvm-dis $TESTS_PATH/test/test.bc
# llvm-link -o $TESTS_PATH/test/test.linked.bc $TESTS_PATH/test/test.bc
# opt -load=$BUILD_PATH/passes/DumpContainerOf/LLVMDumpContainerOfPass.so -dump-container-of $TESTS_PATH/test/test.linked.bc -o $TESTS_PATH/test/test.out.bc
# clang $TESTS_PATH/test/test.out.bc -o $TESTS_PATH/test.out

# this run at compilation time for each module
# clang -O3 -flto -Xclang -load -Xclang $BUILD_PATH/passes/DumpContainerOf/LLVMDumpContainerOfPass.so $TESTS_PATH/test/test.c $TESTS_PATH/test/test1.c -o $TESTS_PATH/test.out

# this run at lto time
rm container_of_log.txt types_log.txt || true
# clang -flegacy-pass-manager -O2 -fuse-ld=lld -flto -Wl,-mllvm=-load=$BUILD_PATH/passes/DumpContainerOf/LLVMDumpContainerOfPass.so $TESTS_PATH/test/test.c $TESTS_PATH/test/test1.c -o $TESTS_PATH/test/test.out
# clang -flegacy-pass-manager -O2 -fuse-ld=lld -flto -Wl,-mllvm=-load=$BUILD_PATH/passes/DumpTypes/LLVMDumpTypesPass.so $TESTS_PATH/test/test.c $TESTS_PATH/test/test1.c -o $TESTS_PATH/test/test.out
# -Wl,--plugin-opt=save-temps
# -mllvm -print-changed -mllvm -filter-print-funcs=main
clang -flegacy-pass-manager -O2 -g -fsanitize=address -mllvm -asan-recover=1 -mllvm -asan-instrument-reads=0 -mllvm -asan-instrument-writes=0 -mllvm -asan-instrument-atomics=0 -mllvm -asan-instrument-byval=0 -fuse-ld=lld -flto -Wl,--plugin-opt=-lto-embed-bitcode=optimized $TESTS_PATH/test/test.c $TESTS_PATH/test/test1.c -o $TESTS_PATH/test/test.out
objcopy $TESTS_PATH/test/test.out --dump-section .llvmbc=$TESTS_PATH/test/test.bc
llvm-dis $TESTS_PATH/test/test.bc -o $TESTS_PATH/test/test.orig.ll
clang -flegacy-pass-manager -O2 -g -fsanitize=address -mllvm -asan-recover=1 -mllvm -asan-instrument-reads=0 -mllvm -asan-instrument-writes=0 -mllvm -asan-instrument-atomics=0 -mllvm -asan-instrument-byval=0 -fuse-ld=lld -flto -Wl,-mllvm=-load=$BUILD_PATH/passes/ContainerOfSanitizer/LLVMContainerOfSanitizerPass.so -Wl,--plugin-opt=-lto-embed-bitcode=optimized $TESTS_PATH/test/test.c $TESTS_PATH/test/test1.c -o $TESTS_PATH/test/test.out
objcopy $TESTS_PATH/test/test.out --dump-section .llvmbc=$TESTS_PATH/test/test.bc
llvm-dis $TESTS_PATH/test/test.bc
