#!/bin/bash

set -e
set -u
# set -x

TESTS_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
BUILD_PATH="$TESTS_PATH/../build"

LLVM_DIR=${LLVM_DIR:-'/home/ubuntu/uncontained-llvm-project/build'}
export PATH="$LLVM_DIR/bin:$PATH"

arrFailures=()

function check_hit() {
    filename=$1
    config="$TESTS_PATH/config.yaml"
    # support ad-hoc configs
    if [ -f ${filename%.c}.yaml ]; then
        config=${filename%.c}.yaml
    fi
    # this runs at lto time
    clang -flegacy-pass-manager -O1 -g -fuse-ld=lld -flto -Wl,--plugin-opt=-lto-embed-bitcode=optimized ${filename} -o ${filename%.c}.out
    objcopy ${filename%.c}.out --dump-section .llvmbc=${filename%.c}.bc
    llvm-dis ${filename%.c}.bc
    echo "---> ${filename}"
    clang -flegacy-pass-manager -O1 -g -fuse-ld=lld -flto -Wl,-mllvm=-load=$BUILD_PATH/passes/SimpleDataflowChecker/LLVMSimpleDataflowCheckerPass.so -Wl,-mllvm=-config=$config -Wl,-mllvm=-dump-reports="" -Wl,-mllvm=-print-instructions=1 -Wl,--plugin-opt=-lto-embed-bitcode=optimized ${filename} -o ${filename%.c}.out | tee out.txt
    grep -q "DATAFLOW RULE TRIGGER" out.txt || { echo "ERROR: RULE DID NOT TRIGGER" && arrFailures[${#arrFailures[@]}]=${filename}; }
    rm out.txt
}

function check_nohit() {
    filename=$1
    config="$TESTS_PATH/config.yaml"
    # support ad-hoc configs
    if [ -f ${filename%.c}.yaml ]; then
        config=${filename%.c}.yaml
    fi
    # this runs at lto time
    clang -flegacy-pass-manager -O1 -g -fuse-ld=lld -flto -Wl,--plugin-opt=-lto-embed-bitcode=optimized ${filename} -o ${filename%.c}.out
    objcopy ${filename%.c}.out --dump-section .llvmbc=${filename%.c}.bc
    llvm-dis ${filename%.c}.bc
    echo "---> ${filename}"
    clang -flegacy-pass-manager -O1 -g -fuse-ld=lld -flto -Wl,-mllvm=-load=$BUILD_PATH/passes/SimpleDataflowChecker/LLVMSimpleDataflowCheckerPass.so -Wl,-mllvm=-config=$config -Wl,-mllvm=-dump-reports="" -Wl,-mllvm=-print-instructions=1 -Wl,--plugin-opt=-lto-embed-bitcode=optimized ${filename} -o ${filename%.c}.out | tee out.txt
    { grep -q "DATAFLOW RULE TRIGGER" out.txt && echo "ERROR: RULE DID TRIGGER WHEN SHOULDN'T" && arrFailures[${#arrFailures[@]}]=${filename}; } || true
    rm out.txt
}
if [[ "${1-}" == *"_hit"* ]]; then
    check_hit $1
elif [[ "${1-}" == *"_nohit"* ]]; then
    check_nohit $1
else
    for filename in $TESTS_PATH/testDF/test_hit*.c; do
        [ -e "$filename" ] || continue
        check_hit $filename
    done

    for filename in $TESTS_PATH/testDF/test_nohit*.c; do
        [ -e "$filename" ] || continue
        check_nohit $filename
    done
fi

if [ ${#arrFailures[@]} -eq 0 ]; then
    echo "[OK]"
    exit 0
fi

echo "[FAILURES]"
for value in "${arrFailures[@]}"
do
    echo $value
done
exit 1
