#!/usr/bin/env bash

set -e

SCRIPTS_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
UNCONTAINED_PATH=$(realpath $SCRIPTS_PATH/..)
KERNEL_TOOLS_PATH=$UNCONTAINED_PATH/kernel-tools
KERNEL_PATH=$UNCONTAINED_PATH/linux
SYZKALLER_RESULTS_PATH=$UNCONTAINED_PATH/evaluation/syzkaller/results

SYZKALLER_NR_RUNS=10
# 1 hour (and two minutes to be safe)
FUZZING_TIME=3720

source $SCRIPTS_PATH/prepare-evaluation.sh

prepare_syzkaller_eval() {
    echo "[WARNING!!!] This script will delete the syzkaller-workdir (containing previous fuzzing results) please backup before continuing if needed."
    read -p "Do you want to continue? (y/N) " answer
    if [[ ! $answer =~ ^[Yy]$ ]]; then
        exit 0
    fi
}

run_syzkaller_eval() {
    LINUX_INSTANCE=$1
    cd $KERNEL_TOOLS_PATH

    mkdir -p $SYZKALLER_RESULTS_PATH
    for ((i=0; i<SYZKALLER_NR_RUNS; i++))
    do
        echo "[INFO] running syzkaller run $i"
        # STEPS:
        # 1. wipe syzkaller-workdir
        echo "[INFO] deleting syzkaller-workdir."
        rm -rf $KERNEL_TOOLS_PATH/out/syzakker-workdir
        # 2. start syzkaller and run for FUZZING_TIME hour
        script -c 'task syzkaller:run' -q -a /dev/null &
        SYZKALLER_PID=$!
        # 3. wait for FUZZING_TIME
        sleep $FUZZING_TIME
        echo "[INFO] kill the syzkaller VM"
        # 4. kill syzkaller
        kill $SYZKALLER_PID
        echo "[INFO] copy out syzkaller-bench-$LINUX_INSTANCE-$i"
        # 5. move syzkaller-bench file
        cp $KERNEL_TOOLS_PATH/out/syzkaller-bench \
            $SYZKALLER_RESULTS_PATH/syzkaller-bench-$LINUX_INSTANCE-$i
    done
}

prepare_syzkaller_eval
prepare_checks

prepare_linux 'baseline'
echo "[INFO] [RUN BASELINE]"
run_syzkaller_eval 'baseline'

prepare_linux 'kasan'
echo "[INFO] [RUN KASAN]"
run_syzkaller_eval 'kasan'

prepare_linux 'uncontained'
echo "[INFO] [RUN UNCONTAINED]"
run_syzkaller_eval 'uncontained'
