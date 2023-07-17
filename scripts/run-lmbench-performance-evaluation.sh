#!/usr/bin/env bash

set -e

SCRIPTS_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
UNCONTAINED_PATH=$(realpath $SCRIPTS_PATH/..)
KERNEL_TOOLS_PATH=$UNCONTAINED_PATH/kernel-tools
KERNEL_PATH=$UNCONTAINED_PATH/linux
LMBENCH_PATH=$UNCONTAINED_PATH/evaluation/lmbench
LMBENCH_RESULTS_PATH=$LMBENCH_PATH/results

LMBENCH_NR_RUNS=10

source $SCRIPTS_PATH/prepare-evaluation.sh

build_lmbench() {
    cd $LMBENCH_PATH

    if [ ! -e lmbench ]
    then
        echo "[INFO] download LMBench"
        git clone https://github.com/intel/lmbench.git
        cd lmbench
        git checkout 701c6c35b0270d4634fb1dc5272721340322b8ed
        git am $SCRIPTS_PATH/../patches/lmbench/0001-Link-against-tirpc.patch
        git am $SCRIPTS_PATH/../patches/lmbench/0002-Fix-rpc-include-error.patch
    fi

    echo "[INFO] build LMBench"
    cd lmbench
    make

    echo "[INFO] copy CONFIG.syzkaller into LMBench"
    cp $LMBENCH_PATH/CONFIG.syzkaller $LMBENCH_PATH/lmbench/bin/x86_64-linux-gnu/
}

run_lmbench () {
    LINUX_INSTANCE=$1

    cd $KERNEL_TOOLS_PATH

    echo "[INFO] launch VM"
    script -c 'task qemu:syzkaller' -q -a /dev/null &
    QEMU_PID=$!

    for i in {1..3}
    do
        echo "[INFO] try to connect to VM and copy in LMBench"
        sleep 60
        set +e
        task syzkaller:scp -- $LMBENCH_PATH/lmbench root@localhost:
        if [ $? -eq 0 ]; then
            # succeeded
            break
        fi
        set -e
    done

    echo "[INFO] LMBench copying done, install dependencies"
    task syzkaller:ssh -- -o StrictHostKeyChecking=no 'sudo apt update'
    task syzkaller:ssh -- -o StrictHostKeyChecking=no 'sudo apt install -y make'

    echo "[INFO] run LMBench"
    for ((i=0; i<LMBENCH_NR_RUNS; i++))
    do
        echo "[INFO] running LMBench run $i"
        task syzkaller:ssh -- -o StrictHostKeyChecking=no 'cd lmbench && make rerun'
    done

    echo "[INFO] copy out LMBench results"
    mkdir -p $LMBENCH_RESULTS_PATH
    task syzkaller:scp -- 'root@localhost:lmbench/results/x86_64-linux-gnu/*' $LMBENCH_RESULTS_PATH

    echo "[INFO] kill the syzkaller VM"
    kill $QEMU_PID

    echo "[INFO] give LMBench results corret names"
    for ((i=0; i<LMBENCH_NR_RUNS; i++))
    do
        mv $LMBENCH_RESULTS_PATH/syzkaller.$i $LMBENCH_RESULTS_PATH/$LINUX_INSTANCE.$i
    done
}

# [PREPARATION]
prepare_checks

build_lmbench

# [BASELINE]
prepare_linux 'baseline'
echo "[INFO] [RUN BASELINE]"
run_lmbench 'baseline'

# [KASAN]
prepare_linux 'kasan'
echo "[INFO] [RUN KASAN]"
run_lmbench 'kasan'

# [UNCONTAINED]
prepare_linux 'uncontained'
echo "[INFO] [RUN UNCONTAINED]"
run_lmbench 'uncontained'
