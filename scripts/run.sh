#!/usr/bin/env bash

set -e

SCRIPTS_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
UNCONTAINED_PATH=$(realpath $SCRIPTS_PATH/..)
KERNEL_TOOLS_PATH=$UNCONTAINED_PATH/kernel-tools
KERNEL_PATH=$UNCONTAINED_PATH/linux

cd $KERNEL_TOOLS_PATH

echo "[INFO] Start syzkaller to do fuzzing (run for at least 24 hours)"
task syzkaller:run
