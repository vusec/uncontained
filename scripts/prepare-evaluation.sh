#!/usr/bin/env bash

set -e

SCRIPTS_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
UNCONTAINED_PATH=$(realpath $SCRIPTS_PATH/..)
KERNEL_TOOLS_PATH=$UNCONTAINED_PATH/kernel-tools
KERNEL_PATH=$UNCONTAINED_PATH/linux

prepare_checks() {
    read -p "[INFO] IMPORTANT! Before you continue make sure you added the .env file
    with the correct paths.
    When you're done press [ENTER] to continue
    "

    read -p "Do you want to build all the dependencies (running compile.sh)? (y/N) " answer

    if [[ $answer =~ ^[Yy]$ ]]; then
        $SCRIPTS_PATH/compile.sh
    fi

    read -p "Do you want to kill any dangling qemu-system-x86_64 processes? (y/N) " answer

    if [[ $answer =~ ^[Yy]$ ]]; then
        killall qemu-system-x86_64 || true
    fi
}

prepare_linux() {
    LINUX_INSTANCE=$1

    cd $KERNEL_TOOLS_PATH

    case $LINUX_INSTANCE in
        "baseline")
            INSTANCE_NAME="BASELINE"
            BRANCH_NAME="uncontained-baseline"
            ;;
        "kasan")
            INSTANCE_NAME="KASAN"
            BRANCH_NAME="uncontained-evaluation-kasan"
            ;;
        "uncontained")
            INSTANCE_NAME="UNCONTAINED"
            BRANCH_NAME="uncontained-evaluation"

            ;;
        *)
            echo "[INFO] invalid instance specified"
            exit 1
            ;;
    esac

    echo "[INFO] [PREPARE $INSTANCE_NAME]"

    echo "[INFO] Overwriting .config"
    (cd $KERNEL_PATH && git checkout uncontained)
    cp $KERNEL_PATH/syzbot.config $KERNEL_PATH/.config

    if [[ "$INSTANCE_NAME" == "BASELINE" ]]; then
        (cd $KERNEL_PATH && scripts/config --disable CONFIG_KASAN)
        (cd $KERNEL_PATH && scripts/config --disable CONFIG_KCSAN)
    fi

    echo "[INFO] switch linux to $BRANCH_NAME branch"
    (cd $KERNEL_PATH && git checkout $BRANCH_NAME)

    echo "[INFO] building kernel..."
    task kernel:bzImage
    if [[ "$INSTANCE_NAME" == "UNCONTAINED" ]]; then
        echo "[INFO] wiping build folder to remove runtime component"
        rm -rf $UNCONTAINED_PATH/build
        DISABLE_PRINTING=1 task build
        task passes:run -- lto:ContainerOfSanitizer
    fi
}
