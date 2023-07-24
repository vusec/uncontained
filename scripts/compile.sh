#!/usr/bin/env bash

set -e

SCRIPTS_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
UNCONTAINED_PATH=$(realpath $SCRIPTS_PATH/..)
KERNEL_TOOLS_PATH=$UNCONTAINED_PATH/kernel-tools
KERNEL_PATH=$UNCONTAINED_PATH/linux

cd $KERNEL_TOOLS_PATH

read -p "[INFO] IMPORTANT! Before you continue make sure you added the .env file
with the correct paths.
When you're done press [ENTER] to continue
"

echo "[INFO] ensure that kernel-tools submodules are updated"
git submodule update --init

read -p "Do you want to create the syzkaller image? (y/N) " answer

if [[ $answer =~ ^[Yy]$ ]]; then
    task syzkaller:create-image
fi

read -p "Do you want to compile LLVM, the kernel and syzkaller? (Y/n) " answer

if [[ $answer =~ ^[Yy]$ ]] || [[ -z $answer ]]; then
    echo "[INFO] Build uncontained-llvm-project"
    task llvm:config llvm:build

    echo "[INFO] Ensure you are on the right kernel commit"
    (cd $KERNEL_PATH && git checkout uncontained-evaluation)

    echo "[INFO] Overwriting .config"
    cp $KERNEL_PATH/syzbot.config $KERNEL_PATH/.config

    echo "[INFO] Build the kernel once (required to build the runtime library)"
    task kernel:bzImage

    echo "[INFO] Force rebuilding the passes and runtime library"
    rm -rf $UNCONTAINED_PATH/build
    task build

    echo "[INFO] Compile the kernel with the sanitizer"
    task passes:run -- lto:ContainerOfSanitizer

    echo "[INFO] Apply syzkaller patch if necessary"
    set +e
    (cd $KERNEL_TOOLS_PATH/syzkaller && git am $UNCONTAINED_PATH/patches/syzkaller/0001-syzkaller-uncontained-ignore-non-uncontained-reports.patch)

    if [ $? -ne 0 ]; then
        echo "[WARNING] Applying syzkaller patch failed, hopefully already applied!"
        (cd $KERNEL_TOOLS_PATH/syzkaller && git am --abort)
    fi
    set -e

    echo "[INFO] Compile syzkaller and generate config"
    task syzkaller:build syzkaller:config
fi
