#!/usr/bin/env bash

set -e

SCRIPTS_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
UNCONTAINED_PATH=$(realpath $SCRIPTS_PATH/..)
KERNEL_TOOLS_PATH=$UNCONTAINED_PATH/kernel-tools
KERNEL_PATH=$UNCONTAINED_PATH/linux
STATIC_ANALYZERS_RESULTS_PATH=$UNCONTAINED_PATH/evaluation/static-analyzer-results

# we don't want to compile the runtime and not have KASAN/KCOV enabled
export unset ENABLE_KASAN
export unset ENABLE_SYZKALLER

cd $KERNEL_TOOLS_PATH

# go to a branch that is guaranteed to have the `syzbot-nosan.config`.
(cd $KERNEL_PATH && git checkout uncontained-static-analysis-tainted)

echo "[INFO] Overwriting .config (disabling sanitizers)"
cp $KERNEL_PATH/syzbot-nosan.config $KERNEL_PATH/.config
task kernel:bzImage

echo "[INFO] wiping build folder to remove runtime component"
rm -rf $UNCONTAINED_PATH/build
task build

mkdir -p $STATIC_ANALYZERS_RESULTS_PATH

echo "[INFO] running coccinelle script for Pattern 4 (Past-the-end Iterator)"
# Pattern 4 (Past-the-end Iterator)
(cd $KERNEL_PATH && git checkout uncontained-static-analysis-tainted)
(cd $KERNEL_PATH && make coccicheck COCCI=scripts/coccinelle/iterators/use_after_iter.cocci > $STATIC_ANALYZERS_RESULTS_PATH/reports-use_after_iter.txt)
sed -i '1,10d' $STATIC_ANALYZERS_RESULTS_PATH/reports-use_after_iter.txt
cat $STATIC_ANALYZERS_RESULTS_PATH/reports-use_after_iter.txt | sort -u > $STATIC_ANALYZERS_RESULTS_PATH/reports-use_after_iter-filtered.txt
mv $STATIC_ANALYZERS_RESULTS_PATH/reports-use_after_iter-filtered.txt $STATIC_ANALYZERS_RESULTS_PATH/reports-use_after_iter.txt

echo "[INFO] running LLVM pass for Pattern 1 (Statically Incompatible Containers) & Pattern 2 (Empty-list Confusion) & Pattern 5 (Containers with Contracts)"
# Pattern 1 (Statically Incompatible Containers) & Pattern 2 (Empty-list Confusion) & Pattern 5 (Containers with Contracts)
(cd $KERNEL_PATH && git checkout uncontained-static-analysis-tainted)
task passes:run -- lto:SimpleDataflowChecker
cp $KERNEL_PATH/reports.yaml $STATIC_ANALYZERS_RESULTS_PATH/reports-tainted.yaml

echo "[INFO] running LLVM pass for Pattern 3 (Mismatch on Data Structure Operators)"
# Pattern 3 (Mismatch on Data Structure Operators)
(cd $KERNEL_PATH && git checkout uncontained-static-analysis-list-correlation)
task passes:run -- lto:SimpleDataflowChecker
cp $KERNEL_PATH/reports.yaml $STATIC_ANALYZERS_RESULTS_PATH/reports-list_entry_correlation.yaml

echo "[INFO] combining reports YAML files into single file"
rm $KERNEL_PATH/reports.yaml
cp  $STATIC_ANALYZERS_RESULTS_PATH/reports-tainted.yaml $KERNEL_PATH/reports.yaml
tail -n +3  $STATIC_ANALYZERS_RESULTS_PATH/reports-list_entry_correlation.yaml  >> $KERNEL_PATH/reports.yaml

echo "[INFO] final reporst YAML is stored at $KERNEL_PATH/reports.yaml"
echo "[INFO] you can now look at it directly or load it into the vscode extension"
echo "[INFO] see the README.md in vscode-extension for more details"
