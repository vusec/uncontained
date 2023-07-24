# uncontained

We present uncontained, a framework to detect type confusion bugs originating from incorrect downcasting operations in non-object-oriented languages, which we call container confusion. In languages like C, object-oriented programming features are often mimicked by embedding structures as fields of other structures and downcast operations performed using the unsafe container_of() macro. uncontained leverages static and dynamic analysis to detect container confusion bugs in large codebases, such as the Linux kernel.

We introduce a novel sanitizer able to detect container confusion at runtime during fuzzing.
Based on the bugs we found, we generalize bug patterns and propose a novel static analysis framework to detect variants of those bugs across the entire codebase. Analyzing the Linux kernel, we found 89 container confusion bugs, responsibly disclosed them, and submitted 149 patches to fix all of them.

## Paper

You can find the full paper [here](https://download.vusec.net/papers/uncontained_sec23.pdf).

## Directory Structure

* evaluation: Contains the necessary LMBench configuration and will include the results of the evaluation scripts.
* passes/ContainerOfSanitizer: The LLVM pass inserting the necessary `container_of()` sanitizer checks.
* passes/Dump{ContainerOf,Types}: Utility passes to aggregate the type graph.
* passes/SimpleDataflowChecker: The LLVM pass to perform the static analysis using data flow.
* patches: Contains the necessary LMBench passes & a syzkaller patch to ignore non-uncontained reports.
* runtime: Contains the runtime component of the sanitizer with the functions called by the LLVM pass.
* scripts: Contains scripts to ease compilation / running syzkaller & scripts to reproduce the experiments.
* tests: Contains basic tests for the sanitizer & static analysis components
* vscode-extension: Contains the vscode extension allowing easier inspection of static analysis results

Submodules:
* kernel-tools: Framework to compile LLVM, syzkaller, Linux & run LLVM passes on the kernel.
* linux: Custom uncontained-linux repository including our own patches.
* llvm-project: Custom uncontained-llvm-project repository including our own patches.

## Artifact Evaluation

### Description & Requirements

#### Hardware Dependencies

`uncontained` does not impose any strict hardware requirements but we assume a
recent x86_64 machine with enough RAM (minimum 64GB, or enough swap) to compile LLVM/Linux and
run virtual QEMU machines for fuzzing with syzkaller.

#### Software Dependencies

We expect certain packages from the Ubuntu package manager to be installed,
which are required to compile LLVM, Linux, syzkaller, etc.
We describe the necessary packages in the Set-up section.

If you use a different distribution you need to make sure to fulfil the
necessary dependencies using your dedicated package manager.

### Setup

In general, we recommend using a bare-metal desktop system
running Ubuntu 22.04. Make sure that you have KVM support
and your user is allowed to use KVM. The following packages
are required:

```
# go-task
sh -c "‘curl -ssL https://taskfile.dev/install.sh‘" \
-- -d -b ~/.local/bin
# llvm-project
sudo apt install build-essential clang-12 lld-12 ninja-build ccache cmake
# linux
sudo apt install bison flex libelf-dev libssl-dev coccinelle
# syzkaller
sudo apt install debootstrap
# install golang 1.20.5
GO_VERSION=go1.20.5.linux-amd64
wget https://go.dev/dl/$GO_VERSION.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf $GO_VERSION.tar.gz
rm -f $GO_VERSION.tar.gz
# qemu
sudo apt install qemu-system-x86
# evaluation
pip3 install scipy pandas
```

Then make sure that `~/.local/bin` and `/usr/local/go/bin` are
in your `PATH` to find the `go` and the `task` binaries:
```
export PATH=$HOME/.local/bin:/usr/local/go/bin:$PATH
```

### Installation

1. Obtain the artifact source and necessary dependencies:
```
git clone --recurse-submodules https://github.com/vusec/uncontained.git
```

2. Create the `kernel/tools.env` file here with the following content (replace
`/path/to/uncontained` with the actual absolute path):
```
REPOS=/path/to/uncontained
LLVMPREFIX=/path/to/uncontained/llvm-project/build
KERNEL=/path/to/uncontained/linux
ENABLE_KASAN=1
ENABLE_DEBUG=1
ENABLE_SYZKALLER=1
ENABLE_GDB_BUILD=1
ADDITIONAL_LLVM_VARIABLES=-DLLVM_ENABLE_EH=ON -DLLVM_ENABLE_RTTI=ON
```

3. Compile all the necessary dependencies (this will take a while to compile
   llvm-project and linux with fullLTO):
```
scripts/compile.sh
```

### Basic Tests

To test if the sanitizer and the static analyzers work as intended
you can use the tests by running the following:
```
# test sanitizer
LLVM_DIR=$PWD/llvm-project/build tests/test.sh
# test static analyzer
LLVM_DIR=$PWD/llvm-project/build tests/testDF.sh
```

### Evaluation workflow

C1. The `uncontained` sanitizer finds new types of container confusions.
This is proven by the experiment (E1).

C2. The `uncontained` sanitizer comes with an acceptable performance runtime
overhead.
This is proven by the experiments (E2) and (E3).

C3. The `uncontained` static analyzer has been used to
uncover new bugs in the Linux kernel. This is proven by
the experiments (E4).

### Experiments

#### Experiment E1: Fuzzing Evaluation [2 human-hours + 24 compute-hours]

* How to: `kernel-tools` is responsible for starting the
   fuzzer with the kernel that has been instrumented with
   the sanitizer.
* Preparation: Make sure you setup everything from the
   Installation step, including building syzkaller and create
   the syzkaller image (should be done by the `compile.sh` script).
* Execution: You can compile the kernel with instrumentation and start the
  fuzzer with executing `./scripts/compile.sh && ./scripts/run.sh`.
  Then let it run for at least 24 hours to get some results.
* Results: The result will be the crashes in the
   `kernel-tools/out/syzkaller-workdir/crashes` directory.
   We need to manually filter out bugs that are not triggered by `uncontained`
   (all that do not have three lines of `[UNCONTAINED]` before the `BUG:` line).

#### Experiment E2: Fuzzing Performance Evaluation [2 human-hours + 30 compute-hours]

This is the fuzzing performance experiment using the sanitizer while fuzzing
with syzkaller.
Expected results are the overhead in terms of throughput of executed testcases.

* How to: We need to run syzkaller 10 times for one hour for all three instances
  (baseline (stock syzkaller), KASAN and `uncontained`)
* Preparation: Make sure you setup everything from the
   Installation step, including building syzkaller and create
   the syzkaller image (should be done by the `compile.sh` script).
* Execution: You can compile the kernel with instrumentation and start the
  fuzzer with executing `./scripts/run-fuzzing-performance-evaluation.sh`.
  Then let it run for the 30 hours to get the results.
* Results: The result will be the percentage of decreased executed testcases
  when running syzkaller.
  You can now look at the results with executing
  `./scripts/evaluation/syzkaller-bench.py --prefix 'evaluation/syzkaller/results/syzkaller-bench-'`.

#### Experiment E3: LMBench Performance Evaluation [2 human-hours + 60 compute-hours]

This is the LMBench experiment using the sanitizer while running the
benchmarking suite to verify performance overhead.

* How to: We need to run LMBench 10 times for the different instances (baseline,
  KASAN, `uncontained`).
* Preparation: Make sure you setup everything from the
   Installation step, including building syzkaller and create
   the syzkaller image (should be done by the `compile.sh` script).
* Execution: You can compile the kernel with instrumentation and start the
  fuzzer with executing `./scripts/run-lmbench-performance-evaluation.sh`.
  Then let it run to get the results.
* Results: The result will be the overhead numbers of the different
  configurations on top of the baseline for the LMBench testcases.
  You can now look at the results with executing
  `./scripts/evaluation/lmbench.py --prefix 'evaluation/lmbench/results/'`.

#### Experiment E4: Static Analyzer Evaluation [1 human-hour + 3 compute-hours]

This is the static analyzers experiment using the static analyzer to find the
necessary reports with static analysis.

* How to: Compile the kernel with our static analyzers enabled to extract all
  the bug reports.
* Preparation: Make sure you setup everything from the Installation step.
  Also make sure you comment out `ENABLE_KASAN` and `ENABLE_SYZKALLER` in your
  `.env` file.
* Execution: You can generate all the reports with
  `./scripts/run-static-analyzer.sh`.
  Then let it run to get the results.
* Results: : The result will be the reports for the different rules.
  The results from the LLVM passes are in YAML and are not yet grouped by the
  source line (to remove duplicates).
  The results from the coccinelle script are text based and are already filtered
  based on uniqueness.
  You can load the YAML reports into the `vscode-extension` to look at them
  in a more convenient way and do the grouping based on the source code line.

##### Rule to Pattern Matching

| Rule                   |  Pattern                                |
|------------------------|-----------------------------------------|
|    backwards_contained | 1. Statically Incompatible Containers   |
|      list_entry_strict | 2. Empty-list Confusion                 |
| list_entry_correlation | 3. Mismatch on Data Structure Operators |
|         use_after_iter | 4. Containers with Contracts            |
|                   kobj | 5. Containers with Contracts            |

## Reproduce on another kernel version

Most on the content in this repository is independet of the kernel version, however many
of the patches done in [uncontained-linux](https://github.com/vusec/uncontained-linux) need to be repeated.

Primarily this means: reapplying the coccinelle scripts (and manually fixing some of the issues that 
arise from it), disable the KASAN checks, allow compiling KASAN with LTO and add nosanitize &
uncontained_struct_nesting_info to certain structs.
