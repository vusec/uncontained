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

In this artifact we provide the means to reproduce our main results.
Specifically, we show that our framework, uncontained, finds container confusion,
both dynamically while fuzzing and statically with dataflow tracking.
We have evaluated our artifact on an Ubuntu 22.04.1 (stock Linux kernel v.5.15)
with 16 cores @2.3GHz (AMD EPYC 7643) using a total of 16 QEMU-KVM virtual machines
with 4GB RAM.

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

2. Create the `kernel-tools/.env` file with the following content (replace
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
   llvm-project and Linux with fullLTO):
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

You can check the expected output in [here](#expected-results-for-tests).

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
* Execution: You can compile the kernel with instrumentation and start
  LMBench with executing `./scripts/run-lmbench-performance-evaluation.sh`.
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

## Expected Results for tests
<details>
  <summary>test.sh</summary>

  ```
rm: cannot remove 'container_of_log.txt': No such file or directory
rm: cannot remove 'types_log.txt': No such file or directory
---------- [TYPE STAT] ----------
0: 8
1: 4
2: 3
---------------------------------
[DEBUG] nosanitize src types: 0
[DEBUG] nosanitize dst types: 2
---------- [UNCONTAINED STAT] ----------
tests/: 24
          --------------------
[+] instrumented: 24
    checks inserted: 36
    avg inserted:    1.666667e+00
[+] skipped: 0
    skipped nounc: 0
    skipped nosan: 0
----------------------------------------
   ```
</details>

<details>
  <summary>testDF.sh</summary>

  ```
---> /path/to/uncontained/tests/testDF/test_hit10.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
  %4 = call fastcc i32* @__test_source(i8* %3), !dbg !37
- sinks:
  call fastcc void @__test_sink(i8* %5), !dbg !39
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
--- [DATAFLOW RULE TRIGGER] ---
rule: test_rule
source:   %4 = call fastcc i32* @__test_source(i8* %3), !dbg !37
  at: main() in tests/testDF/test_hit10.c:35
sink:   call fastcc void @__test_sink(i8* %5), !dbg !39
  at: main() in tests/testDF/test_hit10.c:36
flow:
[#2] __test_source() in tests/testDF/test_hit10.c:9
[#1] main() in tests/testDF/test_hit10.c:35  %4 = call fastcc i32* @__test_source(i8* %3), !dbg !37
[#0] main() in tests/testDF/test_hit10.c:36  call fastcc void @__test_sink(i8* %5), !dbg !39

[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit1.c
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
  %3 = call i32* @__inet_lookup_established(), !dbg !32
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
--- [DATAFLOW RULE TRIGGER] ---
rule: inet_lookup
source:   %3 = call i32* @__inet_lookup_established(), !dbg !32
  at: main() in tests/testDF/test_hit1.c:31
sink:   store volatile i32* %5, i32** @out, align 8, !dbg !35, !tbaa !36
  at: main() in tests/testDF/test_hit1.c:32
flow:
[#18] __inet_lookup_established() in tests/testDF/test_hit1.c:9
[#17] main() in tests/testDF/test_hit1.c:31  %3 = call i32* @__inet_lookup_established(), !dbg !32
[#16] main() in tests/testDF/test_hit1.c:32  %5 = call i32* @func1(i8* %4), !dbg !34
[#15] func1() in tests/testDF/test_hit1.c:26i8* %0
[#14] func1() in tests/testDF/test_hit1.c:27  %2 = call i32* @func2(i8* %0), !dbg !28
[#13] func2() in tests/testDF/test_hit1.c:22i8* %0
[#12] func2() in tests/testDF/test_hit1.c:23  %2 = call i32* @func3(i8* %0), !dbg !28
[#11] func3() in tests/testDF/test_hit1.c:18i8* %0
[#10] func3() in tests/testDF/test_hit1.c:19  %2 = call i32* @func4(i8* %0), !dbg !28
[#9] func4() in tests/testDF/test_hit1.c:14i8* %0
[#8] func4() in tests/testDF/test_hit1.c:15  ret i32* %2, !dbg !29
[#7] func3() in tests/testDF/test_hit1.c:19  %2 = call i32* @func4(i8* %0), !dbg !28
[#6] func3() in tests/testDF/test_hit1.c:19  ret i32* %2, !dbg !29
[#5] func2() in tests/testDF/test_hit1.c:23  %2 = call i32* @func3(i8* %0), !dbg !28
[#4] func2() in tests/testDF/test_hit1.c:23  ret i32* %2, !dbg !29
[#3] func1() in tests/testDF/test_hit1.c:27  %2 = call i32* @func2(i8* %0), !dbg !28
[#2] func1() in tests/testDF/test_hit1.c:27  ret i32* %2, !dbg !29
[#1] main() in tests/testDF/test_hit1.c:32  %5 = call i32* @func1(i8* %4), !dbg !34
[#0] main() in tests/testDF/test_hit1.c:32  store volatile i32* %5, i32** @out, align 8, !dbg !35, !tbaa !36

[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit2.c
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
  %3 = call i32* @__inet_lookup_established(), !dbg !32
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
--- [DATAFLOW RULE TRIGGER] ---
rule: inet_lookup
source:   %3 = call i32* @__inet_lookup_established(), !dbg !32
  at: main() in tests/testDF/test_hit2.c:32
sink:   store volatile i32* %2, i32** @out, align 8, !dbg !29, !tbaa !30
  at: func4() in tests/testDF/test_hit2.c:15
flow:
[#10] __inet_lookup_established() in tests/testDF/test_hit2.c:9
[#9] main() in tests/testDF/test_hit2.c:32  %3 = call i32* @__inet_lookup_established(), !dbg !32
[#8] main() in tests/testDF/test_hit2.c:33  %5 = call i32* @func1(i8* %4), !dbg !34
[#7] func1() in tests/testDF/test_hit2.c:27i8* %0
[#6] func1() in tests/testDF/test_hit2.c:28  %2 = call i32* @func2(i8* %0), !dbg !28
[#5] func2() in tests/testDF/test_hit2.c:23i8* %0
[#4] func2() in tests/testDF/test_hit2.c:24  %2 = call i32* @func3(i8* %0), !dbg !28
[#3] func3() in tests/testDF/test_hit2.c:19i8* %0
[#2] func3() in tests/testDF/test_hit2.c:20  %2 = call i32* @func4(i8* %0), !dbg !28
[#1] func4() in tests/testDF/test_hit2.c:14i8* %0
[#0] func4() in tests/testDF/test_hit2.c:15  store volatile i32* %2, i32** @out, align 8, !dbg !29, !tbaa !30

[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit3.c
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
  %1 = call i32* @__inet_lookup_established(), !dbg !26
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
--- [DATAFLOW RULE TRIGGER] ---
rule: inet_lookup
source:   %1 = call i32* @__inet_lookup_established(), !dbg !26
  at: func4() in tests/testDF/test_hit3.c:15
sink:   store volatile i32* %3, i32** @out, align 8, !dbg !32, !tbaa !33
  at: main() in tests/testDF/test_hit3.c:32
flow:
[#10] __inet_lookup_established() in tests/testDF/test_hit3.c:9
[#9] func4() in tests/testDF/test_hit3.c:15  %1 = call i32* @__inet_lookup_established(), !dbg !26
[#8] func4() in tests/testDF/test_hit3.c:16  ret i32* %1, !dbg !28
[#7] func3() in tests/testDF/test_hit3.c:20  %1 = call i32* @func4(), !dbg !24
[#6] func3() in tests/testDF/test_hit3.c:20  ret i32* %1, !dbg !25
[#5] func2() in tests/testDF/test_hit3.c:24  %1 = call i32* @func3(), !dbg !24
[#4] func2() in tests/testDF/test_hit3.c:24  ret i32* %1, !dbg !25
[#3] func1() in tests/testDF/test_hit3.c:28  %1 = call i32* @func2(), !dbg !24
[#2] func1() in tests/testDF/test_hit3.c:28  ret i32* %1, !dbg !25
[#1] main() in tests/testDF/test_hit3.c:32  %3 = call i32* @func1(), !dbg !31
[#0] main() in tests/testDF/test_hit3.c:32  store volatile i32* %3, i32** @out, align 8, !dbg !32, !tbaa !33

[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit4.c
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
  %1 = call i32* @__inet_lookup_established(), !dbg !26
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
--- [DATAFLOW RULE TRIGGER] ---
rule: inet_lookup
source:   %1 = call i32* @__inet_lookup_established(), !dbg !26
  at: func4() in tests/testDF/test_hit4.c:15
sink:   store volatile i32* %2, i32** @out, align 8, !dbg !29, !tbaa !30
  at: func7() in tests/testDF/test_hit4.c:32
flow:
[#16] __inet_lookup_established() in tests/testDF/test_hit4.c:9
[#15] func4() in tests/testDF/test_hit4.c:15  %1 = call i32* @__inet_lookup_established(), !dbg !26
[#14] func4() in tests/testDF/test_hit4.c:16  ret i32* %1, !dbg !28
[#13] func3() in tests/testDF/test_hit4.c:20  %1 = call i32* @func4(), !dbg !24
[#12] func3() in tests/testDF/test_hit4.c:20  ret i32* %1, !dbg !25
[#11] func2() in tests/testDF/test_hit4.c:24  %1 = call i32* @func3(), !dbg !24
[#10] func2() in tests/testDF/test_hit4.c:24  ret i32* %1, !dbg !25
[#9] func1() in tests/testDF/test_hit4.c:28  %1 = call i32* @func2(), !dbg !24
[#8] func1() in tests/testDF/test_hit4.c:28  ret i32* %1, !dbg !25
[#7] main() in tests/testDF/test_hit4.c:47  %3 = call i32* @func1(), !dbg !32
[#6] main() in tests/testDF/test_hit4.c:48  %5 = call i32* @func5(i8* %4), !dbg !34
[#5] func5() in tests/testDF/test_hit4.c:41i8* %0
[#4] func5() in tests/testDF/test_hit4.c:42  %2 = call i32* @func6(i8* %0), !dbg !28
[#3] func6() in tests/testDF/test_hit4.c:36i8* %0
[#2] func6() in tests/testDF/test_hit4.c:37  %2 = call i32* @func7(i8* %0), !dbg !28
[#1] func7() in tests/testDF/test_hit4.c:31i8* %0
[#0] func7() in tests/testDF/test_hit4.c:32  store volatile i32* %2, i32** @out, align 8, !dbg !29, !tbaa !30

[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit5.c
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
  %1 = call i32* @__inet_lookup_established(), !dbg !26
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
--- [DATAFLOW RULE TRIGGER] ---
rule: inet_lookup
source:   %1 = call i32* @__inet_lookup_established(), !dbg !26
  at: func4() in tests/testDF/test_hit5.c:15
sink:   store volatile i32* %1, i32** @out, align 8, !dbg !28, !tbaa !29
  at: func4() in tests/testDF/test_hit5.c:16
flow:
[#2] __inet_lookup_established() in tests/testDF/test_hit5.c:9
[#1] func4() in tests/testDF/test_hit5.c:15  %1 = call i32* @__inet_lookup_established(), !dbg !26
[#0] func4() in tests/testDF/test_hit5.c:16  store volatile i32* %1, i32** @out, align 8, !dbg !28, !tbaa !29

[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit6.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
  %3 = call i32* @__test_source(), !dbg !32
- sinks:
  call void @__test_sink(i8* %6), !dbg !35
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
--- [DATAFLOW RULE TRIGGER] ---
rule: test_rule
source:   %3 = call i32* @__test_source(), !dbg !32
  at: main() in tests/testDF/test_hit6.c:35
sink:   call void @__test_sink(i8* %6), !dbg !35
  at: main() in tests/testDF/test_hit6.c:36
flow:
[#18] __test_source() in tests/testDF/test_hit6.c:13
[#17] main() in tests/testDF/test_hit6.c:35  %3 = call i32* @__test_source(), !dbg !32
[#16] main() in tests/testDF/test_hit6.c:36  %5 = call i32* @func1(i8* %4), !dbg !34
[#15] func1() in tests/testDF/test_hit6.c:30i8* %0
[#14] func1() in tests/testDF/test_hit6.c:31  %2 = call i32* @func2(i8* %0), !dbg !28
[#13] func2() in tests/testDF/test_hit6.c:26i8* %0
[#12] func2() in tests/testDF/test_hit6.c:27  %2 = call i32* @func3(i8* %0), !dbg !28
[#11] func3() in tests/testDF/test_hit6.c:22i8* %0
[#10] func3() in tests/testDF/test_hit6.c:23  %2 = call i32* @func4(i8* %0), !dbg !28
[#9] func4() in tests/testDF/test_hit6.c:18i8* %0
[#8] func4() in tests/testDF/test_hit6.c:19  ret i32* %2, !dbg !29
[#7] func3() in tests/testDF/test_hit6.c:23  %2 = call i32* @func4(i8* %0), !dbg !28
[#6] func3() in tests/testDF/test_hit6.c:23  ret i32* %2, !dbg !29
[#5] func2() in tests/testDF/test_hit6.c:27  %2 = call i32* @func3(i8* %0), !dbg !28
[#4] func2() in tests/testDF/test_hit6.c:27  ret i32* %2, !dbg !29
[#3] func1() in tests/testDF/test_hit6.c:31  %2 = call i32* @func2(i8* %0), !dbg !28
[#2] func1() in tests/testDF/test_hit6.c:31  ret i32* %2, !dbg !29
[#1] main() in tests/testDF/test_hit6.c:36  %5 = call i32* @func1(i8* %4), !dbg !34
[#0] main() in tests/testDF/test_hit6.c:36  call void @__test_sink(i8* %6), !dbg !35

[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit7.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
  %3 = call i32* @__test_source(), !dbg !33
- sinks:
  call void @__test_sink(i8* %6), !dbg !36
  call void @__test_sink(i8* %6), !dbg !40
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: __test_sanitizer
--- [DATAFLOW RULE TRIGGER] ---
rule: test_rule
source:   %3 = call i32* @__test_source(), !dbg !33
  at: main() in tests/testDF/test_hit7.c:39
sink:   call void @__test_sink(i8* %6), !dbg !36
  at: main() in tests/testDF/test_hit7.c:40
flow:
[#18] __test_source() in tests/testDF/test_hit7.c:17
[#17] main() in tests/testDF/test_hit7.c:39  %3 = call i32* @__test_source(), !dbg !33
[#16] main() in tests/testDF/test_hit7.c:40  %5 = call i32* @func1(i8* %4), !dbg !35
[#15] func1() in tests/testDF/test_hit7.c:34i8* %0
[#14] func1() in tests/testDF/test_hit7.c:35  %2 = call i32* @func2(i8* %0), !dbg !29
[#13] func2() in tests/testDF/test_hit7.c:30i8* %0
[#12] func2() in tests/testDF/test_hit7.c:31  %2 = call i32* @func3(i8* %0), !dbg !29
[#11] func3() in tests/testDF/test_hit7.c:26i8* %0
[#10] func3() in tests/testDF/test_hit7.c:27  %2 = call i32* @func4(i8* %0), !dbg !29
[#9] func4() in tests/testDF/test_hit7.c:22i8* %0
[#8] func4() in tests/testDF/test_hit7.c:23  ret i32* %2, !dbg !30
[#7] func3() in tests/testDF/test_hit7.c:27  %2 = call i32* @func4(i8* %0), !dbg !29
[#6] func3() in tests/testDF/test_hit7.c:27  ret i32* %2, !dbg !30
[#5] func2() in tests/testDF/test_hit7.c:31  %2 = call i32* @func3(i8* %0), !dbg !29
[#4] func2() in tests/testDF/test_hit7.c:31  ret i32* %2, !dbg !30
[#3] func1() in tests/testDF/test_hit7.c:35  %2 = call i32* @func2(i8* %0), !dbg !29
[#2] func1() in tests/testDF/test_hit7.c:35  ret i32* %2, !dbg !30
[#1] main() in tests/testDF/test_hit7.c:40  %5 = call i32* @func1(i8* %4), !dbg !35
[#0] main() in tests/testDF/test_hit7.c:40  call void @__test_sink(i8* %6), !dbg !36

[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit8.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
  %3 = call i32* @__test_source(), !dbg !33
- sinks:
  call void @__test_sink(i8* %9), !dbg !39
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: __test_sanitizer
--- [DATAFLOW RULE TRIGGER] ---
rule: test_rule
source:   %3 = call i32* @__test_source(), !dbg !33
  at: main() in tests/testDF/test_hit8.c:43
sink:   call void @__test_sink(i8* %9), !dbg !39
  at: main() in tests/testDF/test_hit8.c:47
flow:
[#18] __test_source() in tests/testDF/test_hit8.c:21
[#17] main() in tests/testDF/test_hit8.c:43  %3 = call i32* @__test_source(), !dbg !33
[#16] main() in tests/testDF/test_hit8.c:47  %8 = call i32* @func1(i8* %4), !dbg !38
[#15] func1() in tests/testDF/test_hit8.c:38i8* %0
[#14] func1() in tests/testDF/test_hit8.c:39  %2 = call i32* @func2(i8* %0), !dbg !29
[#13] func2() in tests/testDF/test_hit8.c:34i8* %0
[#12] func2() in tests/testDF/test_hit8.c:35  %2 = call i32* @func3(i8* %0), !dbg !29
[#11] func3() in tests/testDF/test_hit8.c:30i8* %0
[#10] func3() in tests/testDF/test_hit8.c:31  %2 = call i32* @func4(i8* %0), !dbg !29
[#9] func4() in tests/testDF/test_hit8.c:26i8* %0
[#8] func4() in tests/testDF/test_hit8.c:27  ret i32* %2, !dbg !30
[#7] func3() in tests/testDF/test_hit8.c:31  %2 = call i32* @func4(i8* %0), !dbg !29
[#6] func3() in tests/testDF/test_hit8.c:31  ret i32* %2, !dbg !30
[#5] func2() in tests/testDF/test_hit8.c:35  %2 = call i32* @func3(i8* %0), !dbg !29
[#4] func2() in tests/testDF/test_hit8.c:35  ret i32* %2, !dbg !30
[#3] func1() in tests/testDF/test_hit8.c:39  %2 = call i32* @func2(i8* %0), !dbg !29
[#2] func1() in tests/testDF/test_hit8.c:39  ret i32* %2, !dbg !30
[#1] main() in tests/testDF/test_hit8.c:47  %8 = call i32* @func1(i8* %4), !dbg !38
[#0] main() in tests/testDF/test_hit8.c:47  call void @__test_sink(i8* %9), !dbg !39

[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit9.c
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
  %3 = call %struct.sock_common* @__inet_lookup_established(), !dbg !58
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
--- [DATAFLOW RULE TRIGGER] ---
rule: inet_lookup
source:   %3 = call %struct.sock_common* @__inet_lookup_established(), !dbg !58
  at: main() in tests/testDF/test_hit9.c:54
sink:   store volatile i32* %8, i32** @out, align 8, !dbg !65, !tbaa !66
  at: main() in tests/testDF/test_hit9.c:57
flow:
[#18] __inet_lookup_established() in tests/testDF/test_hit9.c:32
[#17] main() in tests/testDF/test_hit9.c:54  %3 = call %struct.sock_common* @__inet_lookup_established(), !dbg !58
[#16] main() in tests/testDF/test_hit9.c:57  %8 = call i32* @func1(i8* %7), !dbg !64
[#15] func1() in tests/testDF/test_hit9.c:49i8* %0
[#14] func1() in tests/testDF/test_hit9.c:50  %2 = call i32* @func2(i8* %0), !dbg !54
[#13] func2() in tests/testDF/test_hit9.c:45i8* %0
[#12] func2() in tests/testDF/test_hit9.c:46  %2 = call i32* @func3(i8* %0), !dbg !54
[#11] func3() in tests/testDF/test_hit9.c:41i8* %0
[#10] func3() in tests/testDF/test_hit9.c:42  %2 = call i32* @func4(i8* %0), !dbg !54
[#9] func4() in tests/testDF/test_hit9.c:37i8* %0
[#8] func4() in tests/testDF/test_hit9.c:38  ret i32* %2, !dbg !55
[#7] func3() in tests/testDF/test_hit9.c:42  %2 = call i32* @func4(i8* %0), !dbg !54
[#6] func3() in tests/testDF/test_hit9.c:42  ret i32* %2, !dbg !55
[#5] func2() in tests/testDF/test_hit9.c:46  %2 = call i32* @func3(i8* %0), !dbg !54
[#4] func2() in tests/testDF/test_hit9.c:46  ret i32* %2, !dbg !55
[#3] func1() in tests/testDF/test_hit9.c:50  %2 = call i32* @func2(i8* %0), !dbg !54
[#2] func1() in tests/testDF/test_hit9.c:50  ret i32* %2, !dbg !55
[#1] main() in tests/testDF/test_hit9.c:57  %8 = call i32* @func1(i8* %7), !dbg !64
[#0] main() in tests/testDF/test_hit9.c:57  store volatile i32* %8, i32** @out, align 8, !dbg !65, !tbaa !66

[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit_backwards_contained01.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 1
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.socket_alloc: %struct.socket* %0
- sinks:
  ANY
- ignores:
- sanitizers:
--- [DATAFLOW RULE TRIGGER] ---
rule: backwards_contained
source: struct.socket_alloc: %struct.socket* %0
  at: SOCK_INODE() in tests/testDF/test_hit_backwards_contained01.c:35
sink: struct.tun_file: %struct.socket* getelementptr inbounds (%struct.tun_file, %struct.tun_file* @tfile_storage, i64 0, i32 1)
flow:
[#2] SOCK_INODE() in tests/testDF/test_hit_backwards_contained01.c:33%struct.socket* %0
[#1] sock_init_data() in tests/testDF/test_hit_backwards_contained01.c:38%struct.socket* %0
[#0] %struct.socket* getelementptr inbounds (%struct.tun_file, %struct.tun_file* @tfile_storage, i64 0, i32 1)

[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit_backwards_contained02.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 1
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.socket_alloc: %struct.socket* %0
- sinks:
  ANY
- ignores:
- sanitizers:
--- [DATAFLOW RULE TRIGGER] ---
rule: backwards_contained
source: struct.socket_alloc: %struct.socket* %0
  at: SOCK_INODE() in tests/testDF/test_hit_backwards_contained02.c:39
sink: struct.tun_file: %struct.socket* getelementptr inbounds (%struct.tun_file, %struct.tun_file* @tfile_storage, i64 0, i32 1)
flow:
[#2] SOCK_INODE() in tests/testDF/test_hit_backwards_contained02.c:37%struct.socket* %0
[#1] sock_init_data() in tests/testDF/test_hit_backwards_contained02.c:42%struct.socket* %0
[#0] %struct.socket* getelementptr inbounds (%struct.tun_file, %struct.tun_file* @tfile_storage, i64 0, i32 1)

[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit_kobj01.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 1
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.other_container: %struct.kobject* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
struct.cpufreq_policy: %struct.kobject* %0
- sinks:
  ANY
- ignores:
- sanitizers:
--- [DATAFLOW RULE TRIGGER] ---
rule: kobj
kobj was contained differently!
source: struct.cpufreq_policy: %struct.kobject* %0
  at: main() in tests/testDF/test_hit_kobj01.c:43
sink: struct.other_container:   store volatile i64 %8, i64* @__container_of_flow_ptr_in, align 8, !dbg !88, !tbaa !89
  at: show() in tests/testDF/test_hit_kobj01.c:13
flow:
[#2] show() in tests/testDF/test_hit_kobj01.c:11%struct.kobject* %0
[#1] show() in tests/testDF/test_hit_kobj01.c:13  %8 = ptrtoint %struct.kobject* %0 to i64, !dbg !88
[#0] show() in tests/testDF/test_hit_kobj01.c:13  store volatile i64 %8, i64* @__container_of_flow_ptr_in, align 8, !dbg !88, !tbaa !89

---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit_kobj02.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 1
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.other_container: %struct.kobject* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
%struct.kobject* %0
- sinks:
  ANY
- ignores:
- sanitizers:
--- [DATAFLOW RULE TRIGGER] ---
rule: kobj
kobj was not contained!
source: %struct.kobject* %0
  at: main() in tests/testDF/test_hit_kobj02.c:42
sink: struct.other_container:   store volatile i64 %8, i64* @__container_of_flow_ptr_in, align 8, !dbg !84, !tbaa !85
  at: show() in tests/testDF/test_hit_kobj02.c:13
flow:
[#2] show() in tests/testDF/test_hit_kobj02.c:11%struct.kobject* %0
[#1] show() in tests/testDF/test_hit_kobj02.c:13  %8 = ptrtoint %struct.kobject* %0 to i64, !dbg !84
[#0] show() in tests/testDF/test_hit_kobj02.c:13  store volatile i64 %8, i64* @__container_of_flow_ptr_in, align 8, !dbg !84, !tbaa !85

---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit_kobj03.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 1
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.outer_container2: %struct.kobject* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
struct.cpufreq_policy: %struct.kobject* %0
- sinks:
  ANY
- ignores:
- sanitizers:
--- [DATAFLOW RULE TRIGGER] ---
rule: kobj
kobj was contained differently!
source: struct.cpufreq_policy: %struct.kobject* %0
  at: func2() in tests/testDF/test_hit_kobj03.c:40
sink: struct.outer_container2:   store volatile i64 %8, i64* @__container_of_flow_ptr_in, align 8, !dbg !96, !tbaa !97
  at: show() in tests/testDF/test_hit_kobj03.c:13
flow:
[#2] show() in tests/testDF/test_hit_kobj03.c:11%struct.kobject* %0
[#1] show() in tests/testDF/test_hit_kobj03.c:13  %8 = ptrtoint %struct.kobject* %0 to i64, !dbg !96
[#0] show() in tests/testDF/test_hit_kobj03.c:13  store volatile i64 %8, i64* @__container_of_flow_ptr_in, align 8, !dbg !96, !tbaa !97

---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit_list_entry_correlation01.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 1
kobj
list_entry_correlation
done: 3
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
struct.test:   %1 = alloca %struct.list_head, align 8
struct.test1: %struct.list_head* %0
struct.test1: @test_list_decoy = internal global %struct.list_head zeroinitializer, align 8, !dbg !32
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: __list_add
--- [DATAFLOW RULE TRIGGER] ---
rule: list_entry_correlation
source: struct.test:   %1 = alloca %struct.list_head, align 8
  at: func1() in tests/testDF/test_hit_list_entry_correlation01.c:32
sink: struct.test1:   store volatile i64 %6, i64* @__list_entry_flow_ptr_in, align 8, !dbg !67, !tbaa !68
  at: func2() in tests/testDF/test_hit_list_entry_correlation01.c:25
flow:
[#4] func1() in   %1 = alloca %struct.list_head, align 8
[#3] func1() in tests/testDF/test_hit_list_entry_correlation01.c:33  call fastcc void @func2(%struct.list_head* nonnull %1), !dbg !61
[#2] func2() in tests/testDF/test_hit_list_entry_correlation01.c:23%struct.list_head* %0
[#1] func2() in tests/testDF/test_hit_list_entry_correlation01.c:25  %6 = ptrtoint %struct.list_head* %0 to i64, !dbg !67
[#0] func2() in tests/testDF/test_hit_list_entry_correlation01.c:25  store volatile i64 %6, i64* @__list_entry_flow_ptr_in, align 8, !dbg !67, !tbaa !68

[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.test1: %struct.list_head* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit_list_entry_correlation02.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 3
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
struct.test1:   %1 = alloca %struct.list_head, align 8
struct.test: %struct.list_head* %0
struct.test: @test_list_decoy = internal global %struct.list_head zeroinitializer, align 8, !dbg !31
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: __list_add
--- [DATAFLOW RULE TRIGGER] ---
rule: list_entry_correlation
source: struct.test1:   %1 = alloca %struct.list_head, align 8
  at: func1() in tests/testDF/test_hit_list_entry_correlation02.c:32
sink: struct.test:   call fastcc void @list_add(%struct.list_head* getelementptr inbounds (%struct.test, %struct.test* @test_storage, i64 0, i32 1), %struct.list_head* %0), !dbg !46
  at: func2() in tests/testDF/test_hit_list_entry_correlation02.c:26
flow:
[#3] func1() in   %1 = alloca %struct.list_head, align 8
[#2] func1() in tests/testDF/test_hit_list_entry_correlation02.c:33  call fastcc void @func2(%struct.list_head* nonnull %1), !dbg !48
[#1] func2() in tests/testDF/test_hit_list_entry_correlation02.c:24%struct.list_head* %0
[#0] func2() in tests/testDF/test_hit_list_entry_correlation02.c:26  call fastcc void @list_add(%struct.list_head* getelementptr inbounds (%struct.test, %struct.test* @test_storage, i64 0, i32 1), %struct.list_head* %0), !dbg !46

[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

/path/to/uncontained/tests/testDF/test_hit_list_entry_correlation03.c:26:19: warning: incompatible pointer types initializing 'struct test1 *' with an expression of type 'struct test *' [-Wincompatible-pointer-types]
    struct test1 *test = list_entry(head, struct test, list);
                  ^      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1 warning generated.
---> /path/to/uncontained/tests/testDF/test_hit_list_entry_correlation03.c
/path/to/uncontained/tests/testDF/test_hit_list_entry_correlation03.c:26:19: warning: incompatible pointer types initializing 'struct test1 *' with an expression of type 'struct test *' [-Wincompatible-pointer-types]
    struct test1 *test = list_entry(head, struct test, list);
                  ^      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1 warning generated.
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 2
kobj
list_entry_correlation
done: 4
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
struct.test1:   %1 = alloca %struct.list_head, align 8
struct.test1: %struct.list_head* %0
struct.test: %struct.list_head* %0
struct.test: @test_list_decoy = internal global %struct.list_head zeroinitializer, align 8, !dbg !35
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: __list_add
--- [DATAFLOW RULE TRIGGER] ---
rule: list_entry_correlation
source: struct.test1:   %1 = alloca %struct.list_head, align 8
  at: func1() in tests/testDF/test_hit_list_entry_correlation03.c:40
sink: struct.test:   store volatile i64 %6, i64* @__list_entry_flow_ptr_in, align 8, !dbg !70, !tbaa !71
  at: func3() in tests/testDF/test_hit_list_entry_correlation03.c:26
flow:
[#6] func1() in   %1 = alloca %struct.list_head, align 8
[#5] func1() in tests/testDF/test_hit_list_entry_correlation03.c:41  call fastcc void @func2(%struct.list_head* nonnull %1), !dbg !64
[#4] func2() in tests/testDF/test_hit_list_entry_correlation03.c:30%struct.list_head* %0
[#3] func2() in tests/testDF/test_hit_list_entry_correlation03.c:34  call fastcc void @func3(%struct.list_head* %0), !dbg !84
[#2] func3() in tests/testDF/test_hit_list_entry_correlation03.c:24%struct.list_head* %0
[#1] func3() in tests/testDF/test_hit_list_entry_correlation03.c:26  %6 = ptrtoint %struct.list_head* %0 to i64, !dbg !70
[#0] func3() in tests/testDF/test_hit_list_entry_correlation03.c:26  store volatile i64 %6, i64* @__list_entry_flow_ptr_in, align 8, !dbg !70, !tbaa !71

--- [DATAFLOW RULE TRIGGER] ---
rule: list_entry_correlation
source: struct.test1: %struct.list_head* %0
  at: func2() in tests/testDF/test_hit_list_entry_correlation03.c:32
sink: struct.test:   store volatile i64 %6, i64* @__list_entry_flow_ptr_in, align 8, !dbg !70, !tbaa !71
  at: func3() in tests/testDF/test_hit_list_entry_correlation03.c:26
flow:
[#4] func2() in tests/testDF/test_hit_list_entry_correlation03.c:30%struct.list_head* %0
[#3] func2() in tests/testDF/test_hit_list_entry_correlation03.c:34  call fastcc void @func3(%struct.list_head* %0), !dbg !84
[#2] func3() in tests/testDF/test_hit_list_entry_correlation03.c:24%struct.list_head* %0
[#1] func3() in tests/testDF/test_hit_list_entry_correlation03.c:26  %6 = ptrtoint %struct.list_head* %0 to i64, !dbg !70
[#0] func3() in tests/testDF/test_hit_list_entry_correlation03.c:26  store volatile i64 %6, i64* @__list_entry_flow_ptr_in, align 8, !dbg !70, !tbaa !71

--- [DATAFLOW RULE TRIGGER] ---
rule: list_entry_correlation
source: struct.test: @test_list_decoy = internal global %struct.list_head zeroinitializer, align 8, !dbg !35
  at: main() in tests/testDF/test_hit_list_entry_correlation03.c:53
sink: struct.test1:   store volatile i64 %6, i64* @__list_entry_flow_ptr_in, align 8, !dbg !70, !tbaa !71
  at: func2() in tests/testDF/test_hit_list_entry_correlation03.c:32
flow:
[#4] @test_list_decoy = internal global %struct.list_head zeroinitializer, align 8, !dbg !35
[#3] main() in tests/testDF/test_hit_list_entry_correlation03.c:54  call fastcc void @func2(%struct.list_head* nonnull @test_list_decoy), !dbg !69
[#2] func2() in tests/testDF/test_hit_list_entry_correlation03.c:30%struct.list_head* %0
[#1] func2() in tests/testDF/test_hit_list_entry_correlation03.c:32  %6 = ptrtoint %struct.list_head* %0 to i64, !dbg !70
[#0] func2() in tests/testDF/test_hit_list_entry_correlation03.c:32  store volatile i64 %6, i64* @__list_entry_flow_ptr_in, align 8, !dbg !70, !tbaa !71

[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.test1: %struct.list_head* %0
struct.test: %struct.list_head* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 3
total: 3
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit_list_entry_correlation04.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 1
kobj
list_entry_correlation
done: 4
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
struct.test: @test_list_decoy = internal global %struct.list_head zeroinitializer, align 8, !dbg !34
struct.test1: %struct.list_head* %0
struct.test: %struct.list_head* %0
struct.test1:   %1 = alloca %struct.list_head, align 8
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: __list_add
--- [DATAFLOW RULE TRIGGER] ---
rule: list_entry_correlation
source: struct.test: @test_list_decoy = internal global %struct.list_head zeroinitializer, align 8, !dbg !34
  at: main() in tests/testDF/test_hit_list_entry_correlation04.c:52
sink: struct.test1:   store volatile i64 %6, i64* @__list_entry_flow_ptr_in, align 8, !dbg !69, !tbaa !70
  at: func2() in tests/testDF/test_hit_list_entry_correlation04.c:31
flow:
[#4] @test_list_decoy = internal global %struct.list_head zeroinitializer, align 8, !dbg !34
[#3] main() in tests/testDF/test_hit_list_entry_correlation04.c:53  call fastcc void @func2(%struct.list_head* nonnull @test_list_decoy), !dbg !68
[#2] func2() in tests/testDF/test_hit_list_entry_correlation04.c:29%struct.list_head* %0
[#1] func2() in tests/testDF/test_hit_list_entry_correlation04.c:31  %6 = ptrtoint %struct.list_head* %0 to i64, !dbg !69
[#0] func2() in tests/testDF/test_hit_list_entry_correlation04.c:31  store volatile i64 %6, i64* @__list_entry_flow_ptr_in, align 8, !dbg !69, !tbaa !70

--- [DATAFLOW RULE TRIGGER] ---
rule: list_entry_correlation
source: struct.test1: %struct.list_head* %0
  at: func2() in tests/testDF/test_hit_list_entry_correlation04.c:31
sink: struct.test:   call fastcc void @list_add(%struct.list_head* getelementptr inbounds (%struct.test, %struct.test* @test_storage, i64 0, i32 1), %struct.list_head* %0), !dbg !61
  at: func3() in tests/testDF/test_hit_list_entry_correlation04.c:26
flow:
[#3] func2() in tests/testDF/test_hit_list_entry_correlation04.c:29%struct.list_head* %0
[#2] func2() in tests/testDF/test_hit_list_entry_correlation04.c:33  call fastcc void @func3(%struct.list_head* %0), !dbg !83
[#1] func3() in tests/testDF/test_hit_list_entry_correlation04.c:24%struct.list_head* %0
[#0] func3() in tests/testDF/test_hit_list_entry_correlation04.c:26  call fastcc void @list_add(%struct.list_head* getelementptr inbounds (%struct.test, %struct.test* @test_storage, i64 0, i32 1), %struct.list_head* %0), !dbg !61

--- [DATAFLOW RULE TRIGGER] ---
rule: list_entry_correlation
source: struct.test1:   %1 = alloca %struct.list_head, align 8
  at: func1() in tests/testDF/test_hit_list_entry_correlation04.c:39
sink: struct.test:   call fastcc void @list_add(%struct.list_head* getelementptr inbounds (%struct.test, %struct.test* @test_storage, i64 0, i32 1), %struct.list_head* %0), !dbg !61
  at: func3() in tests/testDF/test_hit_list_entry_correlation04.c:26
flow:
[#5] func1() in   %1 = alloca %struct.list_head, align 8
[#4] func1() in tests/testDF/test_hit_list_entry_correlation04.c:40  call fastcc void @func2(%struct.list_head* nonnull %1), !dbg !63
[#3] func2() in tests/testDF/test_hit_list_entry_correlation04.c:29%struct.list_head* %0
[#2] func2() in tests/testDF/test_hit_list_entry_correlation04.c:33  call fastcc void @func3(%struct.list_head* %0), !dbg !83
[#1] func3() in tests/testDF/test_hit_list_entry_correlation04.c:24%struct.list_head* %0
[#0] func3() in tests/testDF/test_hit_list_entry_correlation04.c:26  call fastcc void @list_add(%struct.list_head* getelementptr inbounds (%struct.test, %struct.test* @test_storage, i64 0, i32 1), %struct.list_head* %0), !dbg !61

[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.test1: %struct.list_head* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
tests/: 3
total: 3
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_hit_list_entry_null.c
[WARNING] No function found for sanitizer: list_is_last
[WARNING] No function found for sanitizer: list_is_first
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
---------- [RULES] ----------
list_entry_null
---------- [checking...] ----------
[rule]: list_entry_null
- sources:
  %3 = call i8* @__uncontained_list_entry_source(i8* %2), !dbg !48
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowInstructionSanitizer: {id: 58}
--- [DATAFLOW RULE TRIGGER] ---
rule: list_entry_null
source:   %3 = call i8* @__uncontained_list_entry_source(i8* %2), !dbg !48
  at: func() in tests/testDF/test_hit_list_entry_null.c:88
sink:   %5 = icmp eq i8* %3, null, !dbg !51
  at: func() in tests/testDF/test_hit_list_entry_null.c:90
flow:
[#2] __uncontained_list_entry_source() in tests/testDF/test_hit_list_entry_null.c:13
[#1] func() in tests/testDF/test_hit_list_entry_null.c:88  %3 = call i8* @__uncontained_list_entry_source(i8* %2), !dbg !48
[#0] func() in tests/testDF/test_hit_list_entry_null.c:90  %5 = icmp eq i8* %3, null, !dbg !51

---------- [REPORT STAT] ----------
tests/: 1
total: 1
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit1.c
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
  %3 = call i32* @__inet_lookup_established(), !dbg !32
- sinks:
  ANY
- ignores:
  kmem_cache_free
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit2.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
  %3 = call i32* @__test_source(), !dbg !33
- sinks:
  call void @__test_sink(i8* %9), !dbg !39
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: __test_sanitizer
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit3.c
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
  %3 = call %struct.sock_common* @__inet_lookup_established(), !dbg !57
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit_backwards_contained01.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 1
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.socket_alloc: %struct.socket* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit_backwards_contained02.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 1
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.socket_alloc: %struct.socket* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit_kobj01.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 1
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.cpufreq_policy: %struct.kobject* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
struct.cpufreq_policy: %struct.kobject* %0
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit_kobj03.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 2
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.cpufreq_policy: %struct.kobject* %0
struct.outer_container: i8* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
struct.cpufreq_policy: %struct.kobject* %0
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit_kobj04.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 1
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.outer_container: %struct.kobject* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
struct.cpufreq_policy: %struct.kobject* %0
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit_list_entry1.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
  %3 = call i8* @__uncontained_list_entry_source(i8* %2), !dbg !62
  %23 = call i8* @__uncontained_list_entry_source(i8* %22), !dbg !85
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: __uncontained_list_entry_is_head
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit_list_entry2.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
  %2 = call i8* @__uncontained_list_entry_source(i8* %1), !dbg !46
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: list_empty
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit_list_entry3.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
[WARNING] No function found for sanitizer: __list_add
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 0
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
  %8 = call i8* @__uncontained_list_entry_source(i8* %7), !dbg !61
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: list_empty
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit_list_entry4.c
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
---------- [RULES] ----------
list_entry_strict
---------- [checking...] ----------
[rule]: list_entry_strict
- sources:
  %2 = call i8* @__uncontained_list_entry_source(i8* %1), !dbg !49
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowInstructionSanitizer: {id: 213909532}
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit_list_entry_correlation01.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 1
kobj
list_entry_correlation
done: 3
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
struct.test: %struct.list_head* %0
struct.test:   %1 = alloca %struct.list_head, align 8
struct.test: @test_list_decoy = internal global %struct.list_head zeroinitializer, align 8, !dbg !27
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: __list_add
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.test: %struct.list_head* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit_list_entry_correlation02.c
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 0
kobj
list_entry_correlation
done: 2
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
struct.test:   %1 = alloca %struct.list_head, align 8
struct.test: @test_list_decoy = internal global %struct.list_head zeroinitializer, align 8, !dbg !31
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: __list_add
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

/path/to/uncontained/tests/testDF/test_nohit_list_entry_correlation03.c:26:19: warning: incompatible pointer types initializing 'struct test1 *' with an expression of type 'struct test *' [-Wincompatible-pointer-types]
    struct test1 *test = list_entry(head, struct test, list);
                  ^      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/path/to/uncontained/tests/testDF/test_nohit_list_entry_correlation03.c:32:19: warning: incompatible pointer types initializing 'struct test1 *' with an expression of type 'struct test *' [-Wincompatible-pointer-types]
    struct test1 *test = list_entry(head, struct test, list);
                  ^      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
2 warnings generated.
---> /path/to/uncontained/tests/testDF/test_nohit_list_entry_correlation03.c
/path/to/uncontained/tests/testDF/test_nohit_list_entry_correlation03.c:26:19: warning: incompatible pointer types initializing 'struct test1 *' with an expression of type 'struct test *' [-Wincompatible-pointer-types]
    struct test1 *test = list_entry(head, struct test, list);
                  ^      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/path/to/uncontained/tests/testDF/test_nohit_list_entry_correlation03.c:32:19: warning: incompatible pointer types initializing 'struct test1 *' with an expression of type 'struct test *' [-Wincompatible-pointer-types]
    struct test1 *test = list_entry(head, struct test, list);
                  ^      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
2 warnings generated.
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 2
kobj
list_entry_correlation
done: 4
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
struct.test:   %1 = alloca %struct.list_head, align 8
struct.test: %struct.list_head* %0
struct.test: %struct.list_head* %0
struct.test: @test_list_decoy = internal global %struct.list_head zeroinitializer, align 8, !dbg !34
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: __list_add
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.test: %struct.list_head* %0
struct.test: %struct.list_head* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

/path/to/uncontained/tests/testDF/test_nohit_list_entry_correlation04.c:31:19: warning: incompatible pointer types initializing 'struct test1 *' with an expression of type 'struct test *' [-Wincompatible-pointer-types]
    struct test1 *test = list_entry(head, struct test, list);
                  ^      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1 warning generated.
---> /path/to/uncontained/tests/testDF/test_nohit_list_entry_correlation04.c
/path/to/uncontained/tests/testDF/test_nohit_list_entry_correlation04.c:31:19: warning: incompatible pointer types initializing 'struct test1 *' with an expression of type 'struct test *' [-Wincompatible-pointer-types]
    struct test1 *test = list_entry(head, struct test, list);
                  ^      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1 warning generated.
[WARNING] No function found for source: __inet_lookup_established
[WARNING] Ignore function not found: kmem_cache_free
[WARNING] No function found for sanitizer: sk_fullsock
[WARNING] No function found for source: __test_source
[WARNING] No function found for sink: __test_sink
[WARNING] No function found for sanitizer: __test_sanitizer
[WARNING] No function found for source: __uncontained_list_entry_source
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
[WARNING] No function found for sanitizer: kfree
[WARNING] No function found for sanitizer: __free_pages
---------- [RULES] ----------
inet_lookup
test_rule
list_entry
backwards_contained
done: 1
kobj
list_entry_correlation
done: 3
---------- [checking...] ----------
[rule]: list_entry_correlation
- sources:
struct.test: @test_list_decoy = internal global %struct.list_head zeroinitializer, align 8, !dbg !34
struct.test: %struct.list_head* %0
struct.test:   %1 = alloca %struct.list_head, align 8
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: __list_add
[rule]: test_rule
- sources:
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
[rule]: inet_lookup
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowInstructionSanitizer: {id: 58, offset: 18}
  DataflowFunctionCallSanitizer: NULL
[rule]: list_entry
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
[rule]: backwards_contained
- sources:
struct.test: %struct.list_head* %0
- sinks:
  ANY
- ignores:
- sanitizers:
[rule]: kobj
- sources:
- sinks:
  ANY
- ignores:
- sanitizers:
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit_list_entry_null2.c
[WARNING] No function found for sanitizer: list_is_last
[WARNING] No function found for sanitizer: list_is_first
[WARNING] No function found for sanitizer: list_is_head
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
---------- [RULES] ----------
list_entry_null
---------- [checking...] ----------
[rule]: list_entry_null
- sources:
  %6 = call i8* @__uncontained_list_entry_source(i8* %5), !dbg !51
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: list_empty
  DataflowFunctionCallSanitizer: NULL
  DataflowInstructionSanitizer: {id: 58}
  DataflowInstructionSanitizer: {id: 81, operand: 0}
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

---> /path/to/uncontained/tests/testDF/test_nohit_list_entry_null.c
[WARNING] No function found for sanitizer: list_is_last
[WARNING] No function found for sanitizer: list_is_first
[WARNING] No function found for sanitizer: list_empty
[WARNING] No function found for sanitizer: __uncontained_list_entry_is_head
---------- [RULES] ----------
list_entry_null
---------- [checking...] ----------
[rule]: list_entry_null
- sources:
  %6 = call i8* @__uncontained_list_entry_source(i8* %5), !dbg !52
- sinks:
- ignores:
- sanitizers:
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: list_is_head
  DataflowFunctionCallSanitizer: NULL
  DataflowFunctionCallSanitizer: NULL
  DataflowInstructionSanitizer: {id: 58}
  DataflowInstructionSanitizer: {id: 81, operand: 0}
---------- [REPORT STAT] ----------
total: 0
Analysis time: 00.000

[OK]
   ```
</details>
