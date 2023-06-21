//=============================================================================
// FILE:
//     DumpTypes.cpp
//
// DESCRIPTION:
// Dump container_of macro invocations to collect different informations
//
//=============================================================================
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"

#include <llvm/IR/IRBuilder.h>
#include "llvm/IR/InstVisitor.h"

#include "llvm/Transforms/IPO/PassManagerBuilder.h" // RegisterStandardPasses
#include <llvm/Transforms/Utils/BasicBlockUtils.h> // SplitBlock

#include "TypeUtils/TypeUtils.hpp"

#include <iostream>
#include <fstream>
#include <iomanip>

extern "C" {
#include <unistd.h>
#include <errno.h>
#include <sys/file.h>  // for flock()
}

using namespace llvm;

#define oprint(s) (outs() << s << "\n")

#define LOGFILE "all_types_log.txt"

//-----------------------------------------------------------------------------
//  DumpTypes implementation
//-----------------------------------------------------------------------------
// No need to expose the internals of the pass to the outside world - keep
// everything in an anonymous namespace.
namespace {

class DumpTypes {
  Module *Mod;
  LLVMContext *Ctx;

  bool init(Module &M);
  bool visitor(Function &F);
  void dumpToFile(const char* filename, std::string& s);

public:
  bool runImpl(Module &M);
};

bool DumpTypes::init(Module &M) {
  Mod = &M;
  Ctx = &M.getContext();

  return true;
}

void DumpTypes::dumpToFile(const char* filename, std::string& s) {
  // appending to a file is atomic, so should be safe but just to be sure
  #define LOCKNAME "/tmp/uncontained_lock"
  int fd = open(LOCKNAME, O_RDWR | O_CREAT, 0664); // open or create lockfile
  int rc = flock(fd, LOCK_EX); // grab exclusive lock

  std::ofstream log(LOGFILE, std::ofstream::app);
  log << s;

  // unlock
  flock(fd, LOCK_UN);
  close(fd);
}

bool DumpTypes::visitor(Function &F) {
  return false;
}

bool DumpTypes::runImpl(Module &M) {

  // keep track of all the uncontained types, i.e. the types that are never contained
  // into any other type
  std::set<size_t> uncontainedTypes;

  // add each type to the list of potential uncontained types
  for (StructType* ST: M.getIdentifiedStructTypes()) {
    uncontainedTypes.insert(TypeToNameHash(ST));
  }

  // for each type, remove all the types it contains from the set
  for (StructType* ST: M.getIdentifiedStructTypes()) {
    for (unsigned i = 0, e = ST->getNumElements(); i != e; ++i)
    {
      Type* T = ST->getElementType(i);
      if (isa<StructType>(T))
        uncontainedTypes.erase(TypeToNameHash(T));
    }
  }

  // collect all type hashes
  for (StructType* ST: M.getIdentifiedStructTypes()) {
    std::string type_str;
    raw_string_ostream rso(type_str);

    size_t name_hash = TypeToNameHash(ST);
    rso << format_hex(name_hash, 18, /*upper=*/ false);
    rso << " -> ";
    ST->print(rso);

    // mark the uncontained types
    if (uncontainedTypes.find(name_hash) != uncontainedTypes.end())
      rso << " UNCONTAINED";
    rso << "\n";

    // std::cout << type_str;
    dumpToFile(LOGFILE, rso.str());
  }
  return false;
}

// New PM implementation
struct DumpTypesPass : PassInfoMixin<DumpTypesPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    bool Changed = DumpTypes().runImpl(M);
    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};

// Legacy PM implementation
struct LegacyDumpTypesPass : public ModulePass {
  static char ID;
  LegacyDumpTypesPass() : ModulePass(ID) {}
  // Main entry point - the name conveys what unit of IR this is to be run on.
  bool runOnModule(Module &M) override {
    return DumpTypes().runImpl(M);
  }
};
} // namespace

//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
llvm::PassPluginLibraryInfo getDumpTypesPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "DumpTypes", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](llvm::ModulePassManager &PM,
                  llvm::PassBuilder::OptimizationLevel Level) {
                PM.addPass(DumpTypesPass());
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "dump-types") {
                    MPM.addPass(DumpTypesPass());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getDumpTypesPassPluginInfo();
}


//-----------------------------------------------------------------------------
// Legacy PM Registration
//-----------------------------------------------------------------------------
char LegacyDumpTypesPass::ID = 0;

static RegisterPass<LegacyDumpTypesPass>
X("dump-container-of", "DumpTypes Pass",
    false, // This pass does modify the CFG => false
    false // This pass is not a pure analysis pass => false
);

static llvm::RegisterStandardPasses RegisterDumpTypesLTOThinPass(
    llvm::PassManagerBuilder::EP_OptimizerLast,
    [](const llvm::PassManagerBuilder &Builder,
       llvm::legacy::PassManagerBase &PM) { PM.add(new LegacyDumpTypesPass()); });

static llvm::RegisterStandardPasses RegisterDumpTypesLTOPass(
    llvm::PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    [](const llvm::PassManagerBuilder &Builder,
       llvm::legacy::PassManagerBase &PM) { PM.add(new LegacyDumpTypesPass()); });
