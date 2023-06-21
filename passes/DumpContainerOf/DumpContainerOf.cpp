//=============================================================================
// FILE:
//     DumpContainerOf.cpp
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

extern "C" {
#include <unistd.h>
#include <errno.h>
#include <sys/file.h>  // for flock()
}

using namespace llvm;

#define oprint(s) (outs() << s << "\n")

#define EDGES_LOGFILE "container_of_edges.txt"
#define NODES_LOGFILE "container_of_nodes.txt"

#define DUMP_DEBUG 1

//-----------------------------------------------------------------------------
//  DumpContainerOf implementation
//-----------------------------------------------------------------------------
// No need to expose the internals of the pass to the outside world - keep
// everything in an anonymous namespace.
namespace {

class DumpContainerOf {
  Module *Mod;
  LLVMContext *Ctx;

  bool init(Module &M);
  bool visitor(Function &F);
  void dumpToFile(const char* filename, std::string& s);

public:
  bool runImpl(Module &M);
};

bool DumpContainerOf::init(Module &M) {
  Mod = &M;
  Ctx = &M.getContext();

  return true;
}

void DumpContainerOf::dumpToFile(const char* filename, std::string& s) {
  // appending to a file is atomic, so should be safe but just to be sure
  #define LOCKNAME "/tmp/uncontained_lock"
  int fd = open(LOCKNAME, O_RDWR | O_CREAT, 0664); // open or create lockfile
  int rc = flock(fd, LOCK_EX); // grab exclusive lock

  std::ofstream log(filename, std::ofstream::app);
  log << s;

  // unlock
  flock(fd, LOCK_UN);
  close(fd);
}

static std::string getDebugLocation(Instruction &I) {
    if (DILocation *Loc = I.getDebugLoc()) {
      unsigned Line = Loc->getLine();
      unsigned Col  = Loc->getColumn();
      StringRef File = Loc->getFilename();
      DILocation *InlineLoc = Loc->getInlinedAt();
      // not worth
      if (Line == 0 && Col == 0) return "";
      if (!InlineLoc)
        return "file: " + File.str() + ", line: " + std::to_string(Line) + ", col:" + std::to_string(Col);
      else {
        unsigned InLine = InlineLoc->getLine();
        unsigned InCol  = InlineLoc->getColumn();
        StringRef InFile = InlineLoc->getFilename();
        return "file: " + File.str() + ", line: " + std::to_string(Line) + ", col:" + std::to_string(Col) +
            ", inlined at: " + InFile.str() + ", line: " + std::to_string(InLine) + ", col:" + std::to_string(InCol);
      }
    } else {
      // No location metadata available
      return "";
    }
}

bool DumpContainerOf::visitor(Function &F) {
    // assume container_of stores information in __container_of_ptr_in, __container_of_type_in, __container_of_type_out, __container_of_ptr_out, __container_of_ptr_diff
    // strictly in this order
    Value* ptrCasted = nullptr;
    Type*  srcType   = nullptr;
    Type*  dstType   = nullptr;
    Value* resCasted = nullptr;
    Instruction* resInstr = nullptr;
    int64_t ptrDiff  = -1;
    bool ptrDiffFound = false;
    DataLayout* DL = new DataLayout(F.getParent());
    for (auto &BB: F) {
        for(auto &I: BB) {
            if (StoreInst* SI = dyn_cast<StoreInst>(&I)) {
                // get the pointer where we are storing
                Value* storeTarget = SI->getPointerOperand();

                // if not a global it cannot be interesting
                if (!isa<GlobalValue>(storeTarget)) continue;

                // get the name of the variable where we are storing
                std::string ptrName = storeTarget->getName().str();

                // try to get the ptr we are casting
                if(!ptrCasted && (ptrName.find("__container_of_ptr_in") != std::string::npos)) {
                    Value* valueStored = SI->getOperand(0);

                    // get the ptr we are casting
                    if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
                        ptrCasted = PI->getOperand(0);
                    } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
                        ptrCasted = PI->getOperand(0);
                    }
                // try to get the source type we are casting
                } else if (ptrCasted && (ptrName.find("__container_of_type_in") != std::string::npos)) {
                    Value* valueStored = SI->getOperand(0);

                    // get the type from the ptrtoint instruction
                    if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
                        srcType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
                    } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
                        srcType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
                    }
                // try to get the destination type we are casting
                } else if (ptrCasted && srcType && (ptrName.find("__container_of_type_out") != std::string::npos)) {
                    Value* valueStored = SI->getOperand(0);

                    // get the type from the ptrtoint instruction
                    if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
                        dstType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
                    } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
                        dstType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
                    }
                // try to get the result of the container_of
                } else if (ptrCasted && srcType && dstType && (ptrName.find("__container_of_ptr_out") != std::string::npos)) {
                    Value* valueStored = SI->getOperand(0);

                    // get the result of the container_of
                    if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
                        resCasted = PI->getOperand(0);
                        resInstr = SI;
                    } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
                        resCasted = PI->getOperand(0);
                        resInstr = SI;
                    }
                } else if (ptrCasted && srcType && dstType && resCasted && (ptrName.find("__container_of_ptr_diff") != std::string::npos)) {
                  Value* valueStored = SI->getOperand(0);
                  if (ConstantInt* CI = dyn_cast<ConstantInt>(valueStored)) {
                    ptrDiffFound = true;
                    ptrDiff = CI->getZExtValue();
                  } else {
                    // in some obscure cases, the container_of offset may not be a constant
                    // see: https://elixir.bootlin.com/linux/v5.17.1/source/kernel/pid.c#L404
                    ptrDiffFound = true;
                    ptrDiff = -1;
                  }
                }

                // if we found everything, dump and restart searching
                if (ptrCasted && srcType && dstType && resCasted && ptrDiffFound) {

                    // compute hashes
                    size_t src_hash = TypeToNameHash(srcType);
                    size_t dst_hash = TypeToNameHash(dstType);
                    {
                        std::string type_str;
                        raw_string_ostream rso(type_str);
                        // dump the edge
                        rso << format_hex(src_hash, 18, /*upper=*/ false);
                        rso << " -> ";
                        rso << format_hex(dst_hash, 18, /*upper=*/ false);
                        if(DUMP_DEBUG) {
                          rso << " -> ";
                          rso << getDebugLocation(*resInstr);
                          rso << " -> ";
                          rso << ptrDiff;
                          rso << ", ";
                          rso << DL->getTypeAllocSize(dstType);
                        }
                        rso << "\n";

                        // std::cout << type_str;
                        dumpToFile(EDGES_LOGFILE, rso.str());
                    }
                    {
                        std::string type_str;
                        raw_string_ostream rso(type_str);
                        // dump the type info
                        rso << format_hex(src_hash, 18, /*upper=*/ false);
                        rso << ": ";
                        srcType->print(rso);
                        rso << "\n";
                        rso << format_hex(dst_hash, 18, /*upper=*/ false);
                        rso << ": ";
                        dstType->print(rso);
                        rso << "\n";

                        dumpToFile(NODES_LOGFILE, rso.str());
                    }

                    // reset all
                    ptrCasted = nullptr;
                    srcType   = nullptr;
                    dstType   = nullptr;
                    resCasted = nullptr;
                    ptrDiffFound = false;
                    ptrDiff = -1;
                }
            }
        }
    }
    return true;
}

bool DumpContainerOf::runImpl(Module &M) {
  bool Changed = false;
  for (Function &F : M)
    Changed |= visitor(F);
  dbgs() << "dumped container_of\n";
  return Changed;
}

// New PM implementation
struct DumpContainerOfPass : PassInfoMixin<DumpContainerOfPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    bool Changed = DumpContainerOf().runImpl(M);
    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};

// Legacy PM implementation
struct LegacyDumpContainerOfPass : public ModulePass {
  static char ID;
  LegacyDumpContainerOfPass() : ModulePass(ID) {}
  // Main entry point - the name conveys what unit of IR this is to be run on.
  bool runOnModule(Module &M) override {
    return DumpContainerOf().runImpl(M);
  }
};
} // namespace

//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
llvm::PassPluginLibraryInfo getDumpContainerOfPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "DumpContainerOf", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](llvm::ModulePassManager &PM,
                  llvm::PassBuilder::OptimizationLevel Level) {
                PM.addPass(DumpContainerOfPass());
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "dump-container-of") {
                    MPM.addPass(DumpContainerOfPass());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getDumpContainerOfPassPluginInfo();
}


//-----------------------------------------------------------------------------
// Legacy PM Registration
//-----------------------------------------------------------------------------
char LegacyDumpContainerOfPass::ID = 0;

static RegisterPass<LegacyDumpContainerOfPass>
X("dump-container-of", "DumpContainerOf Pass",
    false, // This pass does modify the CFG => false
    false // This pass is not a pure analysis pass => false
);

static llvm::RegisterStandardPasses RegisterDumpContainerOfLTOThinPass(
    llvm::PassManagerBuilder::EP_OptimizerLast,
    [](const llvm::PassManagerBuilder &Builder,
       llvm::legacy::PassManagerBase &PM) { PM.add(new LegacyDumpContainerOfPass()); });

static llvm::RegisterStandardPasses RegisterDumpContainerOfLTOPass(
    llvm::PassManagerBuilder::EP_FullLinkTimeOptimizationEarly,
    [](const llvm::PassManagerBuilder &Builder,
       llvm::legacy::PassManagerBase &PM) { PM.add(new LegacyDumpContainerOfPass()); });
