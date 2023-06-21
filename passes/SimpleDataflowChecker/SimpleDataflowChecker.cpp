//=============================================================================
// FILE:
//     SimpleDataflowChecker.cpp
//
// DESCRIPTION:
// Check simple dataflow invariants
//
//=============================================================================
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/Analysis/CFG.h"

#include "llvm/Transforms/IPO/PassManagerBuilder.h" // RegisterStandardPasses
#include <llvm/Transforms/Scalar.h>
#include "llvm/Support/FormatVariadic.h"

#include "SimpleDataflowChecker/SimpleDataflowChecker.hpp"
#include "SimpleDataflowChecker/DataflowRule.hpp"

#include "yaml-cpp/yaml.h"

#include <iostream>
#include <fstream>
#include <map>
#include <mutex>
#include <chrono>
#include <iomanip>

extern "C" {
#include <unistd.h>
#include <errno.h>
#include <sys/file.h>  // for flock()
}

#include "TypeUtils/TypeUtils.hpp"

using namespace llvm;

#define oprint(s) (outs() << s << "\n")
#define eprint(s) (errs() << s << "\n")
#define warning(s) (errs() << "[" YELLOW("WARNING") "] " << s << "\n")

cl::opt<bool>
PrintInstructions("print-instructions",
    cl::desc("Print the involved IR instructions (very slow on big files)"),
    cl::init(false), cl::NotHidden);

cl::opt<bool>
CompactPrint("compact-print",
    cl::desc("Print the flow skipping repeated locations (i.e., multiple instructions on the same line)"),
    cl::init(true), cl::NotHidden);

static cl::opt<std::string>
ConfigFilename("config",
    cl::desc("The configuration file"),
    cl::init("config.yaml"), cl::NotHidden);

static cl::opt<std::string>
ReportFilename("dump-reports",
    cl::desc("If set, dump yaml reports"),
    cl::init("reports.yaml"), cl::NotHidden);

static cl::opt<bool>
OnlyFirst("only-first",
    cl::desc("Report at most one flow per source value"),
    cl::init(true), cl::NotHidden);

//-----------------------------------------------------------------------------
//  SimpleDataflowChecker implementation
//-----------------------------------------------------------------------------

// shared pointer linked list, to be used functionally
// will make fast copies and appends only
struct CallFrame {
  const std::shared_ptr<CallFrame> next;
  const CallBase* CB;

  CallFrame(const CallBase* _CB, const std::shared_ptr<CallFrame>& _next): next(_next), CB(_CB) {}
};

bool SimpleDataflowChecker::init(Module &M) {
  return true;
}

void SimpleDataflowChecker::parseRule(Module& M, YAML::Node& config_rule, std::set<DataflowRule*>& rules) {
  if (config_rule["name"]) {
    if (config_rule["name"].as<std::string>().compare("backwards_contained") == 0) {
      oprint(config_rule["name"].as<std::string>());

      BackwardsContainedDataflowRule *rule = new BackwardsContainedDataflowRule(M, config_rule);
      rules.insert(rule);
      return;
    } else if (config_rule["name"].as<std::string>().compare("kobj") == 0) {
      oprint(config_rule["name"].as<std::string>());

      KObjDataflowRule *rule = new KObjDataflowRule(M, config_rule);
      rules.insert(rule);
      return;
    } else if (config_rule["name"].as<std::string>().compare("list_entry_correlation") == 0) {
      oprint(config_rule["name"].as<std::string>());

      ListEntryCorrelationDataflowRule *rule = new ListEntryCorrelationDataflowRule(M, config_rule);
      rules.insert(rule);
      return;
    }
  }

  if (!config_rule["name"] || !config_rule["source"] || !config_rule["sink"]) {
    report_fatal_error("[CHECKER] malformed rule: ");
    return;
  }

  oprint(config_rule["name"].as<std::string>());

  rules.insert(new DataflowRule(M, config_rule));
}

void initVisitQueue(const Value* source, std::list<std::pair<std::shared_ptr<Dataflow>, std::shared_ptr<CallFrame>>> &toVisit) {
  toVisit.clear();
  // Push the initial dataflow
  std::shared_ptr<Dataflow> InitDataflow;
  Offset init_offset(0, true);
  // If the source is a call, then make a fake initial dataflow on the call itself
  if (const CallBase* CB = dyn_cast<CallBase>(source)) {
    std::shared_ptr<Dataflow> CallDataflow = std::make_shared<Dataflow>(CB->getCalledOperand(), init_offset, nullptr);
    InitDataflow = std::make_shared<Dataflow>(source, init_offset, CallDataflow);
  } else {
    InitDataflow = std::make_shared<Dataflow>(source, init_offset, nullptr);
  }
  toVisit.push_back(std::make_pair(InitDataflow, nullptr));
}

// update the visit queue from the use
void updateVisitQueueFromUse(DataflowRule& rule, const Use& use, std::shared_ptr<Dataflow> &NewDataflow,
                          std::shared_ptr<CallFrame> &ParentFrame,
                          std::list<std::pair<std::shared_ptr<Dataflow>, std::shared_ptr<CallFrame>>> &toVisit) {
  User* user = use.getUser();
  // If the use is a call, then examine interprocedurally all the uses of the corresponding
  // argument, while updating the current call frame
  if(CallBase *CB = dyn_cast<CallBase>(user)) {
    Function* F = dyn_cast<Function>(CB->getCalledOperand()->stripPointerCasts());
    if (F) {
      // We do not parse vararg functions
      if(F->isVarArg()) return;

      // Do not visit functions calls to ignore
      if(rule.isIgnore(F)) return;

      unsigned int argnum = CB->getArgOperandNo(&use);
      if (!CB->isArgOperand(&use)) {
        eprint("CB: "<< *CB);
        eprint("use: " << *use);
        eprint("argnum:" << argnum);
        // if this triggers, the use is probably the function called itself (e.g., casting function)
        report_fatal_error("[CHECKER] internal error, not a valid use for a call");
      }
      Argument* userArg = F->getArg(argnum);
      // Add the new frame to be called
      std::shared_ptr<CallFrame> NewParentFrame = std::make_shared<CallFrame>(CB, ParentFrame);
      // Push the argument as dataflow
      std::shared_ptr<Dataflow> ArgDataflow = std::make_shared<Dataflow>(userArg, NewDataflow->offset, NewDataflow);
      toVisit.push_front(std::make_pair(ArgDataflow, NewParentFrame));
    }
  // If the use is a return, then continue to examine the caller of the return, popping the
  // stack frame
  } else if (ReturnInst *RI = dyn_cast<ReturnInst>(user)) {
    // If we have a parent frame, then return to it
    if(ParentFrame) {
      // Push the call we return to, to the dataflow
      std::shared_ptr<Dataflow> ReturnDataflow = std::make_shared<Dataflow>(ParentFrame->CB, NewDataflow->offset, NewDataflow);
      toVisit.push_front(std::make_pair(ReturnDataflow, ParentFrame->next));
    }
    // Otherwise we are in the source frame, and we have to analyze all the possible functions
    // that may call this function
    else {
      for (const Value* call : getCallsTo(RI->getFunction())) {
        // Push the call we return to, to the dataflow
        std::shared_ptr<Dataflow> ReturnDataflow = std::make_shared<Dataflow>(call, NewDataflow->offset, NewDataflow);
        toVisit.push_front(std::make_pair(ReturnDataflow, nullptr));
      }
    }
  } else {
    toVisit.push_front(std::make_pair(NewDataflow, ParentFrame));
  }
}

void updateVisitQueueFromUseBackwards(const Value *val, std::shared_ptr<Dataflow> &CurrentDataflow,
                          std::shared_ptr<CallFrame> &ParentFrame,
                          std::list<std::pair<std::shared_ptr<Dataflow>, std::shared_ptr<CallFrame>>> &toVisit) {

  // Push the new user to the dataflow
  if (const Argument *A = dyn_cast<Argument>(val)) {
    unsigned argNo = A->getArgNo();

    if (ParentFrame == nullptr) {
      // where could the taint come from
      auto calls = getCallsTo(A->getParent());
      for (const Value* CBV: calls) {
        const CallBase* CB = dyn_cast<CallBase>(CBV);
        Value *operand = CB->getOperand(argNo);
        if (const Function *F = dyn_cast<Function>(operand)) {
          continue;
        }
        std::shared_ptr<Dataflow> NewDataflow = DataflowBackwards::pass_through(CurrentDataflow, operand);
        toVisit.push_front(std::make_pair(NewDataflow, ParentFrame));
      }
    } else {
      // TODO: go back to that argument of the CB
    }
  } else if (const User *U = dyn_cast<User>(val)) {
    Type *resultElementType = nullptr;
    if (const LoadInst *LI = dyn_cast<LoadInst>(val)) {
      // we currently stop propagating on loads
      return;
    } else if (const Function *F = dyn_cast<Function>(val)) {
      // we are not interested in functions
      return;
    } else if (const Constant *C = dyn_cast<Constant>(val)) {
      // we are not interested in constants
      return;
    } else if (const SelectInst *SI = dyn_cast<SelectInst>(val)) {
      // we are not interested in the condition of a select
      const Value *trueOperand = SI->getTrueValue();
      const Value *falseOperand = SI->getFalseValue();

      std::shared_ptr<DataflowBackwards> NewDataflowTrue = DataflowBackwards::pass_through(CurrentDataflow, trueOperand);
      toVisit.push_front(std::make_pair(NewDataflowTrue, ParentFrame));
      std::shared_ptr<DataflowBackwards> NewDataflowFalse = DataflowBackwards::pass_through(CurrentDataflow, falseOperand);
      toVisit.push_front(std::make_pair(NewDataflowFalse, ParentFrame));
      return;
    } else if (const PHINode *PHI = dyn_cast<PHINode>(val)) {
      // we are only about incoming values not incoming blocks
      for (Value *V : PHI->incoming_values()) {
        std::shared_ptr<DataflowBackwards> NewDataflow = DataflowBackwards::pass_through(CurrentDataflow, V);
        toVisit.push_front(std::make_pair(NewDataflow, ParentFrame));
      }
      return;
    } else if (const CallBase *CB = dyn_cast<CallBase>(val)) {
      // taint is returned by a call, let's add all the return instructions of that function
      // to the toVisit queue
      Function *Called = dyn_cast<Function>(CB->getCalledOperand()->stripPointerCasts());
      if (!Called || Called->isDeclaration() || Called->isIntrinsic()) return;
      // TODO: this is specific to the current use case and should be replaced with sanitizer rules
      if (Called->getName().equals("kmem_cache_alloc") ||
          Called->getName().equals("radix_tree_lookup") ||
          Called->getName().equals("rht_bucket_nested_insert") ||
          Called->getName().equals("__rht_bucket_nested"))
        return;
      for (const auto& BB: *Called) {
        for (const auto& I: BB) {
          if (const ReturnInst *RI = dyn_cast<ReturnInst>(&I)) {
            std::shared_ptr<CallFrame> NewParentFrame = std::make_shared<CallFrame>(CB, ParentFrame);
            std::shared_ptr<DataflowBackwards> NewDataflow = DataflowBackwards::pass_through(CurrentDataflow, RI->getReturnValue());
            toVisit.push_front(std::make_pair(NewDataflow, NewParentFrame));
          }
        }
      }
      return;
    }

    unsigned numOperands = U->getNumOperands();
    for (int opNum = 0; opNum < numOperands; opNum++) {
      Value *operand = U->getOperand(opNum);
      if (isa<Function>(operand))
        continue;
      if (isa<Constant>(operand))
        continue;
      // oprint("operand: " << *operand);
      std::shared_ptr<DataflowBackwards> NewDataflow = DataflowBackwards::pass_through(CurrentDataflow, operand);
      toVisit.push_front(std::make_pair(NewDataflow, ParentFrame));
    }
  }
}

// Check wether the source itself may be already sanitized
bool SimpleDataflowChecker::isSourceSanitized(const Value* source, DataflowRule& rule) {
  std::set<const Instruction *> sanitizerInstructions;
  // Analyze the source sanitizers
  if (const Instruction* sourceI = dyn_cast<Instruction>(source)) {
    rule.gatherAllSanitizers(sourceI->getFunction(), sanitizerInstructions, /*target_source=*/true);
    // If we already spot that the flow is sanitized, then finish here
    if (rule.isSanitized(source, sanitizerInstructions)) return true;

    // Heuristic: check also all the possible callers of the function where the source is in
    // and declare the source sanitized if all the calls are
    auto calls = getCallsTo(sourceI->getFunction());
    for (const Value* CBV: calls) {
      const CallBase* CB = dyn_cast<CallBase>(CBV);
      if (!CB) report_fatal_error("[CHECKER] internal error. Invalid call");
      // reset the sanitizers collected as they will all be in separate functions
      sanitizerInstructions.clear();
      // Gather all the sanitizers in the function that calls the function where the source is in
      rule.gatherAllSanitizers(CB->getFunction(), sanitizerInstructions, /*target_source=*/true);
      // If a call is not sanitized, then the source isn't
      if (!rule.isSanitized(CB, sanitizerInstructions)) return false;
    }
    // If all the calls where sanitized then the source is
    if(!calls.empty()) return true;
  }
  return false;
}

std::set<const Instruction *> SimpleDataflowChecker::getSanitizers(const Value* source, DataflowRule& rule) {
  // previous dataflow, caller and value, to keep track where to return
  static thread_local std::list<std::pair<std::shared_ptr<Dataflow>, std::shared_ptr<CallFrame>>> toVisit;
  static thread_local std::set<const Value *> visited;
  static thread_local std::set<const Function*> visitedFuncs;
  std::set<const Instruction *> sanitizerInstructions;
  // no need to visit if there are no sanitizers
  if (rule.sanitizers.empty()) return sanitizerInstructions;

  visited.clear();
  visitedFuncs.clear();
  initVisitQueue(source, toVisit);

  while (!toVisit.empty()) {
    std::pair<std::shared_ptr<Dataflow>, std::shared_ptr<CallFrame>> FlowAndParentFrames = toVisit.front();
    std::shared_ptr<Dataflow> CurrentDataflow = FlowAndParentFrames.first;
    std::shared_ptr<CallFrame> ParentFrame = FlowAndParentFrames.second;
    const Value* curr = CurrentDataflow->flow;

    // oprint("visiting: " << *curr);

    // Always pop from the front
    toVisit.pop_front();
    if (visited.find(curr) != visited.end()) continue;

    // Always visit call bases as their flow depends on the argument position
    // otherwise we should track which argument we analyzed
    if (!isa<CallBase>(curr))
      visited.insert(curr);

    // If the rule should take into account implicit flows, then analyze them
    if (rule.sanitize_implicit_flow) {
      if (const Instruction* currI = dyn_cast<Instruction>(curr)) {
        if (visitedFuncs.find(currI->getFunction()) == visitedFuncs.end()) {
          visitedFuncs.insert(currI->getFunction());
          rule.gatherAllSanitizers(currI->getFunction(), sanitizerInstructions);
        }
      }
    }

    // Visit each use of the value
    for (const Use& use : curr->uses()) {

      User* user = use.getUser();

      // Push the new user to the dataflow
      std::shared_ptr<Dataflow> NewDataflow = Dataflow::pass_through(CurrentDataflow, user);

      // Check if the value sanitizes the flow
      if (rule.isSanitizer(user, CurrentDataflow->offset)) {
        if (Instruction* userI = dyn_cast<Instruction>(user)) {
          sanitizerInstructions.insert(userI);
          continue;
        }
      }

      // update the queue
      updateVisitQueueFromUse(rule, use, NewDataflow, ParentFrame, toVisit);
    }
  }
  return sanitizerInstructions;
}

void SimpleDataflowChecker::searchFlows(DataflowSource *source, DataflowRule& rule, std::set<const Instruction *> &sanitizerInstructions) {
  // previous dataflow, caller and value, to keep track where to return
  static thread_local std::list<std::pair<std::shared_ptr<Dataflow>, std::shared_ptr<CallFrame>>> toVisit;
  static thread_local std::set<const Value *> visited;

  visited.clear();
  initVisitQueue(source->source, toVisit);

  while (!toVisit.empty()) {
    std::pair<std::shared_ptr<Dataflow>, std::shared_ptr<CallFrame>> FlowAndParentFrames = toVisit.front();
    std::shared_ptr<Dataflow> CurrentDataflow = FlowAndParentFrames.first;
    std::shared_ptr<CallFrame> ParentFrame = FlowAndParentFrames.second;
    const Value* curr = CurrentDataflow->flow;

    // oprint("visiting: " << *curr);
    // if (const Instruction *I = dyn_cast<Instruction>(curr)) {
    //   oprint("visiting (func): " << I->getFunction()->getName());
    // }

    // Always pop from the front
    toVisit.pop_front();
    if (visited.find(curr) != visited.end()) continue;

    // Always visit call bases as their flow depends on the argument position
    // otherwise we should track which argument we analyzed
    // add always to visited with backward_flow
    if (!isa<CallBase>(curr) || rule.backward_flow)
      visited.insert(curr);

    if (rule.backward_flow) {
      DataflowSink *sink = rule.isSink((Value *)curr, source);
      if(sink) {
        if (sink->sink) {
          // update stats
          addStatistics(&*sink);
          rule.reportFlow(source, &*sink, CurrentDataflow);
          if (!ReportFilename.getValue().empty())
            rule.dumpReport(ReportFilename, source, &*sink, CurrentDataflow);
          if (OnlyFirst) return;
        }
        if (sink->stopFlow) {
          delete sink;
          continue;
        }
        delete sink;
      }

      updateVisitQueueFromUseBackwards(curr, CurrentDataflow, ParentFrame, toVisit);
    } else {
      // Visit each use of the value
      for (const Use& use : curr->uses()) {

        User* user = use.getUser();

        // Push the new user to the dataflow
        std::shared_ptr<Dataflow> NewDataflow = Dataflow::pass_through(CurrentDataflow, user);

        // If the value is in a sanitized flow, then break it
        if (rule.isSanitized(user, sanitizerInstructions)) {
          continue;
        }

        // If the value is used in a sink, then trigger the report
        DataflowSink *sink = rule.isSink((Value *)user, source);
        if(sink) {
          if (sink->sink) {
            // update stats
            addStatistics(&*sink);
            rule.reportFlow(source, &*sink, NewDataflow);
            if (!ReportFilename.getValue().empty())
              rule.dumpReport(ReportFilename, source, &*sink, NewDataflow);
            if (OnlyFirst) return;
          }
          if (sink->stopFlow) {
            delete sink;
            continue;
          }
          delete sink;
        }


        // update the queue
        updateVisitQueueFromUse(rule, use, NewDataflow, ParentFrame, toVisit);
      }
    }
  }
}

void SimpleDataflowChecker::checkRule(DataflowRule& rule, Module& M) {
  // Two pass analysis to gather all the sanitizers first, and then search flows
  for (auto source: rule.sources) {
    // If we have to check sanitizers on the source too, then do it first
    if (rule.may_sanitize_source && isSourceSanitized(source->source, rule)) continue;
    // first pass to gather all the sanitizers of the current source
    std::set<const Instruction *> sanitizerInstructions = getSanitizers(source->source, rule);
    // second pass to actually check flows
    searchFlows(source, rule, sanitizerInstructions);
  }
}

void SimpleDataflowChecker::addStatistics(DataflowSink *sink) {
  const Value *V = sink->sink;

  std::lock_guard<std::mutex> guard(map_mutex);

  std::string Directory;
  if(const Instruction *I = dyn_cast<Instruction>(V))
    Directory = getDebugLocation(*I);
  else if (const Function *F = dyn_cast<Function>(V))
    Directory = getDebugLocation(*F);
  else if (const Argument *A = dyn_cast<Argument>(V))
    Directory = getDebugLocation(*A->getParent());
  else
    Directory = "";
  if (Directory.size() == 0) {
    stats_map["/"] += 1;
    return;
  }
  size_t start = Directory.find_first_not_of("./");
  std::string Submodule = Directory.substr(start, Directory.find_first_of("./", start) - start + 1);
  stats_map[Submodule] += 1;
}

void SimpleDataflowChecker::printStatistics(void) {
  std::lock_guard<std::mutex> guard(map_mutex);
  uint64_t total = 0;
  oprint("---------- [REPORT STAT] ----------");
  for (auto entry: stats_map) {
    oprint(entry.first << ": " << entry.second);
    total += entry.second;
  }
  oprint("total: " << total);
}

bool SimpleDataflowChecker::runImpl(Module &M) {
  if (!init(M))
    return false;

  YAML::Node config = YAML::LoadFile(ConfigFilename);
  std::set<DataflowRule*> rules;

  // initialization of reports file
  if (!ReportFilename.getValue().empty()) {
    std::ofstream report_file(ReportFilename, std::ios::out | std::ios::trunc);
    report_file << "---\nreports:\n";
    report_file.close();
  }

  outs() << "---------- [RULES] ----------\n";
  for (auto config_rule : config["rules"]) {
    parseRule(M, config_rule, rules);
  }

  outs() << "---------- [checking...] ----------\n";
  auto start = std::chrono::high_resolution_clock::now();
  for (auto rule: rules) {
    // Fixme: here we ignore print instructions to debug easier
    if (PrintInstructions)
      rule->dump();
    checkRule(*rule, M);
  }
  auto end = std::chrono::high_resolution_clock::now();

  // print stats
  printStatistics();
  std::chrono::duration<double, std::milli> elapsed = end - start;
  int seconds = static_cast<int>(elapsed.count() / 1000);
  int milliseconds = static_cast<int>(elapsed.count() - seconds * 1000);
  oprint(llvm::formatv("Analysis time: {0:02}.{1:03}\n", seconds, milliseconds));

  return false;
}

// New PM implementation
struct SimpleDataflowCheckerPass : PassInfoMixin<SimpleDataflowCheckerPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    bool Changed = SimpleDataflowChecker().runImpl(M);
    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};

// Legacy PM implementation
struct LegacySimpleDataflowCheckerPass : public ModulePass {
  static char ID;
  LegacySimpleDataflowCheckerPass() : ModulePass(ID) {}
  // Main entry point - the name conveys what unit of IR this is to be run on.
  bool runOnModule(Module &M) override {
    return SimpleDataflowChecker().runImpl(M);
  }
};

//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
llvm::PassPluginLibraryInfo getSimpleDataflowCheckerPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "SimpleDataflowChecker", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](llvm::ModulePassManager &PM,
                  llvm::PassBuilder::OptimizationLevel Level) {
                PM.addPass(SimpleDataflowCheckerPass());
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "check-dataflow") {
                    MPM.addPass(SimpleDataflowCheckerPass());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getSimpleDataflowCheckerPassPluginInfo();
}


//-----------------------------------------------------------------------------
// Legacy PM Registration
//-----------------------------------------------------------------------------
char LegacySimpleDataflowCheckerPass::ID = 0;

static RegisterPass<LegacySimpleDataflowCheckerPass>
X("check-dataflow", "SimpleDataflowChecker Pass",
    true, // This pass does not modify the CFG => true
    true // This pass is a pure analysis pass => true
);

static llvm::RegisterStandardPasses RegisterSimpleDataflowCheckerLTOThinPass(
    llvm::PassManagerBuilder::EP_OptimizerLast,
    [](const llvm::PassManagerBuilder &Builder,
       llvm::legacy::PassManagerBase &PM) { PM.add(new LegacySimpleDataflowCheckerPass()); });

static llvm::RegisterStandardPasses RegisterSimpleDataflowCheckerLTOPass(
    // early opt so we leverage the optimizer to improve our instrumentation
    // and also we deal with simpler code
    llvm::PassManagerBuilder::EP_FullLinkTimeOptimizationEarly,
    [](const llvm::PassManagerBuilder &Builder,
       llvm::legacy::PassManagerBase &PM) { PM.add(new LegacySimpleDataflowCheckerPass()); });
