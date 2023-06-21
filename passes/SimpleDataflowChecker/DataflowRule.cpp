#include "SimpleDataflowChecker/DataflowRule.hpp"
#include "SimpleDataflowChecker/SimpleDataflowChecker.hpp"

#include "llvm/IR/GetElementPtrTypeIterator.h"

using namespace llvm;

Type *GEPGetFirstType(Value *V, bool *stopFlow) {
  Type *sinkType = nullptr;
  Type *sourceType = nullptr;

  if (const GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(V)) {
    gep_type_iterator GTI = gep_type_begin(*GEP);
    for (unsigned I = 1, E = GEP->getNumOperands(); I != E; ++I, ++GTI) {
      sinkType = GTI.getStructType();
    }
    sourceType = GEP->getSourceElementType();
  } else if (const GEPOperator *GEP = dyn_cast<GEPOperator>(V)) {
    gep_type_iterator GTI = gep_type_begin(*GEP);
    for (unsigned I = 1, E = GEP->getNumOperands(); I != E; ++I, ++GTI) {
      sinkType = GTI.getStructType();
    }
    sourceType = GEP->getSourceElementType();
  }

  if (sinkType && sourceType &&
      GetTypeName(sinkType) != GetTypeName(sourceType)) {
    // ignore those GEPs due to FPs
    if (stopFlow)
      *stopFlow = true;
    return nullptr;
  }

  return sinkType;
}

// Print the instruction location, and optionally the instruction itself
static std::string valueToLocation(const Value* V, bool colors=true) {
  if (PrintInstructions) {
    std::string str;
    llvm::raw_string_ostream rso(str);

    if (!isa<Function>(V))
      V->print(rso);

    if(const Instruction *I = dyn_cast<Instruction>(V))
      return instructionToLocation(I, colors) + str;
    else if (const Function *F = dyn_cast<Function>(V))
      return functionToLocation(F, colors);
    else if (const Argument *A = dyn_cast<Argument>(V))
      return functionToLocation(A->getParent(), colors) + str;

  } else {
    if(const Instruction *I = dyn_cast<Instruction>(V))
      return instructionToLocation(I, colors);
    else if (const Function *F = dyn_cast<Function>(V))
      return functionToLocation(F, colors);
    else if (const Argument *A = dyn_cast<Argument>(V))
      return functionToLocation(A->getParent(), colors);
  }
  std::string str;
  llvm::raw_string_ostream rso(str);
  V->print(rso);
  return str;
}

std::map<const Instruction *, ContainerOf> buildContainerOfMap(Module &M) {
  static thread_local std::map<const Instruction *, ContainerOf> container_of_map;

  if (container_of_map.size() > 0)
    return container_of_map;

  Value* inPtr   = nullptr;
  Type*  inType = nullptr;
  const Instruction *inPtrI = nullptr;
  Type*  resType = nullptr;

  for (Function &F : M) {
    for (auto &BB: F) {
      for(auto &I: BB) {
        if (StoreInst* SI = dyn_cast<StoreInst>(&I)) {
          // get the pointer where we are storing
          Value* storeTarget = SI->getPointerOperand();

          // if not a global it cannot be interesting
          if (!isa<GlobalValue>(storeTarget)) continue;

          std::string ptrName = storeTarget->getName().str();

          if ((ptrName.find("__container_of_flow_ptr_in") != std::string::npos)) {
            // oprint("found __container_of_ptr_in: " << *SI);
            Value* valueStored = SI->getOperand(0);
            inPtrI = SI;

            // get the input of the container_of
            if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
              inPtr = PI->getOperand(0);
            } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
              inPtr = PI->getOperand(0);
            } else {
              // oprint("unrecognized ptr_in");
              // oprint(*valueStored);
              inPtr = valueStored;
            }
          }
          if (inPtr && (ptrName.find("__container_of_flow_type_in") != std::string::npos)) {
            Value* valueStored = SI->getOperand(0);

            // get the type input of the container_of
            if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
              inType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
            } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
              inType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
            } else {
              // oprint("unrecognized type_in");
              // oprint(*SI);
              // oprint(*valueStored);
            }
          }
          if (inPtr && inType && ptrName.find("__container_of_flow_type_out") != std::string::npos) {
            // oprint("found __container_of_type_out: " << *SI);
            Value* valueStored = SI->getOperand(0);

            // get the type from the ptrtoint instruction
            if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
              resType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
            } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
              resType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
            } else {
              oprint("unrecognized type_out");
              oprint(*SI);
              oprint(*valueStored);
            }
          }
        }
        if (inPtr && resType) {
          ContainerOf cO;
          cO.resType = resType;
          cO.inPtr = inPtr;
          cO.inType = inType;
          container_of_map[inPtrI] = cO;

          inPtr = nullptr;
          inType = nullptr;
          resType = nullptr;
        }
      }
    }
  }
  return container_of_map;
}

std::map<const Instruction *, ContainerOf> buildListMap(Module &M) {
  static thread_local std::map<const Instruction *, ContainerOf> list_map;

  if (list_map.size() > 0)
    return list_map;

  Value* inPtr   = nullptr;
  const Instruction *inPtrI = nullptr;
  Type*  resType = nullptr;

  for (Function &F : M) {
    for (auto &BB: F) {
      for(auto &I: BB) {
        if (StoreInst* SI = dyn_cast<StoreInst>(&I)) {
          // get the pointer where we are storing
          Value* storeTarget = SI->getPointerOperand();

          // if not a global it cannot be interesting
          if (!isa<GlobalValue>(storeTarget)) continue;

          std::string ptrName = storeTarget->getName().str();

          if ((ptrName.find("__list_entry_flow_ptr_in") != std::string::npos)) {
            // oprint("found __list_entry_flow_ptr_in: " << *SI);
            Value* valueStored = SI->getOperand(0);
            inPtrI = SI;

            // get the input of the container_of
            if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
              inPtr = PI->getOperand(0);
            } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
              inPtr = PI->getOperand(0);
            } else {
              // oprint("unrecognized ptr_in");
              // oprint(*valueStored);
              inPtr = valueStored;
            }
          }
          if (inPtr && ptrName.find("__list_entry_flow_type_out") != std::string::npos) {
            // oprint("found __list_entry_flow_type_out: " << *SI);
            Value* valueStored = SI->getOperand(0);

            // get the type from the ptrtoint instruction
            if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
              resType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
            } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
              resType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
            } else {
              oprint("unrecognized type_out");
              oprint(*SI);
              oprint(*valueStored);
            }
          }
        }
        if (inPtr && resType) {
          ContainerOf cO;
          cO.resType = resType;
          cO.inPtr = inPtr;
          list_map[inPtrI] = cO;

          inPtr = nullptr;
          resType = nullptr;
        }
      }
    }
  }
  return list_map;
}

//-----------------------------------------------------------------------------
//  DataflowSource implementation
//-----------------------------------------------------------------------------
raw_ostream& operator<<(raw_ostream& os, const DataflowSource& d)
{
  d.write(os);
  return os;
}

void DataflowSource::write(raw_ostream& os) const {
  if (PrintInstructions) {
    source->print(os);
  }
}

void BackwardsContainedDataflowSource::write(raw_ostream& os) const {
  if (type) {
    os << type->getStructName();
    if (PrintInstructions) {
      os << ": ";
    }
  }

  if (PrintInstructions)
    source->print(os);
}

void KObjDataflowSource::write(raw_ostream& os) const {
  if (containerType) {
    os << containerType->getStructName();
    if (PrintInstructions) {
      os << ": ";
    }
  }

  if (PrintInstructions)
    source->print(os);
}

//-----------------------------------------------------------------------------
//  DataflowSink implementation
//-----------------------------------------------------------------------------
raw_ostream& operator<<(raw_ostream& os, const DataflowSink& d)
{
  d.write(os);
  return os;
}

void DataflowSink::write(raw_ostream& os) const {
  if (PrintInstructions) {
    sink->print(os);
  }
}

void BackwardsContainedDataflowSink::write(raw_ostream& os) const {
  if (sinkType) {
    os << sinkType->getStructName();
    if (PrintInstructions) {
      os << ": ";
    }
  }
  if (PrintInstructions)
    sink->print(os);
}

//-----------------------------------------------------------------------------
//  DataflowRule implementation
//-----------------------------------------------------------------------------
DataflowRule::DataflowRule(Module& M, YAML::Node& config) {
  initialize(M, config);
}

void DataflowRule::initialize(Module& M, YAML::Node& config) {
  container_of_map = buildContainerOfMap(M);

  // parse options as first step
  if (config["options"]) {
    parseOptions(config["options"]);
  }

  name = config["name"].as<std::string>();
  sources = getSources(M, config["source"].as<std::string>());

  if (config["sink"].as<std::string>() == "ANY")
    any_sink = true;
  else if (config["sink"].as<std::string>() == "CMPNULL")
    cmp_null = true;
  else
    sinks = getSinks(M, config["sink"].as<std::string>());

  if (config["ignore"]) {
    ignores = getIgnores(M, config["ignore"].as<std::list<std::string>>());
  }

  if (config["sanitizers"]) {
    sanitizers = getSanitizers(M, config["sanitizers"]);
  }
}

void DataflowRule::dump() {
  oprint("[rule]: " << name);
  oprint("- sources:");
  for (auto source : sources) {
    oprint(*source);
  }
  oprint("- sinks:");
  for (auto sink : sinks) {
    oprint(*sink);
  }
  if (any_sink) oprint("  ANY");
  oprint("- ignores:");
  for (auto ignore: ignores) {
    if (isa<Function>(ignore))
      oprint("  " << cast<Function>(ignore)->getName());
    else
      oprint(*ignore);
  }
  oprint("- sanitizers:");
  for (auto& sanitizer: sanitizers) {
    oprint("  " << *sanitizer);
  }
}

// check if value V may have been sanitized by any of the sanitized values
bool DataflowRule::isSanitized(const Value* V, std::set<const Instruction*>& sanitizerInstructions) {
  static thread_local DominatorTree DT;
  if (const Instruction* I = dyn_cast<Instruction>(V)) {
    for (auto &sanitizerI: sanitizerInstructions) {
      if (I->getFunction() == sanitizerI->getFunction()) {
        const Function *F = I->getFunction();
        // lazily recompute the dominator tree when needed
        if (!DT.getRoot() || DT.getRoot()->getParent() != F) {
          DT.reset();
          DT.recalculate(*const_cast<Function*>(F));
        }
        // If it is the sanitizer itself, then sanitize
        if (I==sanitizerI) return true;

        // If the sanitizer dominates the instruction, then it is safe to use
        if (DT.dominates(sanitizerI, I)) return true;

        // If we also accept reachability, then check for it
        // We may want to avoid FP in cases where checks are split over multiple flows,
        // e.g., for loops and complex branches. We should check whether the set of sanitizers
        // dominates the instructions, but we currently have no way to do it, so check for
        // simple reachability
        if (sanitize_reachable && isPotentiallyReachable(sanitizerI, I, {}, &DT)) return true;
      }
    }
  }
  return false;
}

DataflowSink *DataflowRule::isSink(Value* V, DataflowSource *source) {
  // ANY: check for load/store instructions or external calls
  if (any_sink) {
    if (CallBase * CB = dyn_cast<CallBase>(V)) {
      // Only if they represent direct calls to functions
      if (CB->isInlineAsm()) return new DataflowSink(V);
      Function *Called = dyn_cast<Function>(CB->getCalledOperand()->stripPointerCasts());
      if (!Called || Called->isDeclaration() || Called->isIntrinsic()) return new DataflowSink(V);

      if (sinks.find(Called) != sinks.end()) return new DataflowSink(V);
    }
    if (isa<StoreInst>(V) || isa<LoadInst>(V)) return new DataflowSink(V);
  } else if (cmp_null) {
    if (CmpInst * CI = dyn_cast<CmpInst>(V)) {
      for (Value* operand: CI->operands()) {
        if (isa<ConstantPointerNull>(operand)) {
          return new DataflowSink(V);
        }
      }
    }
  } else if (sinks.find(V) != sinks.end()) {
    return new DataflowSink(V);
  }
  return nullptr;
}

bool DataflowRule::isIgnore(Value *V) {
  return ignores.find(V) != ignores.end();
}

bool DataflowRule::isSanitizer(Value* V, const Offset& offset) {
  for(auto& sanitizer: sanitizers) {
    if (sanitizer->match(V, offset)) {
      return true;
    }
  }
  return false;
}

// gather all the instructions that match any sanitizer rule in the function F
// if target_source is true, only match sanitizers that should sanitize dataflow sources
void DataflowRule::gatherAllSanitizers(const Function* F, std::set<const Instruction *> &out, bool target_source/*=false*/) {
  for (const auto& BB: *F) {
    for (const auto& I: BB) {
      for(auto& sanitizer: sanitizers) {
        // if target_source, then skip matching in case this sanitizer does not apply to sources
        if (target_source) {
          if (!sanitizer->sanitize_source) continue;
        }
        // match with invalid offset
        if (sanitizer->match(&I, Offset(0, false))) {
          out.insert(&I);
        }
      }
    }
  }
}

void DataflowRule::reportFlow(DataflowSource *source, DataflowSink *sink, std::shared_ptr<Dataflow> Dataflow) {
  oprint("--- [" << RED("DATAFLOW RULE TRIGGER") << "] ---\nrule: " << name);
  if (!sink->message.empty()) {
    oprint(sink->message);
  }
  oprint(BLUE("source") << ": " << *source);
  if (const Instruction* sourceI = dyn_cast<Instruction>(source->instruction)) {
    oprint("  at: " << instructionToLocation(sourceI));
  }

  oprint(BLUE("sink") << ": " << *sink);
  if (const Instruction* sinkI = dyn_cast<Instruction>(sink->sink)) {
    oprint("  at: " << instructionToLocation(sinkI));
  }
  // the starting location is the trigger location, unless we didn't trigger
  // on an instruction
  int depth = 0;
  oprint(BLUE("flow") << ":");
  std::string lastFrame = "";
  std::string frames = "";
  // Collect the frames in reverse to print from source to sink
  while(Dataflow) {
    std::string frameStr = valueToLocation(Dataflow->flow->stripPointerCasts());
    // If compact, print only if the new frame is different
    if (!CompactPrint || frameStr != lastFrame) {
      frames = ("[" + (PBOLD(std::string("#") + std::to_string(depth++))) + "] " + frameStr + "\n") + frames;
      lastFrame = frameStr;
    }
    // get next flow
    Dataflow = Dataflow->next;
  }
  oprint(frames);
}

void DataflowRule::dumpReport(std::string& filename, DataflowSource *source, DataflowSink *sink, std::shared_ptr<Dataflow> Dataflow) {
  std::ofstream report_file(filename, std::ofstream::app);

  std::string type_str;
  raw_string_ostream rso(type_str);

  rso << "  - { rule: \"" << name << "\", ";

  if (!sink->message.empty()) {
    rso << "msg: \"" << sink->message << "\", ";
  }
  if (const Instruction* sourceI = dyn_cast<Instruction>(source->instruction)) {
    rso << "source: " << instructionToYAMLLocation(sourceI) << ", ";
  }

  if (const Instruction* sinkI = dyn_cast<Instruction>(sink->sink)) {
    rso << "sink: " << instructionToYAMLLocation(sinkI) << ", ";
  }
  // the starting location is the trigger location, unless we didn't trigger
  // on an instruction
  int depth = 0;
  rso << "flow: [";
  std::string lastFrame = "";
  std::string frames = "";
  while(Dataflow) {
    if (const Constant *C = dyn_cast<Constant>(Dataflow->flow)) {
      // get next flow
      Dataflow = Dataflow->next;
      continue;
    }
    std::string frameStr = valueToYAMLLocation(Dataflow->flow->stripPointerCasts());
    // If compact, print only if the new frame is different
    if (!CompactPrint || frameStr != lastFrame) {
      if (frames == "")
        frames = frameStr;
      else
        frames = frameStr + ", " + frames;
      lastFrame = frameStr;
    }
    // get next flow
    Dataflow = Dataflow->next;
  }
  rso << frames << "]}\n";
  report_file << rso.str();
}

std::set<DataflowSource *, CompareSource> DataflowRule::getSources(Module& M, std::string&& _source) {
  Function* F = M.getFunction(_source);
  if (!F)
    warning("No function found for source: " + _source);

  std::set<DataflowSource *, CompareSource> sources;
  for (auto source : getCallsTo(F)) {
    DataflowSource *src = new DataflowSource(/*source=*/source, /*instruction*/source);
    sources.insert(src);
  }
  return sources;
}

std::set<const Value*> DataflowRule::getSinks(Module& M, std::string&& _sink) {
  Function* F = M.getFunction(_sink);
  if (!F)
    warning("No function found for sink: " + _sink);

  std::set<const Value*> sinks;
  for (auto source : getCallsTo(F)) {
    sinks.insert(source);
  }
  return sinks;
}

std::set<const Value*> DataflowRule::getIgnores(Module &M, std::list<std::string>&& ignores) {
  std::set<const Value*> ignoreValues;
  for (auto string_ignore : ignores) {
    Function* F = M.getFunction(string_ignore);
    if (!F)
      warning("Ignore function not found: " << string_ignore);
    else
      ignoreValues.insert(F);
  }
  return ignoreValues;
}

unsigned DataflowRule::getID(std::string&& valueName) {
  // Terminators
  if(valueName == "ret")              return Instruction::InstructionVal + Instruction::Ret;
  else if(valueName == "br")          return Instruction::InstructionVal + Instruction::Br;
  // hack to easily support conditional branch recognitions based on ID
  else if(valueName == "cbr")         return Instruction::InstructionVal + Instruction::Br + CC_BRANCH_ID;
  else if(valueName == "switch")      return Instruction::InstructionVal + Instruction::Switch;
  else if(valueName == "indirectbr")  return Instruction::InstructionVal + Instruction::IndirectBr;
  else if(valueName == "invoke")      return Instruction::InstructionVal + Instruction::Invoke;
  else if(valueName == "resume")      return Instruction::InstructionVal + Instruction::Resume;
  else if(valueName == "unreachable") return Instruction::InstructionVal + Instruction::Unreachable;
  else if(valueName == "cleanupret")  return Instruction::InstructionVal + Instruction::CleanupRet;
  else if(valueName == "catchret")    return Instruction::InstructionVal + Instruction::CatchRet;
  else if(valueName == "catchpad")    return Instruction::InstructionVal + Instruction::CatchPad;
  else if(valueName == "catchswitch") return Instruction::InstructionVal + Instruction::CatchSwitch;
  else if(valueName == "callbr")      return Instruction::InstructionVal + Instruction::CallBr;

  // Standard unary operators...
  else if(valueName == "fneg") return Instruction::InstructionVal + Instruction::FNeg;

  // Standard binary operators...
  else if(valueName == "add")  return Instruction::InstructionVal + Instruction::Add;
  else if(valueName == "fadd") return Instruction::InstructionVal + Instruction::FAdd;
  else if(valueName == "sub")  return Instruction::InstructionVal + Instruction::Sub;
  else if(valueName == "fsub") return Instruction::InstructionVal + Instruction::FSub;
  else if(valueName == "mul")  return Instruction::InstructionVal + Instruction::Mul;
  else if(valueName == "fmul") return Instruction::InstructionVal + Instruction::FMul;
  else if(valueName == "udiv") return Instruction::InstructionVal + Instruction::UDiv;
  else if(valueName == "sdiv") return Instruction::InstructionVal + Instruction::SDiv;
  else if(valueName == "fdiv") return Instruction::InstructionVal + Instruction::FDiv;
  else if(valueName == "urem") return Instruction::InstructionVal + Instruction::URem;
  else if(valueName == "srem") return Instruction::InstructionVal + Instruction::SRem;
  else if(valueName == "frem") return Instruction::InstructionVal + Instruction::FRem;

  // Logical operators...
  else if(valueName == "and") return Instruction::InstructionVal + Instruction::And;
  else if(valueName ==  "or") return Instruction::InstructionVal + Instruction::Or;
  else if(valueName == "xor") return Instruction::InstructionVal + Instruction::Xor;

  // Memory instructions...
  else if(valueName == "alloca")        return Instruction::InstructionVal + Instruction::Alloca;
  else if(valueName == "load")          return Instruction::InstructionVal + Instruction::Load;
  else if(valueName == "store")         return Instruction::InstructionVal + Instruction::Store;
  else if(valueName == "cmpxchg")       return Instruction::InstructionVal + Instruction::AtomicCmpXchg;
  else if(valueName == "atomicrmw")     return Instruction::InstructionVal + Instruction::AtomicRMW;
  else if(valueName == "fence")         return Instruction::InstructionVal + Instruction::Fence;
  else if(valueName == "getelementptr") return Instruction::InstructionVal + Instruction::GetElementPtr;

  // Convert instructions...
  else if(valueName == "trunc")         return Instruction::InstructionVal + Instruction::Trunc;
  else if(valueName == "zext")          return Instruction::InstructionVal + Instruction::ZExt;
  else if(valueName == "sext")          return Instruction::InstructionVal + Instruction::SExt;
  else if(valueName == "fptrunc")       return Instruction::InstructionVal + Instruction::FPTrunc;
  else if(valueName == "fpext")         return Instruction::InstructionVal + Instruction::FPExt;
  else if(valueName == "fptoui")        return Instruction::InstructionVal + Instruction::FPToUI;
  else if(valueName == "fptosi")        return Instruction::InstructionVal + Instruction::FPToSI;
  else if(valueName == "uitofp")        return Instruction::InstructionVal + Instruction::UIToFP;
  else if(valueName == "sitofp")        return Instruction::InstructionVal + Instruction::SIToFP;
  else if(valueName == "inttoptr")      return Instruction::InstructionVal + Instruction::IntToPtr;
  else if(valueName == "ptrtoint")      return Instruction::InstructionVal + Instruction::PtrToInt;
  else if(valueName == "bitcast")       return Instruction::InstructionVal + Instruction::BitCast;
  else if(valueName == "addrspacecast") return Instruction::InstructionVal + Instruction::AddrSpaceCast;

  // Other instructions...
  else if(valueName == "icmp")           return Instruction::InstructionVal + Instruction::ICmp;
  else if(valueName == "fcmp")           return Instruction::InstructionVal + Instruction::FCmp;
  else if(valueName == "phi")            return Instruction::InstructionVal + Instruction::PHI;
  else if(valueName == "select")         return Instruction::InstructionVal + Instruction::Select;
  else if(valueName == "call")           return Instruction::InstructionVal + Instruction::Call;
  else if(valueName == "shl")            return Instruction::InstructionVal + Instruction::Shl;
  else if(valueName == "lshr")           return Instruction::InstructionVal + Instruction::LShr;
  else if(valueName == "ashr")           return Instruction::InstructionVal + Instruction::AShr;
  else if(valueName == "va_arg")         return Instruction::InstructionVal + Instruction::VAArg;
  else if(valueName == "extractelement") return Instruction::InstructionVal + Instruction::ExtractElement;
  else if(valueName == "insertelement")  return Instruction::InstructionVal + Instruction::InsertElement;
  else if(valueName == "shufflevector")  return Instruction::InstructionVal + Instruction::ShuffleVector;
  else if(valueName == "extractvalue")   return Instruction::InstructionVal + Instruction::ExtractValue;
  else if(valueName == "insertvalue")    return Instruction::InstructionVal + Instruction::InsertValue;
  else if(valueName == "landingpad")     return Instruction::InstructionVal + Instruction::LandingPad;
  else if(valueName == "cleanuppad")     return Instruction::InstructionVal + Instruction::CleanupPad;
  else if(valueName == "freeze")         return Instruction::InstructionVal + Instruction::Freeze;
  else report_fatal_error("[CHECKER] unknown instruction for sanitizer: " + valueName);
}

std::set<std::unique_ptr<DataflowSanitizer>> DataflowRule::getSanitizers(Module& M, YAML::Node&& config_sanitizers) {
  std::set<std::unique_ptr<DataflowSanitizer>> sanitizers;
  for (auto config_sanitizer : config_sanitizers) {
    std::unique_ptr<DataflowSanitizer> sanitizer;
    if (config_sanitizer["instruction"]) {

      long match_offset = 0;
      long use_offset = false;
      long match_operand = 0;
      long use_operand = false;
      if (config_sanitizer["offset"]) {
        match_offset = config_sanitizer["offset"].as<long>();
        use_offset = true;
      }
      if (config_sanitizer["operand"]) {
        match_operand = config_sanitizer["operand"].as<long>();
        use_operand = true;
      }
      unsigned match_id = getID(config_sanitizer["instruction"].as<std::string>());

      // create the sanitizer instance
      sanitizer = std::unique_ptr<DataflowSanitizer>(new DataflowInstructionSanitizer(
          match_offset, use_offset, match_operand, use_operand, match_id));

    } else if (config_sanitizer["function_call"]) {

      std::string function = config_sanitizer["function_call"].as<std::string>();

      // create the sanitizer instance
      sanitizer =  std::unique_ptr<DataflowSanitizer>(new DataflowFunctionCallSanitizer(M, function));
    } else {
      report_fatal_error("[CHECKER] unknown sanitizer config for rule: " + this->name);
    }

    // parse whether the sanitizer should also apply to the sources
    if (config_sanitizer["sanitize_source"]) {
      sanitizer->sanitize_source = config_sanitizer["sanitize_source"].as<bool>();
    }
    // if the whole rule should apply to sources, then force the sanitizer
    sanitizer->sanitize_source |= this->sanitize_source;
    // if sanitizer->sanitize_source, signal that we *may* sanitize sources
    this->may_sanitize_source |= sanitizer->sanitize_source;

    // insert the sanitizer
    sanitizers.insert(std::move(sanitizer));
  }
  return sanitizers;
}

void DataflowRule::parseOptions(YAML::Node&& config_options) {
  // flow sensitive and dominant by default
  sanitize_reachable = config_options["sanitize_reachable"]?
    config_options["sanitize_reachable"].as<bool>() : false;
  // avoid aggressively filtering flows by default
  sanitize_implicit_flow = config_options["sanitize_implicit_flow"]?
    config_options["sanitize_implicit_flow"].as<bool>() : false;
  sanitize_source = config_options["sanitize_source"]?
    config_options["sanitize_source"].as<bool>() : false;
  
  // if sanitize_source, then signal that we may sanitize sources
  may_sanitize_source |= sanitize_source;
}

//-----------------------------------------------------------------------------
//  BackwardsContainedDataflowRule implementation
//-----------------------------------------------------------------------------
std::set<DataflowSource *, CompareSource> BackwardsContainedDataflowRule::getSources(Module& M, std::string&& _source) {
  std::set<DataflowSource *, CompareSource> sources;
  std::set<Instruction*> toRemove;
  const Instruction *inPtrI   = nullptr;
  Value* inPtr   = nullptr;
  Type*  inType = nullptr;
  Type*  resType = nullptr;

  for (auto const& container_of : container_of_map) {
    inPtrI = container_of.first;
    inType = container_of.second.inType;
    resType = container_of.second.resType;
    inPtr = container_of.second.inPtr;

    if (const StructType *ST = dyn_cast<StructType>(inType)) {
      // blacklist certain inTypes
      if (ST->getStructName().startswith("struct.lruvec") ||
          ST->getStructName().startswith("struct.cgroup_subsys_state")) {
        continue;
      }
    }

    if (const StructType *ST = dyn_cast<StructType>(resType)) {
      // blacklist certain resTypes
      if (ST->getStructName().startswith("struct.workspace") ||
          ST->getStructName().startswith("struct.usb_hcd")) {
        continue;
      }
    }

    BackwardsContainedDataflowSource *src = new BackwardsContainedDataflowSource(
      /*source=*/inPtr,
      /*instruction=*/inPtrI,
      /*type=*/resType);
    sources.insert(src);
  }

  oprint("done: " << sources.size());
  return sources;
}

DataflowSink *BackwardsContainedDataflowRule::isSink(Value* V, DataflowSource *source) {
  // TODO: currently we only detect incorrect containment, we could also modify this to detect
  // if it is *not* contained in anythin at all
  BackwardsContainedDataflowSource *src = (BackwardsContainedDataflowSource *)source;
  Type *sourceType = src->type;

  DataflowSink *sink = nullptr;
  bool stopFlow = false;

  Type *sinkType = GEPGetFirstType(V, &stopFlow);
  if (sinkType) {
    stopFlow = true;
    if (GetTypeName(sinkType) == GetTypeName(sourceType)) {
      sinkType = nullptr;
    } else {
      // hack to deal with container_of(..., ..., member.member) but two GEPs going back to the contained type
      // since it's usually only two levels deep we exclude reports if the sinkType is contained within the
      // sourceType (container_of target type)
      if (const StructType *ST = dyn_cast<StructType>(sourceType)) {
        for (unsigned i = 0, e = ST->getNumElements(); i != e; ++i) {
          Type* elemT = ST->getElementType(i);
          if (GetTypeName(sinkType) == GetTypeName(elemT)) {
            sinkType = nullptr;
            stopFlow = false;
            break;
          }
        }
      }
    }
  }

  if (sinkType) {
    if (sinkType->isStructTy() && sourceType->isStructTy()) {
      sink = new BackwardsContainedDataflowSink(/*sink=*/ V, /*sinkType=*/ sinkType, /*stopFlow=*/ stopFlow);
    } else if (!sinkType->isIntegerTy(8)) {
      auto I = src->instruction;
      auto F = I->getFunction();
      // oprint("ERROR?!: \n\tfunction: " << I->getFunction()->getName() << ", " << *sinkType << " != \n\tfunction: " << F->getName() << ", " << *sourceType);
    }

    if (!sink)
      sink = new BackwardsContainedDataflowSink(nullptr, nullptr, /*stopFlow=*/ stopFlow);
  } else if (stopFlow) {
    sink = new BackwardsContainedDataflowSink(nullptr, nullptr, /*stopFlow=*/ stopFlow);
  }

  return sink;
}

//-----------------------------------------------------------------------------
//  KObjSourcesDataflowRule implementation
//-----------------------------------------------------------------------------
KObjSourcesDataflowRule::KObjSourcesDataflowRule(Module& M) : DataflowRule() {
  backward_flow = true;
  getSources(M);
}

void KObjSourcesDataflowRule::getSources(Module &M) {
  Function *F = M.getFunction("kobject_init_and_add");
  for (const CallBase* call : getCallsTo(F)) {
    KObjSourcesDataflowSource *src = new KObjSourcesDataflowSource(
      /*source=*/call->getOperand(0),
      /*instruction=*/call,
      /*containerType=*/nullptr,
      /*callBase=*/call);
    sources.insert(src);
  }
}

DataflowSink *KObjSourcesDataflowRule::isSink(Value* V, DataflowSource *source) {
  KObjSourcesDataflowSource *src = dynamic_cast<KObjSourcesDataflowSource*>(source);
  if(!src) {
    report_fatal_error("[CHECKER]: unexpected source type in KObjSourcesDataflowRule");
  }

  bool stopFlow = false;
  Type *sinkType = GEPGetFirstType(V, &stopFlow);
  if (sinkType || stopFlow) {
    StructType *structType = nullptr;

    if (!src->containerType) {
      src->containerType = sinkType;
    }

    // stop the flow on every GEP instruction
    return new DataflowSink(nullptr, /*stopFlow=*/true);
  }

  return nullptr;
}

//-----------------------------------------------------------------------------
//  KObjDataflowRule implementation
//-----------------------------------------------------------------------------
std::set<DataflowSource *, CompareSource> KObjDataflowRule::getSources(Module& M, std::string&& _source) {
  std::set<DataflowSource *, CompareSource> sources;
  KObjSourcesDataflowRule *rule = new KObjSourcesDataflowRule(M);

  for (auto source: rule->sources) {
    std::set<const Instruction *> sanitizerInstructions;
    KObjSourcesDataflowSource *kObjSrc = dynamic_cast<KObjSourcesDataflowSource*>(source);
    SimpleDataflowChecker().searchFlows(kObjSrc, *rule, sanitizerInstructions);
    const CallBase *CB = kObjSrc->callBase;

    if (GlobalVariable *GV = dyn_cast<GlobalVariable>(CB->getOperand(1)->stripPointerCasts())) {
      if (ConstantStruct *CS = dyn_cast<ConstantStruct>(GV->getInitializer())) {
        // Elt is 'sys_ops'
        Constant *Elt = CS->getAggregateElement((unsigned)1);
        if (GlobalVariable *GVOps = dyn_cast<GlobalVariable>(Elt->stripPointerCasts())) {
          if (ConstantStruct *CSOps = dyn_cast<ConstantStruct>(GVOps->getInitializer())) {
            // Elt is show
            // TODO: add store function as well
            Constant *Elt = CSOps->getAggregateElement((unsigned)0);
            if (Function *showF = dyn_cast<Function>(Elt)) {
              Argument *Arg = showF->getArg(0);
              KObjDataflowSource *src = new KObjDataflowSource(
                /*source=*/Arg,
                /*instruction=*/CB,
                /*containerType=*/kObjSrc->containerType,
                /*callBase=*/CB);
              sources.insert(src);
            }
          }
        }
      }
    }
  }
  return sources;
}

bool KObjDataflowRule::isSanitized(const Value* V, std::set<const Instruction*>& sanitizerInstructions) {
  // we only want to look at container_of with the original type originating from the kobj
  if (const GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(V)) {
    return true;
  } else if (const GEPOperator *GEP = dyn_cast<GEPOperator>(V)) {
    return true;
  }
  return false;
}

DataflowSink *KObjDataflowRule::isSink(Value* V, DataflowSource *source) {
  KObjDataflowSource *src = dynamic_cast<KObjDataflowSource*>(source);
  if(!src) {
    report_fatal_error("[CHECKER]: unexpected source type in KObjDataflowRule");
  }

  if (StoreInst* SI = dyn_cast<StoreInst>(V)) {
    if (container_of_map.count(SI) == 0)
      return nullptr;

    if (const Instruction *I = dyn_cast<Instruction>(V)) {
      Type *resType = container_of_map[I].resType;

      if (!src->containerType) {
        BackwardsContainedDataflowSink *sink = new BackwardsContainedDataflowSink(
          /*sink=*/V,
          /*sinkType=*/resType,
          /*stopFlow=*/false,
          /*message=*/"kobj was not contained!");
        return sink;
      }

      Type *containerType = src->containerType;

      if (resType && resType->isStructTy() && containerType->isStructTy()) {
        if (GetTypeName(resType) != GetTypeName(containerType)) {
          // hack to deal with container_of(..., ..., member.member) but two GEPs going back to the contained type
          // since it's usually only two levels deep we exclude reports if the sinkType is contained within the
          // sourceType (container_of target type)
          if (const StructType *ST = dyn_cast<StructType>(resType)) {
            for (unsigned i = 0, e = ST->getNumElements(); i != e; ++i) {
              Type* elemT = ST->getElementType(i);
              if (GetTypeName(containerType) == GetTypeName(elemT)) {
                return nullptr;
              }
            }
          }
          BackwardsContainedDataflowSink *sink = new BackwardsContainedDataflowSink(
          /*sink=*/V,
          /*sinkType=*/resType,
          /*stopFlow=*/false,
          /*message=*/"kobj was contained differently!");
          return sink;
        }
      }
    }
  }
  return nullptr;
}

//-----------------------------------------------------------------------------
//  ListEntryCorrelationSourcesDataflowRule implementation
//-----------------------------------------------------------------------------
ListEntryCorrelationSourcesDataflowRule::ListEntryCorrelationSourcesDataflowRule(Module& M) : DataflowRule() {
  backward_flow = true;
  getSources(M);
}

void ListEntryCorrelationSourcesDataflowRule::getSources(Module &M) {
  for (Function &F : M) {
    if ((F.getName().equals("list_add") ||
        F.getName().startswith("list_add.")) &&
        F.arg_size() == 2) {
      for (const CallBase* call : getCallsTo(&F)) {
        KObjSourcesDataflowSource *src = new KObjSourcesDataflowSource(
            /*source=*/call->getOperand(0),
            /*instruction=*/call,
            /*containerType=*/nullptr,
            /*callBase=*/call);
        sources.insert(src);
      }
    }
  }
  for (Function &F : M) {
    if ((F.getName().equals("list_add_tail") ||
        F.getName().startswith("list_add_tail.")) &&
        F.arg_size() == 2) {
      for (const CallBase* call : getCallsTo(&F)) {
        KObjSourcesDataflowSource *src = new KObjSourcesDataflowSource(
            /*source=*/call->getOperand(0),
            /*instruction=*/call,
            /*containerType=*/nullptr,
            /*callBase=*/call);
        sources.insert(src);
      }
    }
  }
}

DataflowSink *ListEntryCorrelationSourcesDataflowRule::isSink(Value* V, DataflowSource *source) {
  KObjSourcesDataflowSource *src = dynamic_cast<KObjSourcesDataflowSource*>(source);
  if(!src) {
    report_fatal_error("[CHECKER]: unexpected source type in KObjSourcesDataflowRule");
  }

  bool stopFlow = false;
  Type *sinkType = GEPGetFirstType(V, &stopFlow);
  if (sinkType || stopFlow) {
    StructType *structType = nullptr;

    if (!src->containerType) {
      src->containerType = sinkType;
    }

    // stop the flow on every GEP instruction
    return new DataflowSink(nullptr, /*stopFlow=*/true);
  }

  return nullptr;
}

//-----------------------------------------------------------------------------
//  ListEntryCorrelationDataflowRule implementation
//-----------------------------------------------------------------------------
ListEntryCorrelationDataflowRule::ListEntryCorrelationDataflowRule(
    Module& M, YAML::Node& config) : DataflowRule() {
  buildListAddMap(M);
  list_map = buildListMap(M);
  initialize(M, config);
}

/* build a map of callbase instructions to list_add and what type the list_head is contained in */
void ListEntryCorrelationDataflowRule::buildListAddMap(Module& M) {
  ListEntryCorrelationSourcesDataflowRule *rule = new ListEntryCorrelationSourcesDataflowRule(M);
  for (auto source: rule->sources) {
    std::set<const Instruction *> sanitizerInstructions;
    KObjSourcesDataflowSource *kObjSrc = dynamic_cast<KObjSourcesDataflowSource*>(source);
    SimpleDataflowChecker().searchFlows(kObjSrc, *rule, sanitizerInstructions);

    if (!kObjSrc->containerType) {
      oprint("list_add_tail not contained :( : " << kObjSrc->instruction->getFunction()->getName());
      continue;
    }

    /* ignore anonymous structs for now */
    if (StructType *ST = dyn_cast<StructType>(kObjSrc->containerType)) {
      if (ST->getName().equals("struct.anon") || ST->getName().startswith("struct.anon."))
        continue;
      if (ST->getName().equals("struct.sysv_shm"))
        continue;
    }

    list_add_map[kObjSrc->instruction] = kObjSrc->containerType;
  }
}

std::set<DataflowSource *, CompareSource> ListEntryCorrelationDataflowRule::getSources(
    Module& M, std::string&& _source) {
  std::set<DataflowSource *, CompareSource> sources;

  /* source in list_add */
  for (auto list_add: list_add_map) {
     const Instruction *I = list_add.first;
     Type *containerType = list_add.second;

     BackwardsContainedDataflowSource *src = new BackwardsContainedDataflowSource(
         /*source=*/I->getOperand(1), /* start flow from the list head */
         /*instruction=*/I,
         /*type=*/containerType);
     sources.insert(src);
  }

  /* source in list_entry */
  for (auto const& list_entry : list_map) {
    const Value *inPtrI = list_entry.first;
    Type *resType = list_entry.second.resType;
    Value* inPtr = list_entry.second.inPtr;

    BackwardsContainedDataflowSource *src = new BackwardsContainedDataflowSource(
      /*source=*/inPtr,
      /*instruction=*/(Instruction *)inPtrI,
      /*type=*/resType);
    sources.insert(src);
  }

  oprint("done: " << sources.size());
  return sources;
}

DataflowSink *ListEntryCorrelationDataflowRule::isSink(Value* V, DataflowSource *source) {
  BackwardsContainedDataflowSource *src = dynamic_cast<BackwardsContainedDataflowSource*>(source);
  if(!src) {
    report_fatal_error("[CHECKER]: unexpected source type in ListEntryCorrelationDataflowRule");
  }

  DataflowSink *sink = nullptr;
  Type *sinkType = nullptr;

  /* sink in a list_add */
  if (CallBase *CB = dyn_cast<CallBase>(V)) {
    if (list_add_map.count(CB) == 0)
      return nullptr;
    sinkType = list_add_map[CB];
  }

  /* sink in a list_entry */
  if (const StoreInst* SI = dyn_cast<StoreInst>(V)) {
    if (list_map.count(SI) == 0)
      return nullptr;

    if (const Instruction *I = dyn_cast<Instruction>(V))
      sinkType = list_map[I].resType;
  }

  if (sinkType && GetTypeName(sinkType) != GetTypeName(src->type)) {
    /* hack to check if the sinkType actually contains the source type */
    if (const StructType *ST = dyn_cast<StructType>(sinkType)) {
      for (unsigned i = 0, e = ST->getNumElements(); i != e; ++i) {
        Type* elemT = ST->getElementType(i);
        if (GetTypeName(src->type) == GetTypeName(elemT)) {
          return nullptr;
        }
      }
    }

    sink = new BackwardsContainedDataflowSink(
        /*sink=*/V,
        /*sinkType=*/sinkType,
        /*stopFlow=*/false,
        /*message=*/"");
  }

  bool stopFlow = false;
  Type *T = GEPGetFirstType(V, &stopFlow);
  if (T || stopFlow) {
    // stop the flow on every GEP instruction
    return new DataflowSink(nullptr, /*stopFlow=*/true);
  }

  return sink;
}
