//=============================================================================
// FILE:
//     ContainerOfSanitizer.cpp
//
// DESCRIPTION:
// This sanitizer adds the necessary checks if the uses of container_of are
// contained correctly.
//
//=============================================================================
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/SSAUpdater.h"
#include "llvm/IR/Verifier.h"

#include <llvm/IR/IRBuilder.h>
#include "llvm/IR/InstVisitor.h"

#include "llvm/Transforms/IPO/PassManagerBuilder.h" // RegisterStandardPasses
#include <llvm/Transforms/Utils/BasicBlockUtils.h> // SplitBlock
#include <llvm/Transforms/Scalar.h>

#include "TypeUtils/TypeUtils.hpp"

#include <iostream>
#include <fstream>
#include <map>
#include <mutex>

extern "C" {
#include <unistd.h>
#include <errno.h>
#include <sys/file.h>  // for flock()
}

using namespace llvm;

#define oprint(s) (outs() << s << "\n")

//-----------------------------------------------------------------------------
//  ContainerOfSanitizer implementation
//-----------------------------------------------------------------------------
// No need to expose the internals of the pass to the outside world - keep
// everything in an anonymous namespace.
namespace {

//                                     Instruction must be either a PHINode or a Select
using InstructionAndIndex = std::tuple<Instruction*, int>;
using Flow = std::list<InstructionAndIndex>;
using InstructionAndFlow = std::tuple<Instruction*, Flow>;
using ValueAndOffset = std::tuple<Value*, int64_t>;
using ValueToInstructions = std::map<ValueAndOffset, std::set<InstructionAndFlow>>;

using range = std::pair<size_t, size_t>;
// graph holding type_hash -> set<container_type, range of offsets the type might be at in container_type>
// we index with type_hash to merge equal types, but we keep type information to be able to compute sizes
// we use ranges to support fixed array types for which we do not know in which cell the object is
// e.g.,
// type:
// struct S1 { struct S2; };
// graph:
// hash(S2) -> <S1, range<0, 0>> /// -> here range.start == range.end
//
// type:
// struct S1 { struct S2[16]; };
// graph:
// hash(S2) -> <S1, range<0, 15*sizeof(S2)>>
// TODO: actually implement the array check, for now it is ignored
using TypeGraph = std::map<size_t, std::set<std::pair<Type*, range>>>;

class InterestingContainerOf {
public:
  // the value which results from container_of
  Value*       ResultPtr;
  // the type to which container_of transforms to
  Type*        SourceType;
  // the type to which container_of transforms to
  Type*        ResultType;
  // the difference the result pointer incurs in
  int64_t     ResultDiff;
  // an instruction whose container_of result is forced to pass through
  Instruction* ResultGate;

  // the map that maintains the relevant users of the container_of output (ResultPtr)
  // with respect to ResultPtr itself (direct users) or the phi node/cast of ResultPtr
  // that dominates those users (forwarded users)
  ValueToInstructions RelevantUsers;

  InterestingContainerOf(Value* ResultPtr, Type* SourceType, Type* ResultType, int64_t ResultDiff, Instruction* ResultGate, ValueToInstructions &RelevantUsers)
      : ResultPtr(ResultPtr), SourceType(SourceType), ResultType(ResultType), ResultDiff(ResultDiff), ResultGate(ResultGate), RelevantUsers(RelevantUsers) {
  }
};

class ContainerOfSanitizer {
  bool init(Module &M);
  bool visitor(Function &F, TypeGraph &typeGraph,
                std::set<size_t> &nosanitizeSrcTypes, std::set<size_t> &nosanitizeDstTypes);
  void instrumentContainerOf(InterestingContainerOf &ContainerOf, std::set<std::pair<size_t, size_t>> &possibleRedzoneBounds);
  void addContainerOfCheck(Value *Ptr, int64_t PtrOffset, Type* T, Instruction *InsertBefore, Flow InstructionFlow, std::set<std::pair<size_t, size_t>> &possibleRedzoneBounds, std::set<CallBase*> &toInline);
  void addStatistics(Instruction *InsertBefore);
  void printStatistics(void);

  std::map<std::string, uint64_t> stats_map;
  std::mutex map_mutex;
  std::atomic<uint64_t> n_instrumented;
  std::atomic<uint64_t> n_checks;
  std::atomic<uint64_t> n_skipped;
  std::atomic<uint64_t> n_skipped_nouncontained;
  std::atomic<uint64_t> n_skipped_nosanitize;

  std::atomic<uint64_t> n_possible_offsets;

  Module *Mod;
  LLVMContext *Ctx;

  Function *checkContainerOfHook;
  Function *maybeCheckContainerOfHook;
  Function *maybeReportContainerOfHook;

public:
  bool runImpl(Module &M);
};

bool ContainerOfSanitizer::init(Module &M) {
  Mod = &M;
  Ctx = &M.getContext();

  std::vector<Type*> checkContainerOfHookParamTypes = {
    Type::getInt8PtrTy(*Ctx),
    Type::getInt8PtrTy(*Ctx),
    Type::getInt64Ty(*Ctx),
  };
  Type *checkContainerOfHookRetType = Type::getInt1Ty(*Ctx);
  FunctionType *checkContainerOfHookFuncType = FunctionType::get(
      checkContainerOfHookRetType,
      checkContainerOfHookParamTypes, false);
  Value *checkContainerOfHookFunc  = Mod->getOrInsertFunction(
      "uncontained_type_check",
      checkContainerOfHookFuncType).getCallee();
  if (checkContainerOfHookFunc == NULL) {
    report_fatal_error("[UNCONTAINED] uncontained_type_check function not found");
    return false;
  }
  checkContainerOfHook = cast<Function>(checkContainerOfHookFunc);

  std::vector<Type*> maybeCheckContainerOfHookParamTypes = {
    Type::getInt8PtrTy(*Ctx),
    Type::getInt8PtrTy(*Ctx),
    Type::getInt64Ty(*Ctx),
    Type::getInt1Ty(*Ctx),
  };
  Type *maybeCheckContainerOfHookRetType = Type::getInt1Ty(*Ctx);
  FunctionType *maybeCheckContainerOfHookFuncType = FunctionType::get(
      maybeCheckContainerOfHookRetType,
      maybeCheckContainerOfHookParamTypes, false);
  Value *maybeCheckContainerOfHookFunc  = Mod->getOrInsertFunction(
      "uncontained_type_maybe_check",
      maybeCheckContainerOfHookFuncType).getCallee();
  if (maybeCheckContainerOfHookFunc == NULL) {
    report_fatal_error("[UNCONTAINED] uncontained_type_maybe_check function not found");
    return false;
  }
  maybeCheckContainerOfHook = cast<Function>(maybeCheckContainerOfHookFunc);

  std::vector<Type*> maybeReportContainerOfHookParamTypes = {
    Type::getInt8PtrTy(*Ctx),
    Type::getInt64Ty(*Ctx),
    Type::getInt1Ty(*Ctx),
  };
  Type *maybeReportContainerOfHookRetType = Type::getVoidTy(*Ctx);
  FunctionType *maybeReportContainerOfHookFuncType = FunctionType::get(
      maybeReportContainerOfHookRetType,
      maybeReportContainerOfHookParamTypes, false);
  Value *maybeReportContainerOfHookFunc  = Mod->getOrInsertFunction(
      "uncontained_type_maybe_report",
      maybeReportContainerOfHookFuncType).getCallee();
  if (maybeReportContainerOfHookFunc == NULL) {
    report_fatal_error("[UNCONTAINED] uncontained_type_maybe_report function not found");
    return false;
  }
  maybeReportContainerOfHook = cast<Function>(maybeReportContainerOfHookFunc);
  return true;
}

static std::string getDebugLocation(Instruction &I) {
  if (DILocation *Loc = I.getDebugLoc()) {
    StringRef File = Loc->getFilename();
    DILocation *InlineLoc = Loc->getInlinedAt();
    if (!InlineLoc)
      return File.str();
    else {
      StringRef InFile = InlineLoc->getFilename();
      return InFile.str();
    }
  } else {
    // No location metadata available
    return "";
  }
}

void ContainerOfSanitizer::addStatistics(Instruction *InsertBefore) {
  std::lock_guard<std::mutex> guard(map_mutex);

  std::string Directory = getDebugLocation(*InsertBefore);
  if (Directory.size() == 0) {
    stats_map["/"] += 1;
    return;
  }
  size_t start = Directory.find_first_not_of("./");
  std::string Submodule = Directory.substr(start, Directory.find_first_of("./", start) - start + 1);
  stats_map[Submodule] += 1;
}

void ContainerOfSanitizer::printStatistics(void) {
  std::lock_guard<std::mutex> guard(map_mutex);
  dbgs() << "---------- [UNCONTAINED STAT] ----------\n";
  for (auto entry: stats_map) {
    dbgs() << entry.first << ": " << entry.second << "\n";
  }
  dbgs() << "          --------------------          \n";
  dbgs() << "[+] instrumented: " << n_instrumented << "\n";
  dbgs() << "    checks inserted: " << n_checks << "\n";
  dbgs() << "    avg inserted:    " << ((double)n_possible_offsets / n_checks) << "\n";
  dbgs() << "[+] skipped: " << n_skipped << "\n";
  dbgs() << "    skipped nounc: " << n_skipped_nouncontained << "\n";
  dbgs() << "    skipped nosan: " << n_skipped_nosanitize << "\n";
  dbgs() << "----------------------------------------\n";
}

// create a GEP instruction for &((char*)ptr)[offset] with offset being either positive or negative
static Value* makeSignedGep(Value *ptr, ssize_t offset,  IRBuilder<> &IRB) {
  Type *CharPtrTy = IRB.getInt8PtrTy();

  // cast to char* if required
  if (ptr->getType() != CharPtrTy)
    ptr = IRB.CreatePointerCast(ptr, CharPtrTy);

  Value *Idx = ConstantInt::get(IRB.getInt64Ty(), offset, /*isSigned=*/true);

  Value *res = IRB.CreateGEP(ptr, Idx, "signed_gep");
  return res;
}

// get or create the companion instruction for I
// companion instructions:
// I: %phinode   = phi i32 [ %a, %BB1 ], [ %b, %BB2 ]
// C: %companion = phi i32 [ 0, %BB1 ], [ 1, %BB2 ]
//
// I: %sel       = select i1 %cond, %a, %b
// C: %companion = select i1 %cond, 0, 1
static Value* getCompanionInstruction(Instruction* I) {
  static thread_local std::map<Instruction*, Value*> Companions;

  if (Companions.find(I) != Companions.end()) return Companions[I];

  IRBuilder<> IRB(I);
  if (PHINode* PHI = dyn_cast<PHINode>(I)) {

    PHINode* Companion = IRB.CreatePHI(IRB.getInt32Ty(), PHI->getNumOperands(), "companion");
    // add the index for each incoming basic block
    for (unsigned i = 0, e = PHI->getNumOperands(); i != e; ++i) {
      Companion->addIncoming(IRB.getInt32(i), PHI->getIncomingBlock(i));
    }

    Companions[I] = Companion;
    return Companion;
  } else if (SelectInst *Sel = dyn_cast<SelectInst>(I)) {

    Value* Companion = IRB.CreateSelect(Sel->getCondition(), IRB.getInt32(0), IRB.getInt32(1), "companion");
    Companions[I] = Companion;
    return Companion;
  }

  errs() << *I << "\n";
  report_fatal_error("[UNCONTAINED] internal error: cannot create companion instruction");
  return nullptr;
}

// compute all the possible offsets for which we could find a redzone wrt T or
// any other type that contains T
// curr_offset is the offsets we point inside T
static void computeAllPossibleObjectBounds(Type* T, DataLayout *DL, TypeGraph &typeGraph,
                                        std::set<std::pair<size_t, size_t>> &possibleBounds, size_t curr_offset=0, bool new_call=true) {

  // optimization:
  // keep track of the nodes we have seen during the visit to avoid repeating
  // unnecessary path visits
  static thread_local std::set<std::pair<Type*, size_t>> SeenNodes;

  // clear the SeenNodes at the first call
  if(new_call) SeenNodes.clear();

  if (SeenNodes.find(std::make_pair(T, curr_offset)) != SeenNodes.end()) {
    return;
  }
  SeenNodes.insert(std::make_pair(T, curr_offset));

  // base case where the object is not contained in another object
  // redzone will be at the end of the object, taking into account the curr_offset
  // and the left redzone will be at curr_offset distance
  size_t RedzoneOff = DL->getTypeAllocSize(T) - curr_offset;
  possibleBounds.insert(std::make_pair(curr_offset, RedzoneOff));
  for (auto &ContainerObj : typeGraph[TypeToNameHash(T)]) {
    Type* ContainerType = ContainerObj.first;

    // the range for which the object of type T may be contained in this outer object
    auto ContainerRange = ContainerObj.second;

    if (ContainerRange.first != ContainerRange.second) {
      report_fatal_error("[UNCONTAINED] internal error: no support for non-constant ranges in container objects (i.e., array of structs)");
    }

    size_t OffsetInContainer = ContainerRange.first;

    // visit the possible container object, updating the current offset
    computeAllPossibleObjectBounds(ContainerType, DL, typeGraph, possibleBounds,
                                 curr_offset + OffsetInContainer, /*new_call=*/false);
  }
}

// Add the sanitizer check for container of by checking that the uncontained-type
// ptr has the right size and position among the redzone
// [--------object--------][--------redzone--------]
// ^                      ^^
// |                      ||
// ptr         ptr+size-1-  - redzone_start
// =====must be valid=====  === must be poisoned====
// if ConstraintFlow is not empty make sure that the check is only performed under
// that specific flow
// possibleRedzoneBounds contains all the possible offsets where we may find the redzone
void ContainerOfSanitizer::addContainerOfCheck(Value *Ptr, int64_t PtrOffset, Type* T, Instruction *InsertBefore, Flow ConstraintFlow, std::set<std::pair<size_t, size_t>> &possibleRedzoneBounds, std::set<CallBase*> &toInline) {

  DominatorTree DT;
  SmallVector<PHINode *, 16> NewPHIs;
  SSAUpdater SSA(&NewPHIs);

  // increase stats first
  ++n_checks;
  // oprint("check: " << *InsertBefore);
  // oprint("ptr: " << *Ptr << " - off: " << PtrOffset);

  Module* Mod = InsertBefore->getModule();
  LLVMContext* Ctx = &Mod->getContext();
  DataLayout* DL = new DataLayout(Mod);
  TypeSize ObjTypeSize = DL->getTypeAllocSize(T);

  Type *CharTy =
      IntegerType::get(*Ctx, 8);
  Type *CharPtrTy = PointerType::get(CharTy, 0);

  IRBuilder<> IRB(InsertBefore);
  Type *Int64Ty = IRB.getInt64Ty();

  // first cast to the right bitsize
  if (Ptr->getType()->isIntegerTy() && Ptr->getType()->getScalarSizeInBits() < sizeof(void*))
    Ptr = IRB.CreateIntCast(Ptr, IRB.getInt64Ty(), /*isSigned=*/true);
  // cast to char* if required
  if (Ptr->getType() != CharPtrTy)
    Ptr = IRB.CreateBitOrPointerCast(Ptr, CharPtrTy);

  // move the pointer to the original base of the object
  if (PtrOffset != 0) {
    Ptr = makeSignedGep(Ptr, -PtrOffset, IRB);
  }

  DebugLoc DbgLoc = InsertBefore->getDebugLoc();
  if (!DbgLoc)
    if (DISubprogram *SP = InsertBefore->getFunction()->getSubprogram())
      DbgLoc = DILocation::get(SP->getContext(), SP->getScopeLine(), 0, SP);
  IRB.SetCurrentDebugLocation(DbgLoc);

  // build the flow dependency only once
  Value *ShouldCheck = IRB.getInt1(true);
  for (InstructionAndIndex II : ConstraintFlow) {
    Instruction *ConstraintI = std::get<0>(II);
    int idx = std::get<1>(II);

    // get the companion instruction mapping conditions to indexes
    Value* CompanionI = getCompanionInstruction(ConstraintI);

    // recalculate since we are modifying the function
    DT.recalculate(*InsertBefore->getFunction());
    // if the companion instruction does not dominate the use we must forward
    // the value properly with an SSAUpdater
    if (!DT.dominates(CompanionI, InsertBefore)) {
      SSA.Initialize(CompanionI->getType(), CompanionI->getName().str() + "_ssa");
      NewPHIs.clear();

      // add the value as available in the BB of the Flow instruction
      SSA.AddAvailableValue(ConstraintI->getParent(), CompanionI);

      // generate the required phinodes to get the value
      CompanionI = SSA.GetValueInMiddleOfBlock(InsertBefore->getParent());

      // remove any undef that may be present in phinodes
      for (PHINode* NewPHI: NewPHIs) {
        Value* Undef = UndefValue::get(NewPHI->getType());
        for (unsigned i = 0, e = NewPHI->getNumOperands(); i != e; ++i) {
          if (NewPHI->getIncomingValue(i) == Undef) {
            NewPHI->setIncomingValue(i, IRB.getInt32(-1));
          }
        }
      }
    }

    // check if the condition holds for this path
    Value* ConstraintSatisfied = IRB.CreateICmpEQ(CompanionI, IRB.getInt32(idx), "constraint_sat");

    // chain the conditions
    ShouldCheck = IRB.CreateAnd(ShouldCheck, ConstraintSatisfied, "constraint_chain");
  }

  // oprint("Checking: " << *Ptr);
  // oprint("Type: " << *T);
  // oprint("Hash: " << TypeToNameHash(T));
  // oprint("Size: " << ObjTypeSize);

  Value *isSafe = IRB.getInt1(false);
  n_possible_offsets += possibleRedzoneBounds.size();
  for (std::pair<size_t, size_t> possibleBound : possibleRedzoneBounds) {
    size_t possibleStartOffset = possibleBound.first;
    size_t possibleRedzoneOffset = possibleBound.second;
    // oprint("  possible off: " << possibleOffset);
    // easy case with no flow constraint
    CallBase* checkCall;
    Value* StartPtr = Ptr;
    // if we are inside a container object, move back to the start
    if (possibleStartOffset) {
      StartPtr = makeSignedGep(Ptr, -possibleStartOffset, IRB);
    }
    // still pass Ptr to check for edge cases errors like ERR pointers
    if (ConstraintFlow.size() == 0) {
      checkCall = IRB.CreateCall(checkContainerOfHook, {Ptr, StartPtr, IRB.getInt64(possibleStartOffset + possibleRedzoneOffset)});
      checkCall->setCallingConv(checkContainerOfHook->getCallingConv());
    } else {
      checkCall = IRB.CreateCall(maybeCheckContainerOfHook, {Ptr, StartPtr, IRB.getInt64(possibleStartOffset + possibleRedzoneOffset), ShouldCheck});
      checkCall->setCallingConv(maybeCheckContainerOfHook->getCallingConv());
      // if the call is to maybe_check, then inline it
      toInline.insert(checkCall);
    }
    isSafe = IRB.CreateOr(isSafe, checkCall, "uncontained_is_safe");
  }

  CallBase *maybeReportCB = IRB.CreateCall(maybeReportContainerOfHook, {Ptr, IRB.getInt64(ObjTypeSize), isSafe});
  maybeReportCB->setCallingConv(maybeReportContainerOfHook->getCallingConv());
  // inline the maybe_report
  toInline.insert(maybeReportCB);
}

// check if the Instruction I is whitelisted to not be sanitized
// `offset` is the distance from the original container_of result
// most of the times is zero, but it adds support to nested GEPs
// get the src type and container_of ptr_diff to check if the I may be a use on
// the original struct, which is always safe
// ptrDiff is -1 when the original container_of was not using a constant offset
static bool isWhitelisted(Instruction *I, int64_t offset, Type* srcType, int64_t ptrDiff) {

  // whitelist use inside the original region of the container_of which is always safe
  // NOTICE: we rely on custom llvm to avoid removing GEP with zero offset. this allows us to support whitelisting container_of from the first field to the outer struct
  Module* Mod = I->getModule();
  LLVMContext* Ctx = &Mod->getContext();
  DataLayout* DL = new DataLayout(Mod);
  TypeSize typeSize = DL->getTypeAllocSize(srcType);
  if (ptrDiff != -1) {
    // if the use is a GEP we should also consider the GEP offset that is added
    // (for now it will always be like that, since we only update the offset in GEP
    // chains, but keep it generic enough)
    if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(I)) {
      APInt Offset = APInt(sizeof(unsigned long)*8, 0);
      if(GEP->accumulateConstantOffset(*DL, Offset)) {
        offset += Offset.getSExtValue();
      }
    }

    if (offset >= ptrDiff && offset < (ptrDiff + typeSize)) {
      return true;
    }
  }

  // call to uncontained_whitelist_use
  if (CallBase * CB = dyn_cast<CallBase>(I)) {
    if (!CB->isInlineAsm()) {
      Function *Called = dyn_cast<Function>(CB->getCalledOperand()->stripPointerCasts());
      if (Called && Called->getName().contains("uncontained_whitelist_use")) {
        return true;
      }
    }
  }
  return false;
}

// find the index at which Use is used in User
// NOTE: only support PHINode and SelectInst
static int searchUseInUser(Value* Use, Instruction* User) {
  if (PHINode* PHI = dyn_cast<PHINode>(User)) {
    for (unsigned i = 0, e = PHI->getNumOperands(); i != e; ++i) {
      if (Use == PHI->getIncomingValue(i)) return i;
    }
  } else if (SelectInst *Sel = dyn_cast<SelectInst>(User)) {
    if (Use == Sel->getTrueValue()) return 0;
    if (Use == Sel->getFalseValue()) return 1;
  }

  errs() << *Use << "\n";
  errs() << *User << "\n";
  report_fatal_error("[UNCONTAINED] internal error: cannot find value in use chain");
  return -1;
}

// Relevant users:
// - load from pointer
// - store from pointer
// - store of pointer
// - gep from pointer
// - passing pointer as parameter
// - returning pointer
// - comparison of pointer with non-const values
// fills the map that maintains the relevant users of value V
// with respect to V itself (direct users) or the phi node/cast of V
// that dominates those users (forwarded users)
// Each value use has associated it's offset from the original ptr value if it is constant
// Each value user (the actual instruction that we will check for V use validity)
// has associated the PHINode flow that will bring to that instruction using a container_of
// result
static void getRelevantUsers(Value *V, ValueToInstructions &RelevantUsersWrtValue, const int64_t curr_offset = 0) {
  // keep track of which direction we visited phinode/select
  // that they could be taking the use from
  static thread_local std::set<InstructionAndIndex> VisitedFlows;
  static thread_local Flow CurrentFlow;

  // visit all the uses of the instruction and the uses of its pointer casts
    Value *curr = V;
    for (Value* user: curr->users()) {
      // if the instruction is a phinode/select check if we saw this flow
      // TODO: maybe we need to check not only the direction but also
      // considering under which flow we saw this
      if (isa<PHINode>(user) || isa<SelectInst>(user)) {
        Instruction *userI = cast<Instruction>(user);
        int idx_in_user = searchUseInUser(curr, userI);
        if (VisitedFlows.find(std::make_tuple(userI, idx_in_user)) != VisitedFlows.end()) {
          continue;
        }

        // if it is a PHINode check if this is a loop and do not visit to flow
        if (PHINode *PHI = dyn_cast<PHINode>(user)) {
          bool seen = false;
          for (InstructionAndIndex II : CurrentFlow) {
            if (std::get<0>(II) == PHI) {
              seen = true;
              break;
            }
          }
          // if we have already saw the PHINode we are in a loop
          // if (seen) continue;
        }
      }

      // forwarded use:
      // if the user is a select or PHINode, we should visit its own users
      if (isa<PHINode>(user) || isa<SelectInst>(user)) {
        // we have a new use dominator to visit
        // and a new flow to keep track of
        Instruction *userI = cast<Instruction>(user);
        int idx_in_user = searchUseInUser(curr, userI);
        CurrentFlow.push_back(std::make_tuple(userI, idx_in_user));
        VisitedFlows.insert(std::make_tuple(userI, idx_in_user));
        getRelevantUsers(user, RelevantUsersWrtValue, curr_offset);
        CurrentFlow.pop_back();
        continue;
      // if the user is a cast, forward it and add the new dominator to visit
      } else if (isa<CastInst>(user) || isa<BitCastOperator>(user) || isa<AddrSpaceCastOperator>(user) || isa<PtrToIntOperator>(user)) {
        // forward the offset to the user
        getRelevantUsers(user, RelevantUsersWrtValue, curr_offset);
        continue;
      // if the user is a GEP, forward it and update the current_offset from the
      // original pointer, only if it is only used by other GEPs, i.e., is a visit
      // to a nested struct non-optimized
      } else if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(user)) {
        Module* Mod = GEP->getModule();
        LLVMContext* Ctx = &Mod->getContext();
        DataLayout* DL = new DataLayout(Mod);
        APInt Offset = APInt(sizeof(unsigned long)*8, 0);

        // GEP tracking only if constant GEP
        if(GEP->accumulateConstantOffset(*DL, Offset)) {
          // update the offset
          int64_t new_offset = curr_offset + Offset.getSExtValue();
          getRelevantUsers(user, RelevantUsersWrtValue, new_offset);
          continue;
        // otherwise check now
        } else {
          RelevantUsersWrtValue[std::make_tuple(curr, curr_offset)].insert(std::make_tuple(GEP, CurrentFlow));
          continue;
        }
      }

      // if this is not an instruction there is something wrong
      Instruction *userI = dyn_cast<Instruction>(user);
      if (!userI) {
        errs() << *user << "\n";
        report_fatal_error("[UNCONTAINED] found container_of result use which is not a cast or instruction");
      }

      // otherwise this is a relevant user
      // TODO: finer check
      RelevantUsersWrtValue[std::make_tuple(curr, curr_offset)].insert(std::make_tuple(userI, CurrentFlow));
    }
}

static void printCheck(Instruction* I, Flow F) {
  oprint("- Checking: " << *I);
  for (auto SelandIdx : F) {
    Instruction *Sel = std::get<0>(SelandIdx);
    int idx = std::get<1>(SelandIdx);
    oprint( idx << ": " << *Sel);
  }
}

static bool flowEq(Flow F1, Flow F2) {
  if (F1.size() != F2.size()) return false;
  int size = F1.size();
  auto F1it = F1.cbegin();
  auto F2it = F2.cbegin();
  while (size > 0)
  {
    Instruction *I1 = std::get<0>(*F1it);
    Instruction *I2 = std::get<0>(*F2it);
    int idx1 = std::get<1>(*F1it);
    int idx2 = std::get<1>(*F2it);
    if (I1 != I2) return false;
    if (idx1 != idx2) return false;
    size--;
    F1it++;
    F2it++;
  }
  return true;
}

// Instrument the uses of container_of to check for KASAN redzones according to the resulting type.
// We leverage a gate instruction where the container_of result is forced to pass through.
void ContainerOfSanitizer::instrumentContainerOf(InterestingContainerOf &ContainerOf, std::set<std::pair<size_t, size_t>> &possibleRedzoneBounds) {

  Value *Ptr = ContainerOf.ResultPtr;
  Type* T = ContainerOf.ResultType;
  Instruction *GateInstruction = ContainerOf.ResultGate;
  ValueToInstructions &RelevantUsers = ContainerOf.RelevantUsers;

  std::set<CallBase*> toInline;

  // add statistics
  addStatistics(GateInstruction);

  // keep track of which values have already been sanitized, and for which flows
  static thread_local std::map<std::tuple<Value*, BasicBlock*>, std::set<Flow>> sanitizedValuesInBB;

  // now instrument all the users
  for (auto ValAndCheckPoint: RelevantUsers) {
    Value* V = std::get<0>(ValAndCheckPoint.first);
    int64_t ValueOffset = std::get<1>(ValAndCheckPoint.first);

    // use the pointer itself instead of the gate instruction, since it may be removed
    if (V == GateInstruction)
      V = Ptr;

    // ignore casts and ptrtoint/inttoptr
    V = V->stripPointerCasts();
    while (isa<PtrToIntInst>(V) || isa<PtrToIntOperator>(V) || isa<IntToPtrInst>(V))
      V = dyn_cast<Operator>(V)->getOperand(0)->stripPointerCasts();

    auto checkPoints = ValAndCheckPoint.second;
    for (InstructionAndFlow checkPoint: checkPoints) {
      Instruction* checkPointI = std::get<0>(checkPoint);
      Flow checkPointFlow = std::get<1>(checkPoint);

      BasicBlock *checkBB = checkPointI->getParent();

      // if we whitelisted the user, then ignore it
      if (isWhitelisted(checkPointI, ValueOffset, ContainerOf.SourceType, ContainerOf.ResultDiff)) continue;

      // printCheck(checkPointI, checkPointFlow);

      // TODO: split basic blocks at callsites, to catch bugs after modifying calls
      // i.e., free invocations
      // sanitize each value only once per BasicBlock and per each flow
      bool seen_flow = false;
      auto VBB = std::make_tuple(V, checkBB);
      for (Flow Fl : sanitizedValuesInBB[VBB]) {
        if (flowEq(checkPointFlow, Fl)) {
          seen_flow = true;
          break;
        }
      }
      if (!seen_flow) {
        addContainerOfCheck(V, ValueOffset, T, checkPointI, checkPointFlow, possibleRedzoneBounds, toInline);
        sanitizedValuesInBB[VBB].insert(checkPointFlow);
      }
    }
  }

  // now try to inline all the calls to maybe_check
  for (CallBase* checkCall: toInline) {
    InlineFunctionInfo ifi;
    // save the debug location of the call and set it to the inlined calls
    DebugLoc DbgLoc = checkCall->getDebugLoc();
    // inline the call
    InlineFunction(*checkCall, ifi);
    // restore the original debug location to the inlined calls
    for (CallBase *inlinedCB: ifi.InlinedCallSites) {
      // avoid messing with debug intrinsics
      if(inlinedCB->getCalledFunction() && inlinedCB->getCalledFunction()->isIntrinsic()) continue;
      inlinedCB->setDebugLoc(DbgLoc);
    }
  }
}

// return true if the type may be variable size, i.e., has/is a char[]-like array at the end
static bool isVariableSize(Type* T) {
  if (ArrayType *AT = dyn_cast<ArrayType>(T)) {
    // detected a char[]-like array
    if (AT->getNumElements() == 0) return true;
    return isVariableSize(AT->getElementType());
  } else if (StructType *ST = dyn_cast<StructType>(T)) {
    // empty struct
    if (ST->getNumElements() == 0) return false;
    Type* LastType = ST->getTypeAtIndex(ST->getNumElements() - 1);
    bool last_variable_size = isVariableSize(LastType);
    // we need to check also the previous last type in the struct, since LLVM
    // may insert an additional padding at the end of the struct to force alignment
    // e.g., cache alignment requested by the kernel
    bool prev_last_variable_size = false;
    if (ST->getNumElements() > 1) {
      Type* PreviousLastType = ST->getTypeAtIndex(ST->getNumElements() - 2);
      prev_last_variable_size = isVariableSize(PreviousLastType);
    }
    return last_variable_size || prev_last_variable_size;
  }
  return false;
}

// check whether the Type *T has the nosanitize annotation
static bool uncontainedNoSanitize(Type *T, std::set<size_t> &nosanitizeTypes) {
  return nosanitizeTypes.find(TypeToNameHash(T)) != nosanitizeTypes.end();
}

// check if the container graph G contains any cycle when starting from type T
static void checkCycles(Type *T, TypeGraph& G, bool new_check=false, int depht=0) {
  static thread_local std::set<Type*> Visited;

  if (new_check) {
    // errs() << "\n";
    Visited.clear();
  }
  if (Visited.find((T)) != Visited.end()) {
    errs() << TypeToNameHash(T) << "\n";
    errs() << *T << "\n";
    report_fatal_error("[UNCONTAINED] internal error: found cycle in type containers graph");
    return;
  }
  // add to recursion stack
  Visited.insert((T));

  for (auto &ContainerObj : G[TypeToNameHash(T)]) {
    Type* ContainerType = ContainerObj.first;

    // visit the possible container object
    // errs() << std::string(depht, '-') << *T << " -> " << *ContainerType << "\n";
    checkCycles(ContainerType, G, false, depht+1);
  }

  // remove from recursion stack
  Visited.erase((T));
}

bool ContainerOfSanitizer::visitor(Function &F, TypeGraph &typeGraph,
                                    std::set<size_t> &nosanitizeSrcTypes, std::set<size_t> &nosanitizeDstTypes) {
  // keep track of the volatile stores to be removed, the optimizer should
  // remove the rest
  std::set<Instruction*> toRemove;
  // keep track of the container_of invocations to instrument
  SmallVector<InterestingContainerOf, 16> ContainerOfToInstrument;

  DataLayout* DL = new DataLayout(F.getParent());

  { // block to avoid misusage of local variables
    // assume container_of stores information in __container_of_ptr_in, __container_of_type_in, __container_of_type_out, __container_of_ptr_out, __container_of_ptr_diff
    // __container_of_ptr_out should have a store and a load to wrap and retrieve the result
    // strictly in this order
    Type*  resType = nullptr;
    Value* resPtr  = nullptr;
    Type*  inType = nullptr;
    Value* inPtr   = nullptr;
    int64_t ptrDiff  = -1;
    bool ptrDiffFound = false;
    // Container of location of the volatile store and load
    Instruction* resInstr = nullptr;

    // Collect all the container_of invocations to instrument
    for (auto &BB: F) {
      for(auto &I: BB) {
        if (StoreInst* SI = dyn_cast<StoreInst>(&I)) {
          // get the pointer where we are storing
          Value* storeTarget = SI->getPointerOperand();

          // if not a global it cannot be interesting
          if (!isa<GlobalValue>(storeTarget)) continue;

          // get the name of the variable where we are storing
          std::string ptrName = storeTarget->getName().str();

          if ((ptrName.find("__container_of_ptr_in") != std::string::npos)) {
            Value* valueStored = SI->getOperand(0);

            // get the input of the container_of
            if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
              inPtr = PI->getOperand(0);
              toRemove.insert(SI);
            } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
              inPtr = PI->getOperand(0);
              toRemove.insert(SI);
            } else {
              // oprint("unrecognized ptr_in");
              // oprint(*valueStored);
              inPtr = valueStored;
              toRemove.insert(SI);
            }
          } else if (inPtr && (ptrName.find("__container_of_type_in") != std::string::npos)) {
            Value* valueStored = SI->getOperand(0);

            // get the type input of the container_of
            if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
              inType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
              toRemove.insert(SI);
            } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
              inType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
              toRemove.insert(SI);
            } else {
              oprint("unrecognized type_in");
              oprint(*SI);
              oprint(*valueStored);
            }
          } else if (inPtr && inType && (ptrName.find("__container_of_type_out") != std::string::npos)) {
            Value* valueStored = SI->getOperand(0);

            // get the type from the ptrtoint instruction
            if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
              resType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
              toRemove.insert(SI);
            } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
              resType = PI->getOperand(0)->getType()->getPointerElementType()->getPointerElementType();
              toRemove.insert(SI);
            } else {
              oprint("unrecognized type_out");
              oprint(*SI);
              oprint(*valueStored);
            }
          } else if (inPtr && inType && resType && (ptrName.find("__container_of_ptr_out") != std::string::npos)) {
            Value* valueStored = SI->getOperand(0);

            // get the result of the container_of
            if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
              resPtr = PI->getOperand(0);
              toRemove.insert(SI);
            } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
              resPtr = PI->getOperand(0);
              toRemove.insert(SI);
            } else {
              // oprint("unrecognized ptr_out");
              // oprint(*valueStored);
              // resPtr = valueStored;
              // toRemove.insert(SI);
            }
          } else if (inPtr && inType && resType && resPtr && (ptrName.find("__container_of_ptr_diff") != std::string::npos)) {
            Value* valueStored = SI->getOperand(0);
            if (ConstantInt* CI = dyn_cast<ConstantInt>(valueStored)) {
              ptrDiffFound = true;
              ptrDiff = CI->getSExtValue();
              toRemove.insert(SI);
            } else {
              // in some obscure cases, the container_of offset may not be a constant
              // see: https://elixir.bootlin.com/linux/v5.17.1/source/kernel/pid.c#L404
              ptrDiffFound = true;
              ptrDiff = -1;
              toRemove.insert(SI);
            }
          // remove also unneeded global variables
          } else if ((ptrName.find("__uncontained_complex_alloc") != std::string::npos) ||
                     (ptrName.find("__uncontained_kcalloc")       != std::string::npos) ||
                     (ptrName.find("__uncontained_array")         != std::string::npos)) {
            toRemove.insert(SI);
          }
        }
        if (LoadInst* LI = dyn_cast<LoadInst>(&I)) {
          // get the pointer from where we are loading
          Value* loadTarget = LI->getPointerOperand();

          // if not a global it cannot be interesting
          if (!isa<GlobalValue>(loadTarget)) continue;

          // get the name of the variable from where we are loading
          std::string ptrName = loadTarget->getName().str();

          if (inPtr && inType && resPtr && resType && (ptrName.find("__container_of_ptr_out") != std::string::npos)) {
            resInstr = LI;
            toRemove.insert(LI);
          }
        }
        // if we found everything, dump and restart searching
        if (inPtr && inType && resPtr && resType && resInstr && ptrDiffFound) {

          // collect all the relevant users of the container_of before starting
          // to instrument
          ValueToInstructions relevantUsers;
          getRelevantUsers(resInstr, relevantUsers);

          ContainerOfToInstrument.emplace_back(resPtr, inType, resType, ptrDiff, resInstr, relevantUsers);

          // reset all
          inPtr    = nullptr;
          inType   = nullptr;
          resPtr   = nullptr;
          resType  = nullptr;
          resInstr = nullptr;
          ptrDiff  = -1;
          ptrDiffFound = false;
        }
      }
    }
  }

  // now instrument the container_of invocations
  for (InterestingContainerOf ContainerOfInstance: ContainerOfToInstrument) {

    bool has_nosanitize = uncontainedNoSanitize(ContainerOfInstance.SourceType, nosanitizeSrcTypes) ||
                           uncontainedNoSanitize(ContainerOfInstance.ResultType, nosanitizeDstTypes);

    if (!has_nosanitize) {

      // compute all the possible offsets where we could find the redzone for
      // the destination type
      // mitigate the cost of finding all offsets with a cache
      static thread_local std::map<Type*, std::set<std::pair<size_t, size_t>>> possibleRedzoneBoundsForType;
      std::set<std::pair<size_t, size_t>> *possibleRedzoneBounds;
      static thread_local std::set<std::pair<size_t, size_t>> _possibleRedzoneBounds;
      if (possibleRedzoneBoundsForType.count(ContainerOfInstance.ResultType)) {
        possibleRedzoneBounds = &possibleRedzoneBoundsForType[ContainerOfInstance.ResultType];
      } else {
        _possibleRedzoneBounds.clear();

        // // SAFETY CHECK: check for no cycles in the type graph
        // checkCycles(ContainerOfInstance.ResultType, typeGraph, /*new_check=*/true);

        computeAllPossibleObjectBounds(ContainerOfInstance.ResultType, DL, typeGraph, _possibleRedzoneBounds);
        possibleRedzoneBounds = &_possibleRedzoneBounds;
        possibleRedzoneBoundsForType[ContainerOfInstance.ResultType] = _possibleRedzoneBounds;
      }

      ++n_instrumented;
      instrumentContainerOf(ContainerOfInstance, *possibleRedzoneBounds);
    } else {
      ++n_skipped;
      ++n_skipped_nosanitize;
    }

    // after having instrumented replace the uses of the volatile load to avoid
    // affecting performance
    Instruction *I = ContainerOfInstance.ResultGate;
    LoadInst* LI = dyn_cast<LoadInst>(I);
    if (!LI || !LI->isVolatile() || !isa<GlobalValue>(LI->getPointerOperand()) ||
        (dyn_cast<GlobalValue>(LI->getPointerOperand())->getName().str().find("__container_of_ptr_out") == std::string::npos)) {
      errs() << *LI << "\n";
      report_fatal_error("[UNCONTAINED] did not find volatile load after container_of instrumentation");
    }

    // recreate the right type as if it was a result of the wrapper
    IRBuilder<> IRB(I);
    Value *NewI = IRB.CreateBitOrPointerCast(ContainerOfInstance.ResultPtr, I->getType());
    I->replaceAllUsesWith(NewI);
  }

  // now remove all the unnecessary volatile instructions
  for(Instruction *I: toRemove) {
    I->eraseFromParent();
  }

  // verify that we did not broke the function.
  // opt calls it automatically, but not LTO
  if (verifyFunction(F, &outs())) {
    report_fatal_error("[UNCONTAINED] internal error: broken function");
  }
  return true;
}

// visit the type Ty and recursively erase all the subtype hashes that Ty contains
// from the set S
static void recursiveErase(Type *Ty, std::set<size_t> &Set) {
  switch (Ty->getTypeID()) {
    // for struct types check all the inner fields
    case llvm::Type::StructTyID:
    {
      auto ST = llvm::cast<llvm::StructType>(Ty);
      for (unsigned i = 0, e = ST->getNumElements(); i != e; ++i) {
        Type* elemT = ST->getElementType(i);
        if (isa<StructType>(elemT)) {
          Set.erase(TypeToNameHash(elemT));
        }

        // recursive visit of the contained type
        recursiveErase(elemT, Set);
      }
      return;
    }

    // for array type check the elements
    case llvm::Type::ArrayTyID:
    {
      auto AT = llvm::cast<llvm::ArrayType>(Ty);
      Type* elemT = AT->getElementType();
      if (isa<StructType>(elemT)) {
        Set.erase(TypeToNameHash(elemT));
      }

      // recursive visit of the contained type
      recursiveErase(elemT, Set);
      return;
    }

    // in all the other cases we terminated the visit
    default:
    {
      return;
    }
  }
}

// visit the type Ty and recursively add all the subtype hashes that Ty contains
// to the set S
static void recursiveAdd(Type *Ty, std::set<size_t> &Set) {
  switch (Ty->getTypeID()) {
    // for struct types check all the inner fields
    case llvm::Type::StructTyID:
    {
      auto ST = llvm::cast<llvm::StructType>(Ty);
      for (unsigned i = 0, e = ST->getNumElements(); i != e; ++i) {
        Type* elemT = ST->getElementType(i);
        if (isa<StructType>(elemT)) {
          Set.insert(TypeToNameHash(elemT));
        }

        // recursive visit of the contained type
        recursiveAdd(elemT, Set);
      }
      return;
    }

    // for array type check the elements
    case llvm::Type::ArrayTyID:
    {
      auto AT = llvm::cast<llvm::ArrayType>(Ty);
      Type* elemT = AT->getElementType();
      if (isa<StructType>(elemT)) {
        Set.insert(TypeToNameHash(elemT));
      }

      // recursive visit of the contained type
      recursiveAdd(elemT, Set);
      return;
    }

    // in all the other cases we terminated the visit
    default:
    {
      return;
    }
  }
}

// visit the type Ty and for each array subtype, recursively add all the types that
// may be contained into the array
// in addition add all the types that may contain variable sized arrays
static void searchArrayAndRecursiveAdd(Type *Ty, std::set<size_t> &Set) {
  // if the type is variable size, we cannot check any type that may be contained
  // into Ty, since we would not know where the right redzone is
  // FIXME: we leverage the right redzone, so we need to know the size of the type
  if (isVariableSize(Ty)) {
    Set.insert(TypeToNameHash(Ty));
    recursiveAdd(Ty, Set);
    return;
  }

  switch (Ty->getTypeID()) {
    // for struct types check all the inner fields
    case llvm::Type::StructTyID:
    {
      auto ST = llvm::cast<llvm::StructType>(Ty);
      for (unsigned i = 0, e = ST->getNumElements(); i != e; ++i) {
        Type* elemT = ST->getElementType(i);

        // recursive visit of each contained type
        searchArrayAndRecursiveAdd(elemT, Set);
      }
      return;
    }

    // for array type check the elements
    case llvm::Type::ArrayTyID:
    {
      auto AT = llvm::cast<llvm::ArrayType>(Ty);
      Type* elemT = AT->getElementType();
      // add the contained type and all the inner ones
      if (isa<StructType>(elemT)) {
        Set.insert(TypeToNameHash(elemT));
      }

      // recursive visit of the contained type
      recursiveAdd(elemT, Set);
      return;
    }

    // in all the other cases we terminated the visit
    default:
    {
      return;
    }
  }
}

// visit the type Ty and recursively add all the subtypes that Ty contains
// to the graph G
// additionally collect the offset range of where the inner object is located
// inside the outer object
static void visitType(DataLayout* DL, Type *Ty, TypeGraph &G) {

  switch (Ty->getTypeID()) {
    // for struct types check all the inner fields
    case llvm::Type::StructTyID:
    {
      auto ST = llvm::cast<llvm::StructType>(Ty);
      // we cannot analyze opaque structs
      if (ST->isOpaque()) return;

      const StructLayout* STL = DL->getStructLayout(ST);
      TypeSize TySize = DL->getTypeAllocSize(Ty);

      for (unsigned i = 0, e = ST->getNumElements(); i != e; ++i) {
        Type* elemT = ST->getElementType(i);
        size_t elemTOff = STL->getElementOffset(i);
        if (isa<StructType>(elemT)) {
          // set elemT contained into Ty
          // the range is indeed fixed, and obtained as the offset of elemT in Ty
          G[TypeToNameHash(elemT)].insert(std::make_pair(Ty, std::make_pair(elemTOff, elemTOff)));
        }

        // recursive visit of the contained type
        visitType(DL, elemT, G);
      }
      return;
    }

    // for array type check the elements
    case llvm::Type::ArrayTyID:
    {
      auto AT = llvm::cast<llvm::ArrayType>(Ty);

      Type* elemT = AT->getElementType();
      size_t elemTSize = DL->getTypeAllocSize(elemT);

      if (isa<StructType>(elemT)) {
        // set elemT contained into Ty
        // the range start is 0, i.e., offset of first cell in Array Ty
        // the range end is  (N-1) * sizeof(elemT)
        //
        // NOTE: missing entries in typeGraph will result in missing RedzoneBounds allowing the chance of FPs
        // if getNumElements() == 0 we cannot statically determine the possible offset range
        if (AT->getNumElements() != 0) {
          G[TypeToNameHash(elemT)].insert(std::make_pair(Ty, std::make_pair(0, elemTSize * (AT->getNumElements() - 1))));
        }
      }

      // recursive visit of the contained type
      visitType(DL, elemT, G);
      return;
    }

    // in all the other cases we terminated the visit
    default:
    {
      return;
    }
  }
}

/// Check if \p G has been created by a trusted compiler pass.
static bool GlobalWasGeneratedByCompiler(GlobalVariable *G) {
  // Do not instrument @llvm.global_ctors, @llvm.used, etc.
  if (G->getName().startswith("llvm."))
    return true;

  // Do not instrument asan globals.
  if (G->getName().startswith("___asan_gen_") ||
      G->getName().startswith("__odr_asan_gen_") ||
      G->getName().startswith("__sancov_gen_"))
    return true;

  // Do not instrument gcov counter arrays.
  if (G->getName() == "__llvm_gcov_ctr")
    return true;

  return false;
}

// this function is taken from llvm/lib/Transforms/Instrumentation/AddressSanitizer.cpp:shouldInstrumentGlobal
// and slightly modified to return if a global has been likely been instrumented by Asan
static bool globalInstrumentedByAsan(GlobalVariable *G) {
  Type *Ty = G->getValueType();
  // FIXME: Metadata should be attched directly to the global directly instead
  // of being added to llvm.asan.globals.
  // if (GlobalsMD.get(G).IsExcluded) return false;
  if (!Ty->isSized()) return false;
  if (!G->hasInitializer()) return false;
  // Only instrument globals of default address spaces
  if (G->getAddressSpace()) return false;
  if (GlobalWasGeneratedByCompiler(G)) return false; // Our own globals.
  // Two problems with thread-locals:
  //   - The address of the main thread's copy can't be computed at link-time.
  //   - Need to poison all copies, not just the main thread's one.
  if (G->isThreadLocal()) return false;
  // Disable the alignment check as it makes the kernel skip instrumenting some
  // variables (e.g., root_task_group)
  // // For now, just ignore this Global if the alignment is large.
  // if (G->getAlignment() > getMinRedzoneSizeForGlobal()) return false;

  if (G->hasSection()) {
    // The kernel uses explicit sections for mostly special global variables
    // that we should not instrument. E.g. the kernel may rely on their layout
    // without redzones, or remove them at link time ("discard.*"), etc.
    StringRef Section = G->getSection();
    if (true /*ComplileKernel*/)
      // some of the sections are worth keeping
      if (Section != ".data..read_mostly" && Section != ".data..ro_after_init")
        return false;


    // Globals from llvm.metadata aren't emitted, do not instrument them.
    if (Section == "llvm.metadata") return false;
    // Do not instrument globals from special LLVM sections.
    if (Section.find("__llvm") != StringRef::npos || Section.find("__LLVM") != StringRef::npos) return false;

    // Do not instrument function pointers to initialization and termination
    // routines: dynamic linker will not properly handle redzones.
    if (Section.startswith(".preinit_array") ||
        Section.startswith(".init_array") ||
        Section.startswith(".fini_array")) {
      return false;
    }
  }

  if (true /*ComplileKernel*/) {
    // Globals that prefixed by "__" are special and cannot be padded with a
    // redzone.
    if (G->getName().startswith("__"))
      return false;
  }

  return true;
}

// check that the global has likely been generated by the ASan pass
// an ASan global looks like a struct with two fields, whose second field is an
// array of chars, i.e., the redzone
// e.g., @glob = internal global { %struct.container_t, [40 x i8] }
static bool looksLikeInstrumentedByAsan(GlobalVariable *G) {
  Type *T = G->getType()->getPointerElementType();
  // is it a struct?
  if (StructType *ST = dyn_cast<StructType>(T)) {
    // has it two fields?
    if (ST->getNumElements() == 2) {
      Type *MaybeRedzoneTy = ST->getElementType(1);
      // is the second field an array?
      if (ArrayType *AT = dyn_cast<ArrayType>(MaybeRedzoneTy)) {
        if (AT->getElementType() == Type::getInt8Ty(G->getContext())) {
          return true;
        }
      }
    }
  }
  return false;
}

static void dumpTypeGraph(TypeGraph& G) {
  dbgs() << "---------- [TYPE STAT] ----------\n";
  std::map<uint32_t, uint32_t> countMap;
  for (auto entry: G) {
    // get how many types are contained into X structs
    countMap[entry.second.size()]++;
  }
  for (auto entry: countMap) {
    dbgs() << entry.first << ": " << entry.second << "\n";
  }
  dbgs() << "---------------------------------\n";
}

// add nesting information to the TypeGraph by parsing the artificially added struct
// __uncontained_struct_nesting_info that has the following template:
// struct {
//   outer_type* outer;
//   inner_type* inner;
//   unsigned long offset;
// } __uncontained_struct_nesting_info_xxx;
//
// describing a structure like:
// outer_type {
//   [...]
//   inner_type s; // at offset `offset`
// }
//
// this is useful to model implictly contained types (e.g., https://elixir.bootlin.com/linux/v5.19-rc2/source/include/crypto/hash.h#L216)
// or to model unions by automatically modifying the source code (e.g., coccinelle or clang AST)
// since unions are not preserved in llvm
// additionally update the nosanitizeTypes
// NOTICE: we assume that there is no further update to nosanitizeTypes after this function
// i.e., OuterT cannot be added later
void addTypeEdgeFromInfo(GlobalVariable *GV, TypeGraph& G, std::set<size_t> &nosanitizeTypes) {
  ConstantStruct *CS = dyn_cast<ConstantStruct>(GV->getInitializer());
  if (!CS || CS->getNumOperands() != 3 || !CS->getOperand(0)->getType()->isPointerTy() ||
      !CS->getOperand(1)->getType()->isPointerTy() || !CS->getOperand(2)->getType()->isIntegerTy()) {
    oprint(*GV->getInitializer());
    errs() << "[UNCONTAINED]: CS: " << CS << "\n";
    errs() << "[UNCONTAINED]: CS->getNumOperands(): " << CS->getNumOperands() << "\n";
    errs() << "[UNCONTAINED]: CS->getOperand(0)->getType()->isPointerTy(): " << CS->getOperand(0)->getType()->isPointerTy() << "\n";
    errs() << "[UNCONTAINED]: CS->getOperand(1)->getType()->isPointerTy(): " << CS->getOperand(1)->getType()->isPointerTy() << "\n";
    errs() << "[UNCONTAINED]: CS->getOperand(2)->getType()->isIntegerTy(): " << CS->getOperand(2)->getType()->isIntegerTy() << "\n";
    report_fatal_error("[UNCONTAINED] internal error: unexpected type for __uncontained_struct_nesting_info variable");
    return;
  }

  // retrieve the nesting information
  Type* OuterT = CS->getOperand(0)->getType()->getPointerElementType();
  Type* InnerT = CS->getOperand(1)->getType()->getPointerElementType();
  size_t offset = dyn_cast<ConstantInt>(CS->getOperand(2))->getZExtValue();

  // add the nesting information
  G[TypeToNameHash(InnerT)].insert(std::make_pair(OuterT, std::make_pair(offset, offset)));

  // if the OuterT is nosanitize, then also all the inner types should now be
  if (nosanitizeTypes.find(TypeToNameHash(OuterT)) != nosanitizeTypes.end()) {
    nosanitizeTypes.insert(TypeToNameHash(InnerT));
    recursiveAdd(InnerT, nosanitizeTypes);
  }
}

bool ContainerOfSanitizer::runImpl(Module &M) {
  if (!init(M))
    return false;
  bool Changed = false;

  DataLayout* DL = new DataLayout(&M);

  // keep the graph of contained types, from a type to the types it is contained into
  TypeGraph typeGraph;

  // keep track of all the nosanitize types
  std::set<size_t> nosanitizeSrcTypes;
  std::set<size_t> nosanitizeDstTypes;

  // for each type, fill the graph of its contained types
  for (StructType* ST: M.getIdentifiedStructTypes()) {
    // initialize the type in typeGraph
    typeGraph[TypeToNameHash(ST)];

    // visit the type
    visitType(DL, ST, typeGraph);
  }

  // print stats on type graph
  dumpTypeGraph(typeGraph);

  // added to nosanitizeDstTypes:
  // 1. all types that are contained in arrays within structs
  // 2. find __uncontained_nosanitize_dst and add those (should there be some adding of subtypes?)
  // 3. all types that are contained in arrays within global variables
  // 4. all types that have complex_alloc/kcalloc/array including all their subtypes

  // for each type set nosanitize for all types and subtypes that are contained in arrays
  for (StructType* ST: M.getIdentifiedStructTypes()) {
    searchArrayAndRecursiveAdd(ST, nosanitizeDstTypes);
  }

  // walk all the global variables to remove all the types that are contained into arrays
  // and to fill the nosanitize lists
  for (GlobalVariable& G: M.getGlobalList()) {
    if (G.getName().contains("__uncontained_nosanitize_src")) {
      nosanitizeSrcTypes.insert(TypeToNameHash(G.getType()->getPointerElementType()->getPointerElementType()));
    } else if (G.getName().contains("__uncontained_nosanitize_dst")) {
      nosanitizeDstTypes.insert(TypeToNameHash(G.getType()->getPointerElementType()->getPointerElementType()));
    } else {
    // kasan will wrap every global object, so take that into consideration
    // and only whitelist the types contained by the inner struct
    if (globalInstrumentedByAsan(&G) && looksLikeInstrumentedByAsan(&G)) {
      // get only the first field
      searchArrayAndRecursiveAdd(G.getType()->getPointerElementType()->getStructElementType(0), nosanitizeDstTypes);
    } else {
      searchArrayAndRecursiveAdd(G.getType()->getPointerElementType(), nosanitizeDstTypes);
    }
  }
  }

  // Collect all types involved in complex allocations and remove them from `uncontainedTypes`.
  // e.g., https://elixir.bootlin.com/linux/v5.17.5/source/fs/proc/proc_sysctl.c#L1335
  //        header = kzalloc(sizeof(struct ctl_table_header) +
  //                         sizeof(struct ctl_node)*nr_entries, GFP_KERNEL);
  //        node = (struct ctl_node *)(header + 1);
  // These allocations create buffers that contain multiple types implicitly
  // without proper structs defining them. For now avoid to check them.
  // TODO: in the future it will make sense to check them, since this is likely
  // error prone
  // Collect also all the types involved in kcalloc allocations, with `nr!=1`
  // We differentiate them from complex allocs, since they may be easier to deal
  // with in the future
  for (Function &F : M) {
    for (auto &BB: F) {
      for(auto &I: BB) {
        if (StoreInst* SI = dyn_cast<StoreInst>(&I)) {
          // get the pointer where we are storing
          Value* storeTarget = SI->getPointerOperand();

          // if not a global it cannot be interesting
          if (!isa<GlobalValue>(storeTarget)) continue;

          // get the name of the variable where we are storing
          std::string ptrName = storeTarget->getName().str();
          if ((ptrName.find("__uncontained_complex_alloc") != std::string::npos) ||
              (ptrName.find("__uncontained_kcalloc")       != std::string::npos) ||
              (ptrName.find("__uncontained_array")         != std::string::npos)) {
            Value* valueStored = SI->getOperand(0);
            // get the type
            Type* subtype = nullptr;
            if(PtrToIntInst* PI = dyn_cast<PtrToIntInst>(valueStored)) {
              subtype = PI->getOperand(0)->getType()->getPointerElementType();
            } else if (PtrToIntOperator* PI = dyn_cast<PtrToIntOperator>(valueStored)) {
              subtype = PI->getOperand(0)->getType()->getPointerElementType();
            } else continue;
            // nosanitize types involved in complex allocations
            nosanitizeDstTypes.insert(TypeToNameHash(subtype));
            // nosanitize all the inner types too
            recursiveAdd(subtype, nosanitizeDstTypes);
          }
        }
      }
    }
  }

  // walk again the global variables to parse the __uncontained_struct_nesting_info,
  // which represent explicit type edges, to update the graph and the nosanitize types
  for (GlobalVariable& G: M.getGlobalList()) {
    if (G.getName().contains("__uncontained_struct_nesting_info")) {
      addTypeEdgeFromInfo(&G, typeGraph, nosanitizeDstTypes);
    }
  }

  oprint("[DEBUG] nosanitize src types: " << nosanitizeSrcTypes.size());
  oprint("[DEBUG] nosanitize dst types: " << nosanitizeDstTypes.size());

  // llvm::dbgs() << M << "\n------------------------------------\n";

  for (Function &F : M)
    Changed |= visitor(F, typeGraph, nosanitizeSrcTypes, nosanitizeDstTypes);

  // llvm::dbgs() << M << "\n";
  printStatistics();

  return Changed;
}

// New PM implementation
struct ContainerOfSanitizerPass : PassInfoMixin<ContainerOfSanitizerPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    bool Changed = ContainerOfSanitizer().runImpl(M);
    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};

// Legacy PM implementation
struct LegacyContainerOfSanitizerPass : public ModulePass {
  static char ID;
  LegacyContainerOfSanitizerPass() : ModulePass(ID) {}
  // Main entry point - the name conveys what unit of IR this is to be run on.
  bool runOnModule(Module &M) override {
    return ContainerOfSanitizer().runImpl(M);
  }
};
} // namespace

//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
llvm::PassPluginLibraryInfo getContainerOfSanitizerPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "ContainerOfSanitizer", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](llvm::ModulePassManager &PM,
                  llvm::PassBuilder::OptimizationLevel Level) {
                PM.addPass(ContainerOfSanitizerPass());
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "sanitize-container-of") {
                    MPM.addPass(ContainerOfSanitizerPass());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getContainerOfSanitizerPassPluginInfo();
}


//-----------------------------------------------------------------------------
// Legacy PM Registration
//-----------------------------------------------------------------------------
char LegacyContainerOfSanitizerPass::ID = 0;

static RegisterPass<LegacyContainerOfSanitizerPass>
X("sanitize-container-of", "ContainerOfSanitizer Pass",
    false, // This pass does modify the CFG => false
    false // This pass is not a pure analysis pass => false
);

static llvm::RegisterStandardPasses RegisterContainerOfSanitizerLTOThinPass(
    llvm::PassManagerBuilder::EP_OptimizerLast,
    [](const llvm::PassManagerBuilder &Builder,
       llvm::legacy::PassManagerBase &PM) { PM.add(new LegacyContainerOfSanitizerPass()); });

static llvm::RegisterStandardPasses RegisterContainerOfSanitizerLTOPass(
    // early opt so we leverage the optimizer to improve our instrumentation
    // and also we deal with simpler code
    llvm::PassManagerBuilder::EP_FullLinkTimeOptimizationEarly,
    [](const llvm::PassManagerBuilder &Builder,
       llvm::legacy::PassManagerBase &PM) { PM.add(new LegacyContainerOfSanitizerPass()); });
