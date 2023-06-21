#ifndef _Helpers_
#define _Helpers_

#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DebugInfoMetadata.h"

#include <iostream>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <list>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>

#include "Colors/colors.h"

#define oprint(s) (outs() << s << "\n")
#define eprint(s) (errs() << s << "\n")
#define warning(s) (errs() << "[" YELLOW("WARNING") "] " << s << "\n")

using namespace llvm;

// This is an hack: artificially modify the LLVM ID of conditional branches to recognize them
const unsigned CC_BRANCH_ID = 0x0CC00000uL;

// Return all the calls to the function F
static std::set<const CallBase*> getCallsTo(const Function* F) {
  std::set<const CallBase*> calls;
  static thread_local std::list<const Value*> toVisit;
  static thread_local std::set<const Value*> visited;
  toVisit.clear();
  visited.clear();
  if (F) {
    for(auto user: F->users()) {
      toVisit.push_back(user);
    }
    while (!toVisit.empty()) {
      // Always pop from the front
      const Value* curr = toVisit.front();
      toVisit.pop_front();

      // skip if circular visit
      if (visited.find(curr) != visited.end()) continue;
      visited.insert(curr);

      // If we found a callbase then add it to the result
      if (const CallBase* CB =  dyn_cast<CallBase>(curr)) {
        if (CB->getCalledOperand()->stripPointerCasts() == F)
          calls.insert(CB);
      } else {
        for (auto user : curr->users()) {
          toVisit.push_back(user);
        }
      }
    }
  }
  return calls;
}

static std::string getDebugLocation(const Instruction &I, bool short_print=false, std::string *inlinedShort = nullptr) {
  if (DILocation *Loc = I.getDebugLoc()) {
      unsigned Line = Loc->getLine();
      StringRef File = Loc->getFilename();
      DILocation *InlineLoc = Loc->getInlinedAt();
      if (!InlineLoc)
        return File.str() + ":" + std::to_string(Line);
      else {
        unsigned InLine = InlineLoc->getLine();
        StringRef InFile = InlineLoc->getFilename();
        if (short_print && inlinedShort) {
          *inlinedShort = InFile.str() + ":" + std::to_string(InLine);
          return File.str() + ":" + std::to_string(Line);
        }
        return File.str() + ":" + std::to_string(Line) +
          ", inlined at: " + InFile.str() + ":" + std::to_string(InLine);
      }
  } else {
    // No location metadata available
    return "";
  }
}

static std::string getDebugLocation(const Function& F) {
  if (DISubprogram *SP = F.getSubprogram()) {
      unsigned Line = SP->getLine();
      StringRef File = SP->getFilename();
        return File.str() + ":" + std::to_string(Line);
  } else {
    // No location metadata available
    return "";
  }
}

static std::string instructionToLocation(const Instruction* I, bool colors=true) {
  if (I) {
    if (colors)
      return PBOLD(I->getFunction()->getName().str() + "()") + " in " + getDebugLocation(*I);
    else
      return I->getFunction()->getName().str() + "()" + " in " + getDebugLocation(*I);
  }
  return "";
}

static std::string functionToLocation(const Function* F, bool colors=true) {
  if (F) {
    if (colors)
      return PBOLD(F->getName().str() + "()") + " in " + getDebugLocation(*F);
    else
      return F->getName().str() + "()" + " in " + getDebugLocation(*F);
  }
  return "";
}

static std::string instructionToYAMLLocation(const Instruction* I) {
  if (I) {
    std::string inlined;
    std::string debugLoc = getDebugLocation(*I, true, &inlined);
    if (!inlined.empty())
      return "{func: \"" + I->getFunction()->getName().str() + "()\", file: \"" + debugLoc + "\", inlined_at: \"" + inlined + "\"}";
    return "{func: \"" + I->getFunction()->getName().str() + "()\", file: \"" + debugLoc + "\"}";
  }
  return "{}";
}

static std::string functionToYAMLLocation(const Function* F) {
  if (F) {
    return "{func: \"" + F->getName().str() + "()\", file: \"" + getDebugLocation(*F) + "\"}";
  }
  return "{}";
}

// Print the instruction location to yaml
static std::string valueToYAMLLocation(const Value* V) {
  if(const Instruction *I = dyn_cast<Instruction>(V))
    return instructionToYAMLLocation(I);
  else if (const Function *F = dyn_cast<Function>(V))
    return functionToYAMLLocation(F);
  else if (const Argument *A = dyn_cast<Argument>(V))
    return functionToYAMLLocation(A->getParent());
  std::string str;
  llvm::raw_string_ostream rso(str);
  rso << "{raw: \"";
  V->print(rso);
  rso << "}\"";
  return str;
}

// Return the ID of LLVM values differentiating branches and conditional branches
static unsigned getValueID(const Value* V) {
  if (const BranchInst *BI = dyn_cast<BranchInst>(V)) {
    if (BI->isConditional()) return V->getValueID() + CC_BRANCH_ID;
  }
  return V->getValueID();
}

static void appendToFile(const char* filename, std::string& s) {
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

static bool searchOperandInInstruction(const Value* V, const long match_operand) {
  if (const Instruction* I = dyn_cast<Instruction>(V)) {
    for (Value* operand: I->operands()) {
      if (ConstantInt *C = dyn_cast<ConstantInt>(operand)) {
        if (C->getSExtValue() == match_operand) return true;
      } else if (isa<ConstantPointerNull>(operand)) {
        // represent the NULL pointer with 0
        if (match_operand == 0) return true;
      }
    }
  }
  return false;
}

#endif	/* _Helpers_ */
