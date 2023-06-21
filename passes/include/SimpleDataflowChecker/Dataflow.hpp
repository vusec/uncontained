#ifndef _Dataflow_
#define _Dataflow_

#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"

#include <iostream>
#include <fstream>
#include <map>
#include <mutex>

using namespace llvm;

struct Offset {
  const bool is_valid;
  const long offset;

  Offset(const long _offset, const bool _is_valid) :
    offset(_offset), is_valid(_is_valid) {}

  Offset apply(Value *op) const {
    // if the offset is not valid, return another invalid one
    if (!is_valid) return Offset(0, false);

    // Apply the GEP operation
    if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(op)) {
      Module* Mod = GEP->getModule();
      LLVMContext* Ctx = &Mod->getContext();
      static thread_local DataLayout* DL = new DataLayout(Mod);
      APInt GEPOffset = APInt(sizeof(unsigned long)*8, 0);

      // track the offset only if constant GEP
      if(GEP->accumulateConstantOffset(*DL, GEPOffset)) {
        return Offset(offset + GEPOffset.getSExtValue(), true);
        // otherwise invalidate the offset
      } else {
        return Offset(0, false);
      }
      // If it is a load, then we loose the offset of the loaded value
    } else if (LoadInst *LI = dyn_cast<LoadInst>(op)) {
      return Offset(0, false);
    }
    return Offset(offset, true);
  }
};


// Linked list to represent dataflows
struct Dataflow {
  const std::shared_ptr<Dataflow> next;
  const Value* flow;
  const Offset offset;

  Dataflow(const Value* _flow,
      const Offset& _offset,
      const std::shared_ptr<Dataflow>& _next) :
    next(_next), flow(_flow), offset(_offset) {}

  // return a new dataflow passing trough the user
  static std::shared_ptr<Dataflow> pass_through(std::shared_ptr<Dataflow> &dataflow, User* user) {
    // Compute the new offset at the instruction execution
    Offset new_offset = dataflow->offset.apply(user);

    return std::make_shared<Dataflow>(user, new_offset, dataflow);
  }
};

struct DataflowBackwards : public Dataflow {
  DataflowBackwards(const Value* _flow,
      const Offset& _offset,
      const std::shared_ptr<Dataflow>& _next) : Dataflow(_flow, _offset, _next) {}

  // return a new dataflow passing trough the user
  static std::shared_ptr<DataflowBackwards> pass_through(std::shared_ptr<Dataflow> &dataflow, const Value* val) {
    // Compute the new offset at the instruction execution
    // Offset new_offset = dataflow->offset.apply(user);
    Offset new_offset = dataflow->offset;

    return std::make_shared<DataflowBackwards>(val, new_offset, dataflow);
  }
};

#endif	/* _Dataflow_ */
