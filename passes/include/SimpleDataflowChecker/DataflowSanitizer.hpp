#ifndef _DataflowSanitizer_
#define _DataflowSanitizer_

#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"

#include "SimpleDataflowChecker/Helpers.hpp"
#include "SimpleDataflowChecker/Dataflow.hpp"

using namespace llvm;

class DataflowSanitizer {
  public:
    // true if the sanitizer applies also to the source of the dataflow, and not
    // only to the values in the flow
    // e.g.,
    // source: list_entry()
    // sanitizer: list_empty(), list_is_head()
    // if(list_empty()) list_entry()
    // would sanitize only if sanitize_source = true
    //
    // entry = list_entry(); if(list_is_head(entry)) ...
    // would sanitize also with sanitize_source = false
    bool sanitize_source = false;

    virtual bool match(const Value* V, const Offset&  offset) = 0;
    virtual void print(raw_ostream&) const = 0;
    virtual ~DataflowSanitizer() {};
    friend raw_ostream& operator<<(raw_ostream& os, const DataflowSanitizer& d);
};

// Sanitizer: specific instruction that operate on a particular offset
// e.g, loading ptr->type will probably check the type
class DataflowInstructionSanitizer : public DataflowSanitizer {
  public:
    const long match_offset;
    // wether or not the offset should be checked for this sanitizer
    const long use_match_offset;
    const unsigned match_id;

    const long match_operand;
    // wether or not the operands should be checked for this sanitizer
    const long use_match_operand;

    DataflowInstructionSanitizer(long offset, bool use_offset, long operand, bool use_operand, unsigned id) :
      match_offset(offset), use_match_offset(use_offset), 
      match_operand(operand), use_match_operand(use_operand), match_id(id) {};

    bool match(const Value* _V, const Offset& offset) {
      // bail out if the wrong type of instruction
      if (getValueID(_V) != match_id)
        return false;

      // check the offset
      bool offset_matches = true;
      if (use_match_offset)
        offset_matches = offset.is_valid && offset.offset == match_offset;

      // check the operand
      bool operand_matches = true;
      if (use_match_operand)
        operand_matches = searchOperandInInstruction(_V, match_operand);
      
      return offset_matches && operand_matches;
    }

    void print(raw_ostream& os) const
    {
      os << "DataflowInstructionSanitizer: {id: " << match_id;
      if (use_match_offset)
        os << ", offset: " << match_offset;
      if (use_match_operand)
        os << ", operand: " << match_operand;
      os << "}";
    }
};

class DataflowFunctionCallSanitizer : public DataflowSanitizer {
  public:
    Function* match_function;

    DataflowFunctionCallSanitizer(Module &M, std::string& function_name) {
      match_function = M.getFunction(function_name);
      if (!match_function)
        warning("No function found for sanitizer: " + function_name);
    };

    bool match(const Value* V, const Offset& _offset) {
      if (const CallBase *CB = dyn_cast<CallBase>(V)) {
        // Only if they represent direct calls to functions
        if (CB->isInlineAsm()) return false;
        Function *Called = dyn_cast<Function>(CB->getCalledOperand()->stripPointerCasts());
        if (!Called || Called->isDeclaration() || Called->isIntrinsic()) return false;

        return Called == match_function;
      }
      return false;
    }

    void print(raw_ostream& os) const
    {
      if (match_function)
        os << "DataflowFunctionCallSanitizer: " << match_function->getName().str();
      else
        os << "DataflowFunctionCallSanitizer: NULL";  }
};

#endif	/* _DataflowSanitizer_ */
