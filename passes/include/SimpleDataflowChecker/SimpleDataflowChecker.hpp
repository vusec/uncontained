#ifndef _DataflowChecker_
#define _DataflowChecker_

#include "llvm/IR/Module.h"

#include "yaml-cpp/yaml.h"

#include <iostream>
#include <fstream>
#include <map>
#include <mutex>

#include "SimpleDataflowChecker/DataflowRule.hpp"

using namespace llvm;

// Allow using cl arguments also in other files;
extern cl::opt<bool> PrintInstructions;
extern cl::opt<bool> CompactPrint;

class SimpleDataflowChecker {
  bool init(Module &M);

  void addStatistics(DataflowSink *sink);
  void printStatistics(void);

  void parseRule(Module& M, YAML::Node& config_rule, std::set<DataflowRule*>& rules);
  void checkRule(DataflowRule& rule, Module& M);
  bool isSourceSanitized(const Value* source, DataflowRule& rule);
  std::set<const Instruction *> getSanitizers(const Value* source, DataflowRule& rule);

  std::map<std::string, uint64_t> stats_map;
  std::mutex map_mutex;

  public:
  bool runImpl(Module &M);

  void searchFlows(DataflowSource *source, DataflowRule& rule, std::set<const Instruction *> &sanitizerInstructions);
};

#endif	/* _DataflowChecker_ */
