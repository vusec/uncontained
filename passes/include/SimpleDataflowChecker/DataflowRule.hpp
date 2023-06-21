#ifndef _DataflowRule_
#define _DataflowRule_

#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/ADT/Optional.h"

#include "yaml-cpp/yaml.h"

#include <iostream>
#include <fstream>
#include <map>
#include <mutex>

#include "SimpleDataflowChecker/Helpers.hpp"
#include "SimpleDataflowChecker/DataflowSanitizer.hpp"

#include "TypeUtils/TypeUtils.hpp"

using namespace llvm;

struct DataflowSource {
  const Value *source;
  const Instruction *instruction;

  virtual ~DataflowSource() = default;
  virtual void write(raw_ostream&) const;
  DataflowSource(const Value *source, const Instruction *instruction) : source(source), instruction(instruction) {};
};

struct BackwardsContainedDataflowSource : public DataflowSource {
  Type *type;
  void write(raw_ostream&) const;
  BackwardsContainedDataflowSource(const Value *source, const Instruction *instruction, Type* type) :
    DataflowSource(source, instruction), type(type) {};
};

struct KObjSourcesDataflowSource : public DataflowSource {
  Type *containerType;
  const CallBase *callBase;
  KObjSourcesDataflowSource(const Value *source, const Instruction *instruction, Type* containerType, const CallBase *callBase) :
    DataflowSource(source, instruction), containerType(containerType), callBase(callBase) {};
};

struct KObjDataflowSource : public DataflowSource {
  Type *containerType;
  const CallBase *callBase;
  void write(raw_ostream&) const;
  KObjDataflowSource(const Value *source, const Instruction *instruction, Type* containerType, const CallBase *callBase) : DataflowSource(source, instruction), containerType(containerType), callBase(callBase) {};
};

struct CompareSource {
  bool operator() (DataflowSource *left, DataflowSource *right) {
    KObjDataflowSource *kleft = dynamic_cast<KObjDataflowSource *>(left);
    KObjDataflowSource *kright = dynamic_cast<KObjDataflowSource *>(right);
    if (left->source == right->source &&
        kleft != nullptr && kright != nullptr) {
      return kleft->callBase < kright->callBase;
    }
    return left->source < right->source;
  }
};

struct DataflowSink {
  const Value *sink;
  bool stopFlow;
  std::string message;

  virtual void write(raw_ostream&) const;
  DataflowSink(const Value *sink, bool stopFlow=false, const char* message=""): sink(sink), stopFlow(stopFlow), message(message) {};
};

struct BackwardsContainedDataflowSink : public DataflowSink {
  Type *sinkType;
  void write(raw_ostream&) const;
  BackwardsContainedDataflowSink(const Value *sink, Type *sinkType, bool stopFlow=false, const char* message=""):
    DataflowSink(sink, stopFlow, message), sinkType(sinkType) {};
};

struct ContainerOf {
  Type *inType;
  Type *resType;
  Value *inPtr;
};

std::map<const Instruction *, ContainerOf> buildContainerOfMap(Module &M);
std::map<const Instruction *, ContainerOf> buildListMap(Module &M);

class DataflowRule {
  public:
    std::string name;
    std::set<DataflowSource *, CompareSource> sources;
    std::set<const Value*> sinks;
    std::set<const Value*> ignores;
    bool any_sink=false;

    // TODO: this is orrible, implement the same parsing as we do for sanitizers
    bool cmp_null=false;

    bool sanitize_reachable = false;
    bool sanitize_implicit_flow = false;
    // true if the rule should apply all the sanitizers also to the source of the 
    // dataflow, and not only to the values in the flow
    // e.g.,
    // source: list_entry()
    // sanitizer: list_empty(), list_is_head()
    // if(list_empty()) list_entry()
    // would sanitize only if sanitize_source = true
    //
    // entry = list_entry(); if(list_is_head(entry)) ...
    // would sanitize also with sanitize_source = false
    bool sanitize_source = false;
    // true if sanitize_source==true or if any sanitizer has sanitize_source==true
    bool may_sanitize_source = false;
    bool backward_flow = false;

    std::map<const Instruction *, ContainerOf> container_of_map;

    // The list of sanitizers to apply to this rule
    std::set<std::unique_ptr<DataflowSanitizer>> sanitizers;

    DataflowRule() {
      // empty constructor for subclasses
    }

    DataflowRule(Module& M, YAML::Node& config);

    void dump();
    virtual bool isSanitized(const Value* V, std::set<const Instruction*>& sanitizerInstructions);
    virtual DataflowSink *isSink(Value* V, DataflowSource *source);
    virtual void reportFlow(DataflowSource *dataflowSource, DataflowSink *dataflowSink, std::shared_ptr<Dataflow> Dataflow);
    virtual void dumpReport(std::string& filename, DataflowSource *dataflowSource,
                            DataflowSink *dataflowSink, std::shared_ptr<Dataflow> Dataflow);

    bool isIgnore(Value *V);
    bool isSanitizer(Value* V, const Offset& offset);
    void gatherAllSanitizers(const Function* F, std::set<const Instruction *> &out, bool target_source=false);


  protected:
    void initialize(Module& M, YAML::Node& config);

    virtual std::set<DataflowSource *, CompareSource> getSources(Module& M, std::string&& _source);
    std::set<const Value*> getSinks(Module& M, std::string&& _sink);
    std::set<const Value*> getIgnores(Module &M, std::list<std::string>&& ignores);
    unsigned getID(std::string&& valueName);
    std::set<std::unique_ptr<DataflowSanitizer>> getSanitizers(Module& M, YAML::Node&& config_sanitizers);
    void parseOptions(YAML::Node&& config_options);
};

class BackwardsContainedDataflowRule : public DataflowRule {
  public:
    BackwardsContainedDataflowRule(Module& M, YAML::Node& config) : DataflowRule() {
      backward_flow = true;
      initialize(M, config);
    };

    DataflowSink *isSink(Value* V, DataflowSource *source);

  protected:
    std::set<DataflowSource *, CompareSource> getSources(Module& M, std::string&& _source);
};

class KObjSourcesDataflowRule : public DataflowRule {
  public:
    KObjSourcesDataflowRule(Module& M);

    DataflowSink *isSink(Value* V, DataflowSource *source);

  protected:
    void getSources(Module &M);
};

class KObjDataflowRule : public DataflowRule {
  public:
    KObjDataflowRule(Module& M, YAML::Node& config) : DataflowRule() { initialize(M, config); };

    bool isSanitized(const Value* V, std::set<const Instruction*>& sanitizerInstructions);
    DataflowSink *isSink(Value* V, DataflowSource *source);

  protected:
    std::set<DataflowSource *, CompareSource> getSources(Module& M, std::string&& _source);
};

class ListEntryCorrelationSourcesDataflowRule : public DataflowRule {
  public:
    ListEntryCorrelationSourcesDataflowRule(Module& M);

    DataflowSink *isSink(Value* V, DataflowSource *source);

  protected:
    void getSources(Module &M);
};

class ListEntryCorrelationDataflowRule : public DataflowRule {
  public:
    ListEntryCorrelationDataflowRule(Module& M, YAML::Node& config);

    std::map<const Instruction *, ContainerOf> list_map;
    std::map<const Instruction *, Type *> list_add_map;

    DataflowSink *isSink(Value* V, DataflowSource *source);

  protected:
    std::set<DataflowSource *, CompareSource> getSources(Module& M, std::string&& _source);

    void buildListAddMap(Module& M);
};

#endif	/* _DataflowRule_ */
