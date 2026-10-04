#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "reverseplugin/analysis/function_analyzer.hpp"
#include "reverseplugin/analysis/semantic_ir.hpp"

namespace reverseplugin::analysis {

struct StackAlias final {
  std::uint64_t address{};
  std::string raw_alias;
  std::string normalized_alias;
};

struct StackAnalysis final {
  std::vector<RecoveredVariable> variables;
  std::vector<StackAlias> aliases;
};

[[nodiscard]] StackAnalysis analyze_stack(const FunctionAnalysis& function,
                                          bool x64);

}  // namespace reverseplugin::analysis
