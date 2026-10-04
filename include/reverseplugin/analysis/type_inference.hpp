#pragma once

#include <vector>

#include "reverseplugin/analysis/function_analyzer.hpp"
#include "reverseplugin/analysis/semantic_ir.hpp"

namespace reverseplugin::analysis {

[[nodiscard]] std::vector<TypeEvidence> infer_types(
    const FunctionAnalysis& function,
    const std::vector<RecoveredVariable>& stack_variables, bool x64);
[[nodiscard]] std::vector<FieldEvidence> infer_fields(
    const FunctionAnalysis& function, bool x64);

}  // namespace reverseplugin::analysis
