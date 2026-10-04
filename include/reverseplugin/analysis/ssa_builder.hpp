#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "reverseplugin/analysis/function_analyzer.hpp"

namespace reverseplugin::analysis {

struct DecompilerBlock;

struct SsaResult final {
  bool converged{};
  std::size_t phi_count{};
  std::size_t definition_count{};
};

[[nodiscard]] SsaResult build_ssa(std::vector<DecompilerBlock>& blocks,
                                  const std::vector<ControlFlowEdge>& edges,
                                  std::uint64_t image_base, bool x64);

}  // namespace reverseplugin::analysis
