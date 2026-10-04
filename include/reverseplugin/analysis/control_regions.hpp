#pragma once

#include <cstdint>
#include <vector>

#include "reverseplugin/analysis/function_analyzer.hpp"
#include "reverseplugin/analysis/semantic_ir.hpp"

namespace reverseplugin::analysis {

struct DecompilerBlock;

[[nodiscard]] std::vector<ControlRegion> recover_control_regions(
    const std::vector<DecompilerBlock>& blocks,
    const std::vector<ControlFlowEdge>& edges, std::uint64_t image_base,
    std::uint32_t entry_rva);

}  // namespace reverseplugin::analysis
