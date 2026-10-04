#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

#include "reverseplugin/analysis/binary_image.hpp"
#include "reverseplugin/analysis/function_analyzer.hpp"
#include "reverseplugin/analysis/semantic_ir.hpp"
#include "reverseplugin/disasm/disassembler.hpp"

namespace reverseplugin::analysis {

struct DecompilerValue final {
  std::string text;
  std::uint16_t size_bits{};
  std::string kind;
};

struct DecompilerStatement final {
  std::uint64_t address{};
  std::string operation;
  std::string text;
  std::string source;
  std::optional<std::uint32_t> target_rva;
  std::string target_name;
  bool indirect{};
  std::vector<std::string> definitions;
  std::vector<std::string> uses;
  std::vector<SsaDefinition> ssa_definitions;
  std::vector<SsaUse> ssa_uses;
  std::vector<MemoryAccess> memory_accesses;
  std::string confidence;
};

struct DecompilerBlock final {
  std::uint32_t rva{};
  std::vector<PhiNode> phi_nodes;
  std::vector<DecompilerStatement> statements;
};

struct Decompilation final {
  std::uint32_t entry_rva{};
  std::string architecture;
  std::string calling_convention;
  std::vector<DecompilerBlock> blocks;
  std::vector<ControlFlowEdge> edges;
  std::vector<CodeReference> references;
  std::vector<RecoveredVariable> stack_variables;
  std::vector<RecoveredParameter> parameters;
  std::vector<ControlRegion> control_regions;
  std::vector<TypeEvidence> type_evidence;
  std::vector<FieldEvidence> field_evidence;
  std::vector<std::string> pseudocode;
  std::vector<std::string> warnings;
  std::size_t instruction_count{};
  std::size_t lifted_instruction_count{};
  std::size_t phi_count{};
  bool ssa_converged{};
  bool truncated{};
};

[[nodiscard]] std::expected<Decompilation, std::string> decompile_function(
    const BinaryImage& image, const disasm::Disassembler& disassembler,
    std::uint32_t entry_rva, std::size_t max_bytes, std::size_t max_blocks);

}  // namespace reverseplugin::analysis
