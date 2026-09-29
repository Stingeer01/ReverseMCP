#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include "reverseplugin/analysis/binary_image.hpp"
#include "reverseplugin/disasm/disassembler.hpp"

namespace reverseplugin::analysis {

struct BasicBlock final {
  std::uint32_t rva;
  std::vector<disasm::Instruction> instructions;
};

struct ControlFlowEdge final {
  std::uint32_t from_rva;
  std::uint32_t to_rva;
  std::string type;
};

struct CodeReference final {
  std::uint32_t from_rva;
  std::uint32_t to_rva;
  std::string type;
};

struct FunctionAnalysis final {
  std::uint32_t entry_rva;
  std::vector<BasicBlock> blocks;
  std::vector<ControlFlowEdge> edges;
  std::vector<CodeReference> references;
  std::size_t instruction_count;
  std::size_t decoded_bytes;
  bool truncated;
};

[[nodiscard]] std::expected<FunctionAnalysis, std::string> analyze_function(
    const BinaryImage& image, const disasm::Disassembler& disassembler,
    std::uint32_t entry_rva, std::size_t max_bytes, std::size_t max_blocks);

}  // namespace reverseplugin::analysis
