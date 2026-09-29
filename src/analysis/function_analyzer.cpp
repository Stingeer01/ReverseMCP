#include "reverseplugin/analysis/function_analyzer.hpp"

#include <algorithm>
#include <deque>
#include <limits>
#include <optional>
#include <string_view>
#include <unordered_set>

namespace reverseplugin::analysis {
namespace {

bool is_return(std::string_view mnemonic) {
  return mnemonic == "ret" || mnemonic == "retf" || mnemonic == "iret" ||
         mnemonic == "iretd" || mnemonic == "iretq";
}

bool is_unconditional_jump(std::string_view mnemonic) {
  return mnemonic == "jmp" || mnemonic == "jmpf";
}

bool is_conditional_jump(std::string_view mnemonic) {
  return (mnemonic.size() > 1 && mnemonic.front() == 'j' && mnemonic != "jmp" &&
          mnemonic != "jmpf") || mnemonic.starts_with("loop");
}

std::optional<std::uint32_t> direct_target(const BinaryImage& image,
                                           const disasm::Instruction& instruction) {
  for (const auto& operand : instruction.operands) {
    if (!operand.absolute_address) continue;
    auto normalized = image.normalize_address(*operand.absolute_address);
    if (normalized) return *normalized;
  }
  return std::nullopt;
}

}  // namespace

std::expected<FunctionAnalysis, std::string> analyze_function(
    const BinaryImage& image, const disasm::Disassembler& disassembler,
    std::uint32_t entry_rva, std::size_t max_bytes, std::size_t max_blocks) {
  if (!image.executable_rva(entry_rva))
    return std::unexpected("Entry RVA is outside executable image sections");
  if (max_bytes == 0 || max_bytes > 1024U * 1024U)
    return std::unexpected("max_bytes must be between 1 and 1048576");
  if (max_blocks == 0 || max_blocks > 4096)
    return std::unexpected("max_blocks must be between 1 and 4096");

  FunctionAnalysis result{.entry_rva = entry_rva};
  std::deque<std::uint32_t> pending{entry_rva};
  std::unordered_set<std::uint32_t> scheduled{entry_rva};
  const auto mode = image.info().architecture == "x86_64"
                        ? disasm::Mode::x64
                        : disasm::Mode::x86;
  while (!pending.empty() && result.blocks.size() < max_blocks &&
         result.decoded_bytes < max_bytes) {
    const auto block_rva = pending.front();
    pending.pop_front();
    BasicBlock block{.rva = block_rva};
    auto cursor = block_rva;
    while (result.decoded_bytes < max_bytes) {
      auto bytes = image.bytes_at(cursor, 15);
      if (!bytes || bytes->empty()) break;
      auto decoded = disassembler.decode(*bytes, image.info().image_base + cursor, 1,
                                         mode, disasm::Syntax::intel);
      if (!decoded || decoded->empty()) break;
      auto instruction = std::move(decoded->front());
      const auto size = instruction.size;
      const auto mnemonic = instruction.mnemonic;
      const auto next = static_cast<std::uint64_t>(cursor) + size;
      const auto target = direct_target(image, instruction);
      block.instructions.push_back(std::move(instruction));
      ++result.instruction_count;
      result.decoded_bytes += size;

      if (mnemonic == "call") {
        if (target) result.references.push_back({cursor, *target, "call"});
      } else if (is_conditional_jump(mnemonic)) {
        if (target) {
          result.edges.push_back({cursor, *target, "taken"});
          if (image.executable_rva(*target) && scheduled.insert(*target).second)
            pending.push_back(*target);
        }
        if (next <= std::numeric_limits<std::uint32_t>::max() && image.contains_rva(next)) {
          const auto fallthrough = static_cast<std::uint32_t>(next);
          result.edges.push_back({cursor, fallthrough, "fallthrough"});
          if (scheduled.insert(fallthrough).second) pending.push_back(fallthrough);
        }
        break;
      } else if (is_unconditional_jump(mnemonic)) {
        if (target) {
          result.edges.push_back({cursor, *target, "jump"});
          if (image.executable_rva(*target) && scheduled.insert(*target).second)
            pending.push_back(*target);
        }
        break;
      } else if (is_return(mnemonic) || mnemonic == "int3" || mnemonic == "ud2") {
        break;
      }
      if (next > std::numeric_limits<std::uint32_t>::max() || !image.contains_rva(next)) break;
      cursor = static_cast<std::uint32_t>(next);
      if (scheduled.contains(cursor) && cursor != block_rva) {
        const auto source = static_cast<std::uint32_t>(
            block.instructions.back().address - image.info().image_base);
        result.edges.push_back({source, cursor, "fallthrough"});
        break;
      }
    }
    if (!block.instructions.empty()) result.blocks.push_back(std::move(block));
  }
  result.truncated = !pending.empty() || result.decoded_bytes >= max_bytes;
  return result;
}

}  // namespace reverseplugin::analysis
