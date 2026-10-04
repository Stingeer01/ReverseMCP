#include "reverseplugin/analysis/function_analyzer.hpp"

#include <algorithm>
#include <deque>
#include <limits>
#include <optional>
#include <ranges>
#include <string_view>
#include <unordered_map>
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

std::optional<std::uint32_t> direct_target(
    const BinaryImage& image, const disasm::Instruction& instruction) {
  for (const auto& operand : instruction.operands) {
    if (!operand.absolute_address) continue;
    if (auto normalized = image.normalize_address(*operand.absolute_address))
      return *normalized;
  }
  return std::nullopt;
}

struct Successor final {
  std::uint32_t rva{};
  std::string type;
};

struct Node final {
  disasm::Instruction instruction;
  std::vector<Successor> successors;
};

bool valid_next(const BinaryImage& image, std::uint64_t value) {
  return value <= std::numeric_limits<std::uint32_t>::max() &&
         image.executable_rva(value);
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
  const auto mode = image.info().architecture == "x86_64"
                        ? disasm::Mode::x64
                        : disasm::Mode::x86;
  std::unordered_map<std::uint32_t, Node> nodes;
  const auto* runtime_function = image.runtime_function_at(entry_rva);
  const auto within_function = [&](std::uint32_t rva) {
    return runtime_function == nullptr ||
           (rva >= runtime_function->begin_rva &&
            rva < runtime_function->end_rva);
  };
  std::unordered_set<std::uint32_t> scheduled{entry_rva};
  std::unordered_set<std::uint32_t> block_starts{entry_rva};
  std::deque<std::uint32_t> pending{entry_rva};
  bool budget_truncated = false;

  auto schedule = [&](std::uint32_t rva, bool block_start) {
    if (!image.executable_rva(rva) || !within_function(rva)) return;
    if (block_start && !block_starts.contains(rva)) {
      if (block_starts.size() >= max_blocks) {
        budget_truncated = true;
        return;
      }
      block_starts.insert(rva);
    }
    if (scheduled.insert(rva).second) pending.push_back(rva);
  };

  while (!pending.empty() && result.decoded_bytes < max_bytes) {
    const auto rva = pending.front();
    pending.pop_front();
    if (nodes.contains(rva)) continue;
    auto bytes = image.bytes_at(rva, 15);
    if (!bytes || bytes->empty()) continue;
    auto decoded = disassembler.decode(*bytes, image.info().image_base + rva, 1,
                                       mode, disasm::Syntax::intel);
    if (!decoded || decoded->empty()) continue;
    auto instruction = std::move(decoded->front());
    if (result.decoded_bytes + instruction.size > max_bytes) {
      budget_truncated = true;
      break;
    }

    const auto mnemonic = instruction.mnemonic;
    const auto target = direct_target(image, instruction);
    const auto next_value = static_cast<std::uint64_t>(rva) + instruction.size;
    const auto next = valid_next(image, next_value) &&
                              within_function(static_cast<std::uint32_t>(next_value))
                          ? std::optional{static_cast<std::uint32_t>(next_value)}
                          : std::nullopt;
    Node node{.instruction = std::move(instruction)};
    if (mnemonic == "call") {
      if (target) result.references.push_back({rva, *target, "call"});
      if (next) {
        node.successors.push_back({*next, "flow"});
        schedule(*next, false);
      }
    } else if (is_conditional_jump(mnemonic)) {
      if (target) {
        if (within_function(*target)) {
          node.successors.push_back({*target, "taken"});
          schedule(*target, true);
        } else {
          result.references.push_back({rva, *target, "external_branch"});
        }
      }
      if (next) {
        node.successors.push_back({*next, "fallthrough"});
        schedule(*next, true);
      }
    } else if (is_unconditional_jump(mnemonic)) {
      if (target) {
        if (within_function(*target)) {
          node.successors.push_back({*target, "jump"});
          schedule(*target, true);
        } else {
          result.references.push_back({rva, *target, "tail_call"});
        }
      }
    } else if (!is_return(mnemonic) && mnemonic != "int3" && mnemonic != "ud2") {
      if (next) {
        node.successors.push_back({*next, "flow"});
        schedule(*next, false);
      }
    }
    result.decoded_bytes += node.instruction.size;
    ++result.instruction_count;
    nodes.emplace(rva, std::move(node));
  }

  std::unordered_map<std::uint32_t, std::size_t> predecessor_count;
  for (const auto& [_, node] : nodes)
    for (const auto& successor : node.successors)
      ++predecessor_count[successor.rva];
  for (const auto& [rva, count] : predecessor_count)
    if (count > 1) block_starts.insert(rva);

  std::vector<std::uint32_t> ordered_starts{block_starts.begin(), block_starts.end()};
  std::ranges::sort(ordered_starts);
  if (const auto entry = std::ranges::find(ordered_starts, entry_rva);
      entry != ordered_starts.end())
    std::rotate(ordered_starts.begin(), entry, std::next(entry));

  std::unordered_set<std::uint32_t> assigned;
  result.blocks.reserve(ordered_starts.size());
  for (const auto start : ordered_starts) {
    if (!nodes.contains(start) || assigned.contains(start)) continue;
    BasicBlock block{.rva = start};
    auto cursor = start;
    while (true) {
      const auto found = nodes.find(cursor);
      if (found == nodes.end() || !assigned.insert(cursor).second) break;
      block.instructions.push_back(found->second.instruction);
      const auto& successors = found->second.successors;
      if (successors.size() != 1) {
        for (const auto& successor : successors)
          result.edges.push_back({cursor, successor.rva, successor.type});
        break;
      }
      const auto& successor = successors.front();
      if (successor.type != "flow" ||
          (successor.rva != start && block_starts.contains(successor.rva))) {
        result.edges.push_back(
            {cursor, successor.rva,
             successor.type == "flow" ? "fallthrough" : successor.type});
        break;
      }
      cursor = successor.rva;
    }
    if (!block.instructions.empty()) result.blocks.push_back(std::move(block));
  }

  result.truncated = budget_truncated || !pending.empty();
  return result;
}

}  // namespace reverseplugin::analysis
