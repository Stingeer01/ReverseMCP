#include "reverseplugin/analysis/stack_analysis.hpp"

#include <algorithm>
#include <format>
#include <optional>
#include <ranges>
#include <unordered_map>

namespace reverseplugin::analysis {
namespace {

struct FrameState final {
  std::optional<std::int64_t> sp;
  std::optional<std::int64_t> bp;
  bool operator==(const FrameState&) const = default;
};

struct Graph final {
  std::vector<std::vector<std::size_t>> predecessors;
};

Graph graph(const FunctionAnalysis& function) {
  Graph result{.predecessors =
                   std::vector<std::vector<std::size_t>>(function.blocks.size())};
  std::unordered_map<std::uint32_t, std::size_t> owners;
  std::unordered_map<std::uint32_t, std::size_t> starts;
  for (std::size_t i = 0; i < function.blocks.size(); ++i) {
    starts.emplace(function.blocks[i].rva, i);
    for (const auto& instruction : function.blocks[i].instructions)
      owners.emplace(static_cast<std::uint32_t>(
                         instruction.address -
                         function.blocks[i].instructions.front().address +
                         function.blocks[i].rva),
                     i);
  }
  for (const auto& edge : function.edges) {
    const auto from = owners.find(edge.from_rva);
    const auto to = starts.find(edge.to_rva);
    if (from == owners.end() || to == starts.end()) continue;
    auto& predecessors = result.predecessors[to->second];
    if (std::ranges::find(predecessors, from->second) == predecessors.end())
      predecessors.push_back(from->second);
  }
  return result;
}

std::vector<const disasm::Operand*> explicit_operands(
    const disasm::Instruction& instruction) {
  std::vector<const disasm::Operand*> result;
  for (const auto& operand : instruction.operands)
    if (operand.visibility == "explicit") result.push_back(&operand);
  return result;
}

bool stack_register(const disasm::Operand& operand, bool x64) {
  return operand.type == "register" &&
         operand.register_name == (x64 ? "rsp" : "esp");
}

bool frame_register(const disasm::Operand& operand, bool x64) {
  return operand.type == "register" &&
         operand.register_name == (x64 ? "rbp" : "ebp");
}

std::optional<std::int64_t> immediate(const disasm::Operand& operand) {
  return operand.type == "immediate" ? operand.immediate : std::nullopt;
}

void apply(const disasm::Instruction& instruction, FrameState& state, bool x64) {
  const auto operands = explicit_operands(instruction);
  const auto width = static_cast<std::int64_t>(x64 ? 8 : 4);
  if (instruction.mnemonic == "push") {
    if (state.sp) *state.sp -= width;
    return;
  }
  if (instruction.mnemonic == "pop") {
    if (state.sp) *state.sp += width;
    return;
  }
  if (instruction.mnemonic == "leave") {
    state.sp = state.bp ? std::optional{*state.bp + width} : std::nullopt;
    state.bp.reset();
    return;
  }
  if (operands.size() < 2) return;
  if (instruction.mnemonic == "mov" && frame_register(*operands[0], x64) &&
      stack_register(*operands[1], x64)) {
    state.bp = state.sp;
    return;
  }
  if (instruction.mnemonic == "mov" && stack_register(*operands[0], x64) &&
      frame_register(*operands[1], x64)) {
    state.sp = state.bp;
    return;
  }
  if (stack_register(*operands[0], x64)) {
    if ((instruction.mnemonic == "sub" || instruction.mnemonic == "add") &&
        immediate(*operands[1])) {
      if (state.sp)
        *state.sp += instruction.mnemonic == "sub" ? -*immediate(*operands[1])
                                                     : *immediate(*operands[1]);
      return;
    }
    if (instruction.mnemonic == "lea" && operands[1]->memory &&
        operands[1]->memory->base == (x64 ? "rsp" : "esp") &&
        operands[1]->memory->index.empty()) {
      if (state.sp) *state.sp += operands[1]->memory->displacement;
      return;
    }
    state.sp.reset();
  }
  if (frame_register(*operands[0], x64)) state.bp.reset();
}

FrameState transfer(const BasicBlock& block, FrameState state, bool x64) {
  for (const auto& instruction : block.instructions) apply(instruction, state, x64);
  return state;
}

std::optional<std::int64_t> merge_value(
    const std::vector<std::optional<std::int64_t>>& values) {
  if (values.empty()) return std::nullopt;
  const auto first = values.front();
  return std::ranges::all_of(values, [&](const auto& value) { return value == first; })
             ? first
             : std::nullopt;
}

FrameState merge(std::size_t block, const Graph& cfg,
                 const std::vector<FrameState>& outgoing) {
  std::vector<std::optional<std::int64_t>> sp;
  std::vector<std::optional<std::int64_t>> bp;
  if (block == 0) {
    sp.emplace_back(0);
    bp.emplace_back(std::nullopt);
  }
  for (const auto predecessor : cfg.predecessors[block]) {
    sp.push_back(outgoing[predecessor].sp);
    bp.push_back(outgoing[predecessor].bp);
  }
  return {.sp = merge_value(sp), .bp = merge_value(bp)};
}

std::string variable_name(std::int64_t offset) {
  const auto magnitude = offset < 0
                             ? static_cast<std::uint64_t>(-(offset + 1)) + 1
                             : static_cast<std::uint64_t>(offset);
  return std::format("stack_{}_{:x}", offset < 0 ? "minus" : "plus", magnitude);
}

std::string role(std::int64_t offset, bool x64) {
  if (offset < 0) return "local";
  if (offset == 0) return "return_address";
  if (x64 && offset <= 0x20) return "home_slot";
  if (offset >= (x64 ? 0x28 : 4)) return "stack_argument";
  return "stack_slot";
}

}  // namespace

StackAnalysis analyze_stack(const FunctionAnalysis& function, bool x64) {
  const auto cfg = graph(function);
  std::vector<FrameState> incoming(function.blocks.size());
  std::vector<FrameState> outgoing(function.blocks.size());
  bool changed = true;
  std::size_t iterations = 0;
  while (changed && iterations++ < std::max<std::size_t>(16, function.blocks.size() * 4)) {
    changed = false;
    for (std::size_t i = 0; i < function.blocks.size(); ++i) {
      const auto next_in = merge(i, cfg, outgoing);
      const auto next_out = transfer(function.blocks[i], next_in, x64);
      if (next_in != incoming[i] || next_out != outgoing[i]) changed = true;
      incoming[i] = next_in;
      outgoing[i] = next_out;
    }
  }

  StackAnalysis result;
  std::unordered_map<std::string, std::size_t> indices;
  for (std::size_t i = 0; i < function.blocks.size(); ++i) {
    auto state = incoming[i];
    for (const auto& instruction : function.blocks[i].instructions) {
      if (instruction.mnemonic != "lea") {
        for (const auto& operand : instruction.operands) {
          if (operand.visibility != "explicit" || !operand.memory) continue;
          const auto& memory = *operand.memory;
          const bool sp = memory.base == (x64 ? "rsp" : "esp");
          const bool bp = memory.base == (x64 ? "rbp" : "ebp");
          if (!sp && !bp) continue;
          const auto base = sp ? state.sp : state.bp;
          const auto normalized = base ? std::optional{*base + memory.displacement}
                                       : std::nullopt;
          const auto name = normalized
                                ? variable_name(*normalized)
                                : std::format("{}_relative_{:+x}", memory.base,
                                              memory.displacement);
          result.aliases.push_back(
              {.address = instruction.address,
               .raw_alias = std::format("stack:{}{:+x}", memory.base,
                                        memory.displacement),
               .normalized_alias = "stack:" + name});
          const auto [found, inserted] =
              indices.try_emplace(name, result.variables.size());
          if (inserted)
            result.variables.push_back(
                {.name = name,
                 .storage = memory.base,
                 .role = normalized ? role(*normalized, x64) : "unknown",
                 .offset = memory.displacement,
                 .entry_sp_offset = normalized,
                 .size_bits = operand.size_bits,
                 .confidence = normalized ? "inferred" : "partial"});
          auto& variable = result.variables[found->second];
          variable.size_bits = std::max(variable.size_bits, operand.size_bits);
          variable.references.push_back(instruction.address);
        }
      }
      apply(instruction, state, x64);
    }
  }
  return result;
}

}  // namespace reverseplugin::analysis
