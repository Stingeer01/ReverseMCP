#include "reverseplugin/analysis/type_inference.hpp"

#include <algorithm>
#include <ranges>
#include <string_view>
#include <unordered_map>

#include "reverseplugin/analysis/decompiler.hpp"
#include "reverseplugin/analysis/register_model.hpp"

namespace reverseplugin::analysis {
namespace {

std::string key(std::string_view storage, std::string_view kind) {
  std::string result;
  result.reserve(storage.size() + kind.size() + 1);
  result.append(storage);
  result.push_back('|');
  result.append(kind);
  return result;
}

void add(std::vector<TypeEvidence>& result,
         std::unordered_map<std::string, std::size_t>& indices,
         std::string storage, std::string kind, std::uint16_t bits,
         std::string signedness, std::string confidence,
         std::uint64_t address) {
  const auto identity = key(storage, kind);
  const auto [found, inserted] = indices.try_emplace(identity, result.size());
  if (inserted)
    result.push_back({.storage = std::move(storage),
                      .kind = std::move(kind),
                      .size_bits = bits,
                      .signedness = std::move(signedness),
                      .confidence = std::move(confidence)});
  auto& evidence = result[found->second];
  evidence.size_bits = std::max(evidence.size_bits, bits);
  if (evidence.signedness != signedness && evidence.signedness != "unknown")
    evidence.signedness = "unknown";
  if (std::ranges::find(evidence.evidence, address) == evidence.evidence.end())
    evidence.evidence.push_back(address);
}

std::vector<std::string> explicit_registers(const disasm::Instruction& instruction) {
  std::vector<std::string> result;
  for (const auto& operand : instruction.operands) {
    if (operand.visibility == "explicit" && operand.type == "register")
      result.push_back(operand.register_name);
  }
  return result;
}

}  // namespace

std::vector<TypeEvidence> infer_types(
    const FunctionAnalysis& function,
    const std::vector<RecoveredVariable>& stack_variables, bool x64) {
  std::vector<TypeEvidence> result;
  std::unordered_map<std::string, std::size_t> indices;
  for (const auto& block : function.blocks) {
    std::vector<std::string> comparison_registers;
    for (const auto& instruction : block.instructions) {
      for (const auto& operand : instruction.operands) {
        if (!operand.memory) continue;
        for (const auto& value : {operand.memory->base, operand.memory->index}) {
          if (value.empty()) continue;
          if (auto reg = resolve_register(value, x64))
            add(result, indices, reg->canonical, "pointer", reg->canonical_bits,
                "unsigned", "inferred", instruction.address);
        }
      }

      const auto registers = explicit_registers(instruction);
      if (instruction.mnemonic == "cmp" || instruction.mnemonic == "test")
        comparison_registers = registers;
      const bool signed_branch = instruction.mnemonic == "jg" ||
                                 instruction.mnemonic == "jge" ||
                                 instruction.mnemonic == "jl" ||
                                 instruction.mnemonic == "jle";
      const bool unsigned_branch = instruction.mnemonic == "ja" ||
                                   instruction.mnemonic == "jae" ||
                                   instruction.mnemonic == "jb" ||
                                   instruction.mnemonic == "jbe";
      if (signed_branch || unsigned_branch) {
        for (const auto& value : comparison_registers) {
          if (auto reg = resolve_register(value, x64))
            add(result, indices, reg->canonical, "integer", reg->size_bits,
                signed_branch ? "signed" : "unsigned", "inferred",
                instruction.address);
        }
      }
      if (instruction.mnemonic != "cmp" && instruction.mnemonic != "test" &&
          !instruction.mnemonic.starts_with("j") &&
          !instruction.mnemonic.starts_with("set") &&
          !instruction.mnemonic.starts_with("cmov") &&
          (std::ranges::find(instruction.registers_written, "rflags") !=
               instruction.registers_written.end() ||
           std::ranges::find(instruction.registers_written, "eflags") !=
               instruction.registers_written.end() ||
           std::ranges::find(instruction.registers_written, "flags") !=
               instruction.registers_written.end()))
        comparison_registers.clear();
      if (instruction.mnemonic.starts_with("set") && !registers.empty()) {
        if (auto reg = resolve_register(registers.front(), x64))
          add(result, indices, reg->canonical, "boolean", 1, "unsigned",
              "inferred", instruction.address);
      }

      const bool signed_operation =
          instruction.mnemonic == "idiv" || instruction.mnemonic == "imul" ||
          instruction.mnemonic == "sar" || instruction.mnemonic == "movsx" ||
          instruction.mnemonic == "movsxd";
      const bool unsigned_operation =
          instruction.mnemonic == "div" || instruction.mnemonic == "mul" ||
          instruction.mnemonic == "shr" || instruction.mnemonic == "movzx";
      if (!signed_operation && !unsigned_operation) continue;
      for (const auto& value : registers) {
        if (auto reg = resolve_register(value, x64))
          add(result, indices, reg->canonical, "integer", reg->size_bits,
              signed_operation ? "signed" : "unsigned", "inferred",
              instruction.address);
      }
    }
  }

  for (const auto& variable : stack_variables) {
    const auto kind = variable.storage == "rbp" || variable.storage == "ebp"
                          ? "stack_object"
                          : "stack_slot";
    for (const auto address : variable.references)
      add(result, indices, variable.name, kind, variable.size_bits, "unknown",
          "inferred", address);
  }
  return result;
}

std::vector<FieldEvidence> infer_fields(const FunctionAnalysis& function,
                                        bool x64) {
  std::vector<FieldEvidence> result;
  std::unordered_map<std::string, std::size_t> indices;
  for (const auto& block : function.blocks) {
    for (const auto& instruction : block.instructions) {
      for (const auto& operand : instruction.operands) {
        if (!operand.memory || operand.visibility != "explicit") continue;
        const auto& memory = *operand.memory;
        if (memory.base.empty() || memory.base == "rip" || memory.base == "eip" ||
            memory.base == "rsp" || memory.base == "esp" || memory.base == "rbp" ||
            memory.base == "ebp")
          continue;
        const auto base = resolve_register(memory.base, x64);
        if (!base) continue;
        const auto index = memory.index.empty() ? std::optional<RegisterSlice>{}
                                                 : resolve_register(memory.index, x64);
        const auto identity = std::format("{}|{}|{}|{}", base->canonical,
                                          index ? index->canonical : "",
                                          memory.scale, memory.displacement);
        const auto [found, inserted] = indices.try_emplace(identity, result.size());
        if (inserted)
          result.push_back({.base_storage = base->canonical,
                            .index_storage = index ? index->canonical : "",
                            .offset = memory.displacement,
                            .scale = memory.scale,
                            .size_bits = operand.size_bits,
                            .kind = index ? "array_element" : "field"});
        auto& field = result[found->second];
        field.size_bits = std::max(field.size_bits, operand.size_bits);
        field.read = field.read ||
                     std::ranges::find(operand.actions, "read") !=
                         operand.actions.end() ||
                     std::ranges::find(operand.actions, "conditional_read") !=
                         operand.actions.end();
        field.written = field.written ||
                        std::ranges::find(operand.actions, "write") !=
                            operand.actions.end() ||
                        std::ranges::find(operand.actions, "conditional_write") !=
                            operand.actions.end();
        field.evidence.push_back(instruction.address);
      }
    }
  }
  return result;
}

}  // namespace reverseplugin::analysis
