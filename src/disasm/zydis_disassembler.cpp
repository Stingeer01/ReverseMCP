#include "reverseplugin/disasm/disassembler.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <string_view>

namespace reverseplugin::disasm {
namespace {

std::string register_name(ZydisRegister value) {
  if (value == ZYDIS_REGISTER_NONE) {
    return {};
  }
  const auto* name = ZydisRegisterGetString(value);
  return name == nullptr ? std::string{} : std::string{name};
}

std::string_view visibility_name(ZydisOperandVisibility visibility) noexcept {
  switch (visibility) {
    case ZYDIS_OPERAND_VISIBILITY_EXPLICIT:
      return "explicit";
    case ZYDIS_OPERAND_VISIBILITY_IMPLICIT:
      return "implicit";
    case ZYDIS_OPERAND_VISIBILITY_HIDDEN:
      return "hidden";
    default:
      return "invalid";
  }
}

std::string_view branch_name(ZydisBranchType type) noexcept {
  switch (type) {
    case ZYDIS_BRANCH_TYPE_NONE:
      return "none";
    case ZYDIS_BRANCH_TYPE_SHORT:
      return "short";
    case ZYDIS_BRANCH_TYPE_NEAR:
      return "near";
    case ZYDIS_BRANCH_TYPE_FAR:
      return "far";
    default:
      return "unknown";
  }
}

std::vector<std::string> action_names(ZydisOperandActions actions) {
  std::vector<std::string> result;
  result.reserve(2);
  if ((actions & ZYDIS_OPERAND_ACTION_READ) != 0) {
    result.emplace_back("read");
  }
  if ((actions & ZYDIS_OPERAND_ACTION_CONDREAD) != 0) {
    result.emplace_back("conditional_read");
  }
  if ((actions & ZYDIS_OPERAND_ACTION_WRITE) != 0) {
    result.emplace_back("write");
  }
  if ((actions & ZYDIS_OPERAND_ACTION_CONDWRITE) != 0) {
    result.emplace_back("conditional_write");
  }
  return result;
}

void add_unique(std::vector<std::string>& values, const std::string& value) {
  if (!value.empty() && std::ranges::find(values, value) == values.end()) {
    values.push_back(value);
  }
}

Operand make_operand(const ZydisDecodedInstruction& instruction,
                     const ZydisDecodedOperand& source,
                     std::uint64_t runtime_address) {
  Operand result{.visibility = std::string{visibility_name(source.visibility)},
                 .actions = action_names(source.actions),
                 .size_bits = source.size};
  switch (source.type) {
    case ZYDIS_OPERAND_TYPE_REGISTER:
      result.type = "register";
      result.register_name = register_name(source.reg.value);
      break;
    case ZYDIS_OPERAND_TYPE_MEMORY:
      result.type = "memory";
      result.memory = MemoryOperand{
          .segment = register_name(source.mem.segment),
          .base = register_name(source.mem.base),
          .index = register_name(source.mem.index),
          .scale = source.mem.scale,
          .displacement = source.mem.disp.has_displacement ? source.mem.disp.value : 0};
      {
        ZyanU64 absolute = 0;
        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &source,
                                                  runtime_address, &absolute)))
          result.absolute_address = absolute;
      }
      break;
    case ZYDIS_OPERAND_TYPE_POINTER:
      result.type = "pointer";
      result.absolute_address =
          (static_cast<std::uint64_t>(source.ptr.segment) << 32U) |
          source.ptr.offset;
      break;
    case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
      result.type = "immediate";
      result.immediate = source.imm.is_signed
                             ? source.imm.value.s
                             : static_cast<std::int64_t>(source.imm.value.u);
      ZyanU64 absolute = 0;
      if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &source,
                                                runtime_address, &absolute))) {
        result.absolute_address = absolute;
      }
      break;
    }
    default:
      result.type = "unused";
      break;
  }
  return result;
}

void collect_registers(const ZydisDecodedOperand& operand, Instruction& output) {
  std::array<ZydisRegister, 3> registers{ZYDIS_REGISTER_NONE,
                                         ZYDIS_REGISTER_NONE,
                                         ZYDIS_REGISTER_NONE};
  if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
    registers[0] = operand.reg.value;
  } else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
    registers = {operand.mem.segment, operand.mem.base, operand.mem.index};
  }

  for (const auto reg : registers) {
    const auto name = register_name(reg);
    if ((operand.actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0 ||
        operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
      add_unique(output.registers_read, name);
    }
    if ((operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0 &&
        operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
      add_unique(output.registers_written, name);
    }
  }
}

}  // namespace

std::expected<std::vector<Instruction>, Error> Disassembler::decode(
    std::span<const std::byte> bytes, std::uint64_t address,
    std::size_t max_instructions, Mode mode, Syntax syntax) const {
  ZydisDecoder decoder{};
  const auto machine_mode = mode == Mode::x64 ? ZYDIS_MACHINE_MODE_LONG_64
                                               : ZYDIS_MACHINE_MODE_LEGACY_32;
  const auto stack_width = mode == Mode::x64 ? ZYDIS_STACK_WIDTH_64
                                              : ZYDIS_STACK_WIDTH_32;
  if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, machine_mode, stack_width))) {
    return std::unexpected(Error{"Could not initialize Zydis decoder", 0});
  }

  ZydisFormatter formatter{};
  const auto style = syntax == Syntax::intel ? ZYDIS_FORMATTER_STYLE_INTEL
                                              : ZYDIS_FORMATTER_STYLE_ATT;
  if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, style))) {
    return std::unexpected(Error{"Could not initialize Zydis formatter", 0});
  }

  std::vector<Instruction> result;
  result.reserve(max_instructions);
  std::size_t offset = 0;
  while (offset < bytes.size() && result.size() < max_instructions) {
    ZydisDecodedInstruction decoded{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
    const auto remaining = bytes.subspan(offset);
    const auto status = ZydisDecoderDecodeFull(
        &decoder, remaining.data(), remaining.size(), &decoded, operands.data());
    if (!ZYAN_SUCCESS(status)) {
      return std::unexpected(Error{"Invalid or truncated instruction", offset});
    }

    std::array<char, 256> formatted{};
    if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(
            &formatter, &decoded, operands.data(), decoded.operand_count_visible,
            formatted.data(), formatted.size(), address + offset, nullptr))) {
      return std::unexpected(Error{"Could not format decoded instruction", offset});
    }

    const auto* mnemonic = ZydisMnemonicGetString(decoded.mnemonic);
    const auto* category = ZydisCategoryGetString(decoded.meta.category);
    Instruction output{.address = address + offset,
                       .size = decoded.length,
                       .bytes = std::vector<std::byte>(
                           remaining.begin(), remaining.begin() + decoded.length),
                       .text = formatted.data(),
                       .mnemonic = mnemonic == nullptr ? "unknown" : mnemonic,
                       .category = category == nullptr ? "unknown" : category,
                       .branch_type = std::string{branch_name(decoded.meta.branch_type)}};
    output.operands.reserve(decoded.operand_count);
    for (std::size_t i = 0; i < decoded.operand_count; ++i) {
      output.operands.push_back(make_operand(decoded, operands[i], output.address));
      collect_registers(operands[i], output);
    }
    result.push_back(std::move(output));
    offset += decoded.length;
  }
  return result;
}

}  // namespace reverseplugin::disasm
