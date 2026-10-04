#include "reverseplugin/analysis/decompiler.hpp"

#include "reverseplugin/analysis/control_regions.hpp"
#include "reverseplugin/analysis/register_model.hpp"
#include "reverseplugin/analysis/ssa_builder.hpp"
#include "reverseplugin/analysis/stack_analysis.hpp"
#include "reverseplugin/analysis/type_inference.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <format>
#include <limits>
#include <optional>
#include <ranges>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace reverseplugin::analysis {
namespace {

constexpr std::array<std::string_view, 8> x64_argument_registers{
    "rcx", "rdx", "r8", "r9", "zmm0", "zmm1", "zmm2", "zmm3"};

struct LiftContext final {
  const BinaryImage& image;
  bool x64{};
  std::unordered_map<std::string, std::string> values;
  std::optional<std::pair<std::string, std::string>> comparison;
  std::optional<std::string> test;
};

std::string hex(std::uint64_t value) { return std::format("0x{:x}", value); }

std::string signed_offset(std::int64_t value) {
  if (value == 0) return {};
  const auto magnitude = value < 0
                             ? static_cast<std::uint64_t>(-(value + 1)) + 1
                             : static_cast<std::uint64_t>(value);
  return std::format(" {} {}", value < 0 ? "-" : "+", hex(magnitude));
}

bool has_action(const disasm::Operand& operand, std::string_view action) {
  return std::ranges::find(operand.actions, action) != operand.actions.end();
}

std::vector<const disasm::Operand*> explicit_operands(
    const disasm::Instruction& instruction) {
  std::vector<const disasm::Operand*> result;
  result.reserve(instruction.operands.size());
  for (const auto& operand : instruction.operands) {
    if (operand.visibility == "explicit") result.push_back(&operand);
  }
  return result;
}

std::string register_value(std::string_view name, const LiftContext& ctx) {
  const auto resolved = resolve_register(name, ctx.x64);
  const auto storage = resolved ? resolved->canonical : std::string{name};
  const auto found = ctx.values.find(storage);
  if (found == ctx.values.end()) return std::string{name};
  if (found->second.size() > 192) return std::string{name};
  if (!resolved || (resolved->offset_bits == 0 &&
                    resolved->size_bits == resolved->canonical_bits))
    return found->second;
  return std::format("extract<{}, {}>({})", resolved->offset_bits,
                     resolved->size_bits, found->second);
}

std::string memory_address(const disasm::Operand& operand, const LiftContext& ctx) {
  if (!operand.memory) return "unknown_address";
  const auto& memory = *operand.memory;
  if (memory.base == "rip" && operand.absolute_address)
    return hex(*operand.absolute_address);

  std::string result;
  if (memory.segment == "fs" || memory.segment == "gs")
    result += memory.segment + ":";
  if (!memory.base.empty()) result += register_value(memory.base, ctx);
  if (!memory.index.empty()) {
    if (!result.empty() && result.back() != ':') result += " + ";
    result += register_value(memory.index, ctx);
    if (memory.scale > 1) result += std::format(" * {}", memory.scale);
  }
  if (result.empty()) result = "0";
  result += signed_offset(memory.displacement);
  return result;
}

std::string integer_type(std::uint16_t bits) {
  switch (bits) {
    case 8: return "uint8_t";
    case 16: return "uint16_t";
    case 32: return "uint32_t";
    case 64: return "uint64_t";
    case 128: return "__m128i";
    case 256: return "__m256i";
    case 512: return "__m512i";
    default: return std::format("uint{}_t", bits);
  }
}

std::string operand_value(const disasm::Operand& operand, const LiftContext& ctx,
                          bool address_only = false) {
  if (operand.type == "register") return register_value(operand.register_name, ctx);
  if (operand.type == "immediate") {
    if (!operand.immediate) return "unknown_immediate";
    return *operand.immediate < 0
               ? std::format("-{}", hex(static_cast<std::uint64_t>(
                                            -(*operand.immediate + 1)) + 1))
               : hex(static_cast<std::uint64_t>(*operand.immediate));
  }
  if (operand.type == "memory") {
    auto address = memory_address(operand, ctx);
    if (address_only) return address;
    return std::format("*({}*)({})", integer_type(operand.size_bits), address);
  }
  if (operand.absolute_address) return hex(*operand.absolute_address);
  return "unknown";
}

std::string destination(const disasm::Operand& operand, const LiftContext& ctx) {
  if (operand.type == "register") return operand.register_name;
  return operand_value(operand, ctx);
}

std::optional<std::uint32_t> target_rva(const BinaryImage& image,
                                        const disasm::Instruction& instruction) {
  for (const auto* operand : explicit_operands(instruction)) {
    if (!operand->absolute_address) continue;
    if (auto rva = image.normalize_address(*operand->absolute_address)) return *rva;
  }
  return std::nullopt;
}

std::string label(std::uint32_t rva) { return std::format("loc_{:x}", rva); }

std::string callee_name(const BinaryImage& image, std::uint32_t rva) {
  const auto symbol = image.symbol_at(rva);
  if (symbol.empty()) return std::format("sub_{:x}", rva);
  std::string result;
  result.reserve(symbol.size());
  for (const auto value : symbol) {
    const auto byte = static_cast<unsigned char>(value);
    result.push_back(std::isalnum(byte) != 0 || value == '_' ? value : '_');
  }
  if (result.empty() || std::isdigit(static_cast<unsigned char>(result.front())) != 0)
    result.insert(result.begin(), '_');
  return result;
}

std::string condition(std::string_view mnemonic, const LiftContext& ctx) {
  const auto operands = ctx.comparison.value_or(std::pair{"lhs", "rhs"});
  const auto& [lhs, rhs] = operands;
  if (mnemonic == "je" || mnemonic == "jz") return lhs + " == " + rhs;
  if (mnemonic == "jne" || mnemonic == "jnz") return lhs + " != " + rhs;
  if (mnemonic == "ja") return std::format("as_unsigned({}) > as_unsigned({})", lhs, rhs);
  if (mnemonic == "jae" || mnemonic == "jnb")
    return std::format("as_unsigned({}) >= as_unsigned({})", lhs, rhs);
  if (mnemonic == "jb" || mnemonic == "jc")
    return std::format("as_unsigned({}) < as_unsigned({})", lhs, rhs);
  if (mnemonic == "jbe")
    return std::format("as_unsigned({}) <= as_unsigned({})", lhs, rhs);
  if (mnemonic == "jg") return std::format("as_signed({}) > as_signed({})", lhs, rhs);
  if (mnemonic == "jge")
    return std::format("as_signed({}) >= as_signed({})", lhs, rhs);
  if (mnemonic == "jl") return std::format("as_signed({}) < as_signed({})", lhs, rhs);
  if (mnemonic == "jle")
    return std::format("as_signed({}) <= as_signed({})", lhs, rhs);
  if (mnemonic == "js") return "sign_flag";
  if (mnemonic == "jns") return "!sign_flag";
  if (mnemonic == "jo") return "overflow_flag";
  if (mnemonic == "jno") return "!overflow_flag";
  if (mnemonic == "jp" || mnemonic == "jpe") return "parity_flag";
  if (mnemonic == "jnp" || mnemonic == "jpo") return "!parity_flag";
  if (mnemonic == "jcxz") return "cx == 0";
  if (mnemonic == "jecxz") return "ecx == 0";
  if (mnemonic == "jrcxz") return "rcx == 0";
  if (mnemonic.starts_with("loop")) return "--counter != 0";
  if (ctx.test) return *ctx.test;
  return std::format("condition_{}", mnemonic);
}

std::vector<std::string> uses(const disasm::Instruction& instruction) {
  std::vector<std::string> result = instruction.registers_read;
  for (const auto& operand : instruction.operands) {
    if (operand.type == "memory" && operand.memory) {
      if (!operand.memory->base.empty() &&
          std::ranges::find(result, operand.memory->base) == result.end())
        result.push_back(operand.memory->base);
      if (!operand.memory->index.empty() &&
          std::ranges::find(result, operand.memory->index) == result.end())
        result.push_back(operand.memory->index);
    }
  }
  return result;
}

std::vector<MemoryAccess> memory_accesses(
    const disasm::Instruction& instruction) {
  std::vector<MemoryAccess> result;
  for (const auto& operand : instruction.operands) {
    if (!operand.memory) continue;
    const bool reads = has_action(operand, "read") ||
                       has_action(operand, "conditional_read");
    const bool writes = has_action(operand, "write") ||
                        has_action(operand, "conditional_write");
    if (!reads && !writes) continue;
    const auto& memory = *operand.memory;
    std::string address;
    if (!memory.base.empty()) address += memory.base;
    if (!memory.index.empty()) {
      if (!address.empty()) address += "+";
      address += memory.index;
      if (memory.scale > 1) address += std::format("*{}", memory.scale);
    }
    if (address.empty()) address = "0";
    address += signed_offset(memory.displacement);
    std::string alias_set = "memory:unknown";
    if ((memory.base == "rip" || memory.base == "eip") &&
        operand.absolute_address)
      alias_set = "global:" + hex(*operand.absolute_address);
    else if (memory.base == "rsp" || memory.base == "esp" ||
             memory.base == "rbp" || memory.base == "ebp")
      alias_set = std::format("stack:{}{:+x}", memory.base,
                              memory.displacement);
    else if (memory.segment == "fs" || memory.segment == "gs")
      alias_set = std::format("tls:{}{:+x}", memory.segment,
                              memory.displacement);
    else if (memory.base.empty() && operand.absolute_address)
      alias_set = "global:" + hex(*operand.absolute_address);
    result.push_back(
        {.action = reads && writes ? "read_write" : reads ? "read" : "write",
         .address = std::move(address),
         .alias_set = std::move(alias_set),
         .size_bits = operand.size_bits});
  }
  return result;
}

DecompilerStatement statement(const disasm::Instruction& instruction,
                              std::string operation, std::string text,
                              std::string confidence = "exact") {
  return {.address = instruction.address,
          .operation = std::move(operation),
          .text = std::move(text),
          .source = instruction.text,
          .definitions = instruction.registers_written,
          .uses = uses(instruction),
          .memory_accesses = memory_accesses(instruction),
          .confidence = std::move(confidence)};
}

void assign_register(const disasm::Operand& target, std::string value,
                     LiftContext& ctx) {
  if (target.type != "register") return;
  const auto resolved = resolve_register(target.register_name, ctx.x64);
  if (!resolved) {
    ctx.values[target.register_name] = std::move(value);
    return;
  }
  if (resolved->write == RegisterWrite::full) {
    ctx.values[resolved->canonical] = std::move(value);
    return;
  }
  if (resolved->write == RegisterWrite::zero_extend) {
    ctx.values[resolved->canonical] = std::format(
        "zero_extend<{}>({})", resolved->canonical_bits, value);
    return;
  }
  const auto found = ctx.values.find(resolved->canonical);
  const auto previous = found == ctx.values.end() ? resolved->canonical
                                                   : found->second;
  ctx.values[resolved->canonical] =
      std::format("insert_bits<{}, {}>({}, {})", resolved->offset_bits,
                  resolved->size_bits, previous, value);
}

void invalidate_register(std::string_view value, LiftContext& ctx) {
  if (const auto resolved = resolve_register(value, ctx.x64))
    ctx.values.erase(resolved->canonical);
  else
    ctx.values.erase(std::string{value});
}

DecompilerStatement lift(const disasm::Instruction& instruction, LiftContext& ctx,
                         bool x64) {
  const auto operands = explicit_operands(instruction);
  const auto& mnemonic = instruction.mnemonic;
  if (mnemonic != "cmp" && mnemonic != "test" &&
      (std::ranges::find(instruction.registers_written, "flags") !=
           instruction.registers_written.end() ||
       std::ranges::find(instruction.registers_written, "eflags") !=
           instruction.registers_written.end() ||
       std::ranges::find(instruction.registers_written, "rflags") !=
           instruction.registers_written.end())) {
    ctx.comparison.reset();
    ctx.test.reset();
  }
  auto binary_assignment = [&](std::string_view symbol) {
    if (operands.size() < 2)
      return statement(instruction, "intrinsic", instruction.text, "unmodeled");
    const auto lhs = destination(*operands[0], ctx);
    const auto old = operand_value(*operands[0], ctx);
    const auto rhs = operand_value(*operands[1], ctx);
    auto value = std::format("({} {} {})", old, symbol, rhs);
    assign_register(*operands[0], value, ctx);
    if (mnemonic == "sub") {
      ctx.comparison = std::pair{old, rhs};
      ctx.test.reset();
    }
    return statement(instruction, "assign", std::format("{} = {};", lhs, value));
  };

  if ((mnemonic == "mov" || mnemonic == "movabs") && operands.size() >= 2) {
    const auto lhs = destination(*operands[0], ctx);
    auto rhs = operand_value(*operands[1], ctx);
    assign_register(*operands[0], rhs, ctx);
    return statement(instruction, "assign", std::format("{} = {};", lhs, rhs));
  }
  if ((mnemonic == "movzx" || mnemonic == "movsx" || mnemonic == "movsxd") &&
      operands.size() >= 2) {
    const auto lhs = destination(*operands[0], ctx);
    const auto source = operand_value(*operands[1], ctx);
    const auto cast = mnemonic == "movzx" ? "zero_extend" : "sign_extend";
    auto rhs = std::format("{}<{}>({})", cast, operands[0]->size_bits, source);
    assign_register(*operands[0], rhs, ctx);
    return statement(instruction, "cast", std::format("{} = {};", lhs, rhs));
  }
  if ((mnemonic.starts_with("mov") || mnemonic.starts_with("vmov")) &&
      operands.size() >= 2) {
    const auto lhs = destination(*operands[0], ctx);
    auto rhs = operand_value(*operands[1], ctx);
    assign_register(*operands[0], rhs, ctx);
    return statement(instruction, "assign", std::format("{} = {};", lhs, rhs));
  }
  if (mnemonic == "lea" && operands.size() >= 2) {
    const auto lhs = destination(*operands[0], ctx);
    auto rhs = operand_value(*operands[1], ctx, true);
    assign_register(*operands[0], rhs, ctx);
    return statement(instruction, "address", std::format("{} = {};", lhs, rhs));
  }
  if (mnemonic == "add") return binary_assignment("+");
  if (mnemonic == "sub") return binary_assignment("-");
  if (mnemonic == "and") return binary_assignment("&");
  if (mnemonic == "or") return binary_assignment("|");
  if (mnemonic == "xor") return binary_assignment("^");
  if (mnemonic == "adc" && operands.size() >= 2) {
    const auto lhs = destination(*operands[0], ctx);
    const auto old = operand_value(*operands[0], ctx);
    const auto rhs = operand_value(*operands[1], ctx);
    auto value = std::format("({} + {} + carry_flag)", old, rhs);
    assign_register(*operands[0], value, ctx);
    return statement(instruction, "assign", std::format("{} = {};", lhs, value));
  }
  if (mnemonic == "sbb" && operands.size() >= 2) {
    const auto lhs = destination(*operands[0], ctx);
    const auto old = operand_value(*operands[0], ctx);
    const auto rhs = operand_value(*operands[1], ctx);
    auto value = std::format("({} - {} - carry_flag)", old, rhs);
    assign_register(*operands[0], value, ctx);
    return statement(instruction, "assign", std::format("{} = {};", lhs, value));
  }
  if (mnemonic == "shl" || mnemonic == "sal") return binary_assignment("<<");
  if (mnemonic == "shr") return binary_assignment(">>");
  if (mnemonic == "sar" && operands.size() >= 2) {
    const auto lhs = destination(*operands[0], ctx);
    const auto old = operand_value(*operands[0], ctx);
    const auto rhs = operand_value(*operands[1], ctx);
    auto value = std::format("arithmetic_shift_right({}, {})", old, rhs);
    assign_register(*operands[0], value, ctx);
    return statement(instruction, "assign", std::format("{} = {};", lhs, value));
  }
  if ((mnemonic == "rol" || mnemonic == "ror") && operands.size() >= 2) {
    const auto lhs = destination(*operands[0], ctx);
    const auto old = operand_value(*operands[0], ctx);
    const auto rhs = operand_value(*operands[1], ctx);
    auto value = std::format("rotate_{}({}, {})",
                             mnemonic == "rol" ? "left" : "right", old, rhs);
    assign_register(*operands[0], value, ctx);
    return statement(instruction, "assign", std::format("{} = {};", lhs, value));
  }
  if (mnemonic == "imul" && operands.size() >= 3) {
    const auto lhs = destination(*operands[0], ctx);
    const auto first = operand_value(*operands[1], ctx);
    const auto second = operand_value(*operands[2], ctx);
    auto value = std::format("({} * {})", first, second);
    assign_register(*operands[0], value, ctx);
    return statement(instruction, "assign", std::format("{} = {};", lhs, value));
  }
  if (mnemonic == "imul" && operands.size() == 2) return binary_assignment("*");
  if ((mnemonic == "mul" || mnemonic == "imul") && operands.size() == 1)
    return statement(instruction, "wide_multiply",
                     std::format("wide_{}multiply({});",
                                 mnemonic == "imul" ? "signed_" : "unsigned_",
                                 operand_value(*operands[0], ctx)),
                     "exact");
  if ((mnemonic == "div" || mnemonic == "idiv") && operands.size() == 1)
    return statement(instruction, "divide",
                     std::format("{}_divide_{}bit({});",
                                 mnemonic == "idiv" ? "signed" : "unsigned",
                                 operands[0]->size_bits,
                                 operand_value(*operands[0], ctx)),
                     "exact");
  if ((mnemonic == "inc" || mnemonic == "dec" || mnemonic == "neg" ||
       mnemonic == "not") && !operands.empty()) {
    const auto lhs = destination(*operands[0], ctx);
    const auto old = operand_value(*operands[0], ctx);
    const auto value = mnemonic == "inc"   ? std::format("({} + 1)", old)
                       : mnemonic == "dec" ? std::format("({} - 1)", old)
                       : mnemonic == "neg" ? std::format("-({})", old)
                                             : std::format("~({})", old);
    assign_register(*operands[0], value, ctx);
    return statement(instruction, "assign", std::format("{} = {};", lhs, value));
  }
  if (mnemonic == "cmp" && operands.size() >= 2) {
    auto lhs = operand_value(*operands[0], ctx);
    auto rhs = operand_value(*operands[1], ctx);
    ctx.comparison = std::pair{lhs, rhs};
    ctx.test.reset();
    return statement(instruction, "compare", std::format("flags = compare({}, {});", lhs, rhs));
  }
  if (mnemonic == "test" && operands.size() >= 2) {
    auto lhs = operand_value(*operands[0], ctx);
    auto rhs = operand_value(*operands[1], ctx);
    ctx.test = std::format("({} & {}) != 0", lhs, rhs);
    ctx.comparison = std::pair{std::format("({} & {})", lhs, rhs), "0"};
    return statement(instruction, "compare", std::format("flags = test({}, {});", lhs, rhs));
  }
  if (mnemonic == "call") {
    std::string callee = "indirect_call";
    const auto target = target_rva(ctx.image, instruction);
    if (target)
      callee = callee_name(ctx.image, *target);
    else if (!operands.empty())
      callee = operand_value(*operands.front(), ctx);
    if (x64) {
      for (const auto reg : {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"})
        invalidate_register(reg, ctx);
    } else {
      for (const auto reg : {"eax", "ecx", "edx"}) invalidate_register(reg, ctx);
    }
    for (const auto reg : {"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"})
      invalidate_register(reg, ctx);
    ctx.comparison.reset();
    ctx.test.reset();
    auto result = statement(instruction, "call", std::format("{}();", callee),
                            target ? "exact" : "inferred");
    result.target_rva = target;
    result.target_name = callee;
    result.indirect = !target;
    return result;
  }
  if (mnemonic.starts_with("set") && mnemonic.size() > 3 && !operands.empty()) {
    const auto lhs = destination(*operands.front(), ctx);
    auto value = std::format("({}) ? 1 : 0",
                             condition("j" + mnemonic.substr(3), ctx));
    assign_register(*operands.front(), value, ctx);
    return statement(instruction, "select", std::format("{} = {};", lhs, value),
                     ctx.comparison || ctx.test ? "inferred" : "partial");
  }
  if (mnemonic.starts_with("cmov") && mnemonic.size() > 4 && operands.size() >= 2) {
    const auto lhs = destination(*operands[0], ctx);
    const auto old = operand_value(*operands[0], ctx);
    const auto rhs = operand_value(*operands[1], ctx);
    auto value = std::format("({}) ? {} : {}",
                             condition("j" + mnemonic.substr(4), ctx), rhs, old);
    assign_register(*operands[0], value, ctx);
    return statement(instruction, "select", std::format("{} = {};", lhs, value),
                     ctx.comparison || ctx.test ? "inferred" : "partial");
  }
  if (mnemonic == "xchg" && operands.size() >= 2) {
    const auto lhs = destination(*operands[0], ctx);
    const auto rhs = destination(*operands[1], ctx);
    const auto lhs_value = operand_value(*operands[0], ctx);
    const auto rhs_value = operand_value(*operands[1], ctx);
    assign_register(*operands[0], rhs_value, ctx);
    assign_register(*operands[1], lhs_value, ctx);
    return statement(instruction, "exchange",
                     std::format("swap({}, {});", lhs, rhs));
  }
  if (mnemonic == "bswap" && !operands.empty()) {
    const auto lhs = destination(*operands[0], ctx);
    const auto old = operand_value(*operands[0], ctx);
    auto value = std::format("byte_swap({})", old);
    assign_register(*operands[0], value, ctx);
    return statement(instruction, "assign", std::format("{} = {};", lhs, value));
  }
  if (mnemonic == "xadd" && operands.size() >= 2) {
    const auto lhs = destination(*operands[0], ctx);
    const auto rhs = destination(*operands[1], ctx);
    const auto lhs_value = operand_value(*operands[0], ctx);
    const auto rhs_value = operand_value(*operands[1], ctx);
    assign_register(*operands[0], std::format("({} + {})", lhs_value, rhs_value), ctx);
    assign_register(*operands[1], lhs_value, ctx);
    return statement(instruction, "exchange_add",
                     std::format("{{{}, {}}} = xadd({}, {});", lhs, rhs,
                                 lhs_value, rhs_value));
  }
  if (mnemonic == "jmp" || mnemonic == "jmpf") {
    if (const auto target = target_rva(ctx.image, instruction)) {
      auto result = statement(instruction, "jump",
                              std::format("goto {};", label(*target)));
      result.target_rva = target;
      result.target_name = callee_name(ctx.image, *target);
      return result;
    }
    const auto target = operands.empty() ? "unknown" : operand_value(*operands.front(), ctx);
    auto result = statement(instruction, "indirect_jump",
                            std::format("goto *{};", target), "inferred");
    result.target_name = target;
    result.indirect = true;
    return result;
  }
  if (((mnemonic.size() > 1 && mnemonic.front() == 'j') || mnemonic.starts_with("loop")) &&
      mnemonic != "jmp" && mnemonic != "jmpf") {
    const auto target = target_rva(ctx.image, instruction);
    auto result = statement(
        instruction, "branch",
        std::format("if ({}) goto {};", condition(mnemonic, ctx),
                    target ? label(*target) : "unknown_target"),
        ctx.comparison || ctx.test ? "inferred" : "partial");
    result.target_rva = target;
    result.indirect = !target;
    return result;
  }
  if (mnemonic == "ret" || mnemonic == "retf")
    return statement(instruction, "return",
                     "return /* ABI result may be in ax/eax/rax or xmm0 */;",
                     "partial");
  if (mnemonic == "push" && !operands.empty()) {
    const auto value = operand_value(*operands.front(), ctx);
    return statement(instruction, "stack_write",
                     std::format("sp -= {}; *(uintptr_t*)sp = {};", x64 ? 8 : 4, value));
  }
  if (mnemonic == "pop" && !operands.empty()) {
    const auto lhs = destination(*operands.front(), ctx);
    invalidate_register(lhs, ctx);
    return statement(instruction, "stack_read",
                     std::format("{} = *(uintptr_t*)sp; sp += {};", lhs, x64 ? 8 : 4));
  }
  if (mnemonic == "leave") {
    invalidate_register(x64 ? "rsp" : "esp", ctx);
    invalidate_register(x64 ? "rbp" : "ebp", ctx);
    return statement(instruction, "frame_teardown",
                     std::format("sp = bp; bp = *(uintptr_t*)sp; sp += {};",
                                 x64 ? 8 : 4));
  }
  if (mnemonic == "nop" || mnemonic.starts_with("endbr"))
    return statement(instruction, "nop", "/* no operation */");
  if (mnemonic == "syscall" || mnemonic == "sysenter")
    return statement(instruction, "system_call",
                     std::format("{}();", mnemonic), "exact");
  if (mnemonic == "ud2")
    return statement(instruction, "trap", "unreachable_trap();", "exact");
  if ((mnemonic.starts_with("movs") && operands.empty()) || mnemonic.starts_with("stos") ||
      mnemonic.starts_with("lods") || mnemonic.starts_with("scas") ||
      mnemonic.starts_with("cmps"))
    return statement(instruction, "string_operation",
                     std::format("x86_{}();", mnemonic), "partial");

  for (const auto& reg : instruction.registers_written)
    invalidate_register(reg, ctx);
  return statement(instruction, "intrinsic",
                   std::format("__asm_{}(\"{}\");", mnemonic, instruction.text),
                   "unmodeled");
}

void collect_parameters(const std::vector<DecompilerBlock>& blocks,
                        const std::vector<RecoveredVariable>& stack_variables,
                        bool x64, std::vector<RecoveredParameter>& output) {
  if (x64) {
    for (const auto storage : x64_argument_registers) {
      RecoveredParameter parameter{
          .name = std::format("arg_{}", storage.starts_with("zmm")
                                                ? "xmm" + std::string{storage.substr(3)}
                                                : std::string{storage}),
          .storage = storage.starts_with("zmm")
                         ? "xmm" + std::string{storage.substr(3)}
                         : std::string{storage},
          .size_bits = static_cast<std::uint16_t>(storage.starts_with("zmm") ? 128 : 64)};
      const auto entry = std::format("{}_entry", storage);
      for (const auto& block : blocks) {
        for (const auto& statement : block.statements) {
          const auto found = std::ranges::find_if(statement.ssa_uses, [&](const auto& use) {
            return use.storage == storage && use.value == entry &&
                   use.role == "instruction";
          });
          if (found != statement.ssa_uses.end())
            parameter.evidence.push_back(statement.address);
        }
      }
      if (!parameter.evidence.empty()) output.push_back(std::move(parameter));
    }
  }
  for (const auto& variable : stack_variables) {
    if (variable.role != "stack_argument") continue;
    output.push_back({.name = "arg_" + variable.name,
                      .storage = variable.name,
                      .size_bits = variable.size_bits,
                      .evidence = variable.references});
  }
}

}  // namespace

std::expected<Decompilation, std::string> decompile_function(
    const BinaryImage& image, const disasm::Disassembler& disassembler,
    std::uint32_t entry_rva, std::size_t max_bytes, std::size_t max_blocks) {
  auto analyzed = analyze_function(image, disassembler, entry_rva, max_bytes, max_blocks);
  if (!analyzed) return std::unexpected(std::move(analyzed.error()));

  const bool x64 = image.info().architecture == "x86_64";
  Decompilation result{.entry_rva = entry_rva,
                       .architecture = image.info().architecture,
                       .calling_convention = x64 ? "microsoft_x64" : "x86_unknown",
                       .edges = analyzed->edges,
                       .references = analyzed->references,
                       .instruction_count = analyzed->instruction_count,
                       .truncated = analyzed->truncated};
  result.blocks.reserve(analyzed->blocks.size());
  std::unordered_map<std::uint32_t, const CodeReference*> references_by_source;
  for (const auto& reference : analyzed->references)
    references_by_source.emplace(reference.from_rva, &reference);
  for (const auto& block : analyzed->blocks) {
    DecompilerBlock lifted{.rva = block.rva};
    lifted.statements.reserve(block.instructions.size());
    LiftContext ctx{.image = image, .x64 = x64};
    for (const auto& instruction : block.instructions) {
      auto current = lift(instruction, ctx, x64);
      const auto instruction_rva = static_cast<std::uint32_t>(
          instruction.address - image.info().image_base);
      if (const auto found = references_by_source.find(instruction_rva);
          found != references_by_source.end() &&
          found->second->type == "tail_call") {
        current.operation = "tail_call";
        current.text = std::format("return tailcall {}();",
                                   callee_name(image, found->second->to_rva));
        current.confidence = "exact";
        current.target_rva = found->second->to_rva;
        current.target_name = callee_name(image, found->second->to_rva);
        current.indirect = false;
      }
      if (current.confidence != "unmodeled") ++result.lifted_instruction_count;
      lifted.statements.push_back(std::move(current));
    }
    std::optional<std::uint32_t> implicit_successor;
    if (!block.instructions.empty()) {
      const auto source_rva = static_cast<std::uint32_t>(
          block.instructions.back().address - image.info().image_base);
      for (const auto& edge : analyzed->edges) {
        if (edge.from_rva != source_rva) continue;
        if (edge.type == "fallthrough") {
          implicit_successor = edge.to_rva;
          if (!lifted.statements.empty() &&
              lifted.statements.back().operation == "branch")
            lifted.statements.back().text +=
                std::format(" else goto {};", label(edge.to_rva));
        }
      }
    }
    result.blocks.push_back(std::move(lifted));
  }
  auto stack = analyze_stack(*analyzed, x64);
  result.stack_variables = std::move(stack.variables);
  std::unordered_multimap<std::uint64_t, const StackAlias*> stack_aliases;
  stack_aliases.reserve(stack.aliases.size());
  for (const auto& alias : stack.aliases)
    stack_aliases.emplace(alias.address, &alias);
  for (auto& block : result.blocks) {
    for (auto& current : block.statements) {
      for (auto& memory : current.memory_accesses) {
        const auto [first, last] = stack_aliases.equal_range(current.address);
        const auto alias = std::ranges::find_if(
            std::ranges::subrange(first, last), [&](const auto& value) {
              return value.second->raw_alias == memory.alias_set;
            });
        if (alias != last) memory.alias_set = alias->second->normalized_alias;
      }
    }
  }
  result.type_evidence = infer_types(*analyzed, result.stack_variables, x64);
  result.field_evidence = infer_fields(*analyzed, x64);
  const auto ssa = build_ssa(result.blocks, result.edges,
                             image.info().image_base, x64);
  result.ssa_converged = ssa.converged;
  result.phi_count = ssa.phi_count;
  collect_parameters(result.blocks, result.stack_variables, x64,
                     result.parameters);
  result.control_regions = recover_control_regions(
      result.blocks, result.edges, image.info().image_base, entry_rva);

  result.pseudocode.push_back(std::format("function_{:x}() {{", entry_rva));
  for (const auto& block : result.blocks) {
    result.pseudocode.push_back(std::format("{}:", label(block.rva)));
    for (const auto& phi : block.phi_nodes) {
      std::string inputs;
      for (const auto& input : phi.inputs) {
        if (!inputs.empty()) inputs += ", ";
        inputs += input.function_entry
                      ? std::format("{} from function_entry", input.value)
                      : std::format("{} from {}", input.value,
                                    label(input.predecessor_rva));
      }
      result.pseudocode.push_back(
          std::format("  {} = phi({});", phi.output, inputs));
    }
    for (const auto& current : block.statements)
      result.pseudocode.push_back("  " + current.text);
    if (block.statements.empty()) continue;
    const auto& tail = block.statements.back();
    if (tail.operation == "branch" || tail.operation == "jump" ||
        tail.operation == "indirect_jump" || tail.operation == "tail_call" ||
        tail.operation == "return")
      continue;
    const auto source = tail.address - image.info().image_base;
    if (source > std::numeric_limits<std::uint32_t>::max()) continue;
    const auto found = std::ranges::find_if(result.edges, [&](const auto& edge) {
      return edge.from_rva == source && edge.type == "fallthrough";
    });
    if (found != result.edges.end())
      result.pseudocode.push_back(
          std::format("  goto {};", label(found->to_rva)));
  }
  result.pseudocode.push_back("}");
  if (result.lifted_instruction_count != result.instruction_count)
    result.warnings.emplace_back(
        "Unmodeled instructions are preserved as address-linked intrinsics; do not infer their side effects from pseudocode alone.");
  result.warnings.emplace_back(
      "Recovered parameter and variable names describe storage, not original source identifiers or proven types.");
  if (!result.ssa_converged)
    result.warnings.emplace_back(
        "SSA fixed-point analysis did not converge within its bounded iteration budget.");
  if (result.truncated)
    result.warnings.emplace_back(
        "Analysis reached a byte or block budget; the returned control flow is incomplete.");
  return result;
}

}  // namespace reverseplugin::analysis
