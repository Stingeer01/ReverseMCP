#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace reverseplugin::disasm {

enum class Mode { x86, x64 };
enum class Syntax { intel, att };

struct Error final {
  std::string message;
  std::size_t offset;
};

struct MemoryOperand final {
  std::string segment;
  std::string base;
  std::string index;
  std::uint8_t scale;
  std::int64_t displacement;
};

struct Operand final {
  std::string type;
  std::string visibility;
  std::vector<std::string> actions;
  std::uint16_t size_bits;
  std::string register_name;
  std::optional<MemoryOperand> memory;
  std::optional<std::int64_t> immediate;
  std::optional<std::uint64_t> absolute_address;
};

struct Instruction final {
  std::uint64_t address;
  std::uint8_t size;
  std::vector<std::byte> bytes;
  std::string text;
  std::string mnemonic;
  std::string category;
  std::string branch_type;
  std::vector<Operand> operands;
  std::vector<std::string> registers_read;
  std::vector<std::string> registers_written;
};

class Disassembler final {
 public:
  [[nodiscard]] std::expected<std::vector<Instruction>, Error> decode(
      std::span<const std::byte> bytes, std::uint64_t address,
      std::size_t max_instructions, Mode mode, Syntax syntax) const;
};

}  // namespace reverseplugin::disasm
