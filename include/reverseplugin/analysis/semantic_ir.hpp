#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace reverseplugin::analysis {

struct SsaUse final {
  std::string storage;
  std::string value;
  std::string role;
  std::uint16_t offset_bits{};
  std::uint16_t size_bits{};
};

struct SsaDefinition final {
  std::string storage;
  std::string value;
  std::string previous_value;
  std::string write;
  std::string role;
  std::uint16_t offset_bits{};
  std::uint16_t size_bits{};
};

struct MemoryAccess final {
  std::string action;
  std::string address;
  std::string alias_set;
  std::uint16_t size_bits{};
  std::string ssa_input;
  std::string ssa_output;
};

struct PhiInput final {
  std::uint32_t predecessor_rva{};
  std::string value;
  bool function_entry{};
};

struct PhiNode final {
  std::string storage;
  std::string output;
  std::vector<PhiInput> inputs;
};

struct ControlRegion final {
  std::string kind;
  std::uint32_t header_rva{};
  std::uint32_t merge_rva{};
  std::vector<std::uint32_t> entries;
  std::vector<std::uint32_t> members;
  std::vector<std::uint32_t> exits;
  std::string confidence;
};

struct TypeEvidence final {
  std::string storage;
  std::string kind;
  std::uint16_t size_bits{};
  std::string signedness;
  std::string confidence;
  std::vector<std::uint64_t> evidence;
};

struct FieldEvidence final {
  std::string base_storage;
  std::string index_storage;
  std::int64_t offset{};
  std::uint8_t scale{};
  std::uint16_t size_bits{};
  bool read{};
  bool written{};
  std::string kind;
  std::vector<std::uint64_t> evidence;
};

struct RecoveredVariable final {
  std::string name;
  std::string storage;
  std::string role;
  std::int64_t offset{};
  std::optional<std::int64_t> entry_sp_offset;
  std::uint16_t size_bits{};
  std::string confidence;
  std::vector<std::uint64_t> references;
};

struct RecoveredParameter final {
  std::string name;
  std::string storage;
  std::uint16_t size_bits{};
  std::vector<std::uint64_t> evidence;
};

}  // namespace reverseplugin::analysis
