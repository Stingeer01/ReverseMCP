#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include "reverseplugin/analysis/binary_image.hpp"
#include "reverseplugin/disasm/disassembler.hpp"

namespace reverseplugin::analysis {

struct IndexedString final {
  std::uint32_t rva;
  std::string encoding;
  std::string value;
  std::size_t byte_length;
};

struct StringIndex final {
  std::vector<IndexedString> strings;
  std::size_t bytes_scanned;
  bool truncated;
};

struct IndexedReference final {
  std::uint32_t from_rva;
  std::uint32_t to_rva;
  std::string type;
};

struct IndexedFunction final {
  std::uint32_t rva;
  std::string source;
  std::size_t block_count;
  std::size_t instruction_count;
  std::size_t decoded_bytes;
  bool truncated;
};

struct FunctionIndex final {
  std::vector<IndexedFunction> functions;
  std::vector<IndexedReference> references;
  std::size_t decoded_bytes;
  bool truncated;
};

[[nodiscard]] StringIndex scan_strings(
    const BinaryImage& image, std::size_t minimum_length,
    std::size_t max_results, std::size_t max_scan_bytes);

[[nodiscard]] std::expected<std::vector<IndexedReference>, std::string>
    find_references(const BinaryImage& image,
                    const disasm::Disassembler& disassembler,
                    std::uint32_t target_rva, std::size_t max_scan_bytes,
                    std::size_t max_results);

[[nodiscard]] std::expected<FunctionIndex, std::string> discover_functions(
    const BinaryImage& image, const disasm::Disassembler& disassembler,
    std::size_t max_functions, std::size_t max_total_bytes);

}  // namespace reverseplugin::analysis
