#include "reverseplugin/analysis/static_index.hpp"

#include <algorithm>
#include <deque>
#include <unordered_map>
#include <unordered_set>

#include "reverseplugin/analysis/function_analyzer.hpp"

namespace reverseplugin::analysis {
namespace {

bool printable(std::uint8_t value) noexcept {
  return value >= 0x20 && value <= 0x7e;
}

std::string reference_type(const disasm::Instruction& instruction) {
  if (instruction.mnemonic == "call") return "call";
  if (instruction.mnemonic == "jmp" ||
      (instruction.mnemonic.size() > 1 && instruction.mnemonic.front() == 'j'))
    return "jump";
  return "data";
}

void add_seed(std::uint32_t rva, std::string source, const BinaryImage& image,
              std::deque<std::uint32_t>& pending,
              std::unordered_map<std::uint32_t, std::string>& sources,
              std::size_t maximum) {
  if (!image.executable_rva(rva)) return;
  if (sources.size() >= maximum && !sources.contains(rva)) return;
  if (sources.emplace(rva, std::move(source)).second) pending.push_back(rva);
}

}  // namespace

StringIndex scan_strings(const BinaryImage& image, std::size_t minimum_length,
                         std::size_t max_results, std::size_t max_scan_bytes) {
  StringIndex index{};
  index.strings.reserve((std::min)(max_results, std::size_t{1024}));
  for (const auto& section : image.sections()) {
    if (!section.readable || section.raw_size == 0 ||
        index.bytes_scanned >= max_scan_bytes) continue;
    const auto amount = (std::min)(static_cast<std::size_t>(section.raw_size),
                                   max_scan_bytes - index.bytes_scanned);
    auto bytes = image.bytes_at(section.rva, amount);
    if (!bytes) continue;
    std::size_t cursor = 0;
    while (cursor < bytes->size() && index.strings.size() < max_results) {
      const auto start = cursor;
      while (cursor < bytes->size() &&
             printable(std::to_integer<std::uint8_t>((*bytes)[cursor])))
        ++cursor;
      if (cursor - start >= minimum_length) {
        const auto* chars = reinterpret_cast<const char*>(bytes->data() + start);
        index.strings.push_back({section.rva + static_cast<std::uint32_t>(start), "ascii",
                                 std::string{chars, chars + (cursor - start)}, cursor - start});
      }
      cursor = cursor == start ? cursor + 1 : cursor;
    }
    cursor = 0;
    while (cursor + 1 < bytes->size() && index.strings.size() < max_results) {
      const auto start = cursor;
      std::string value;
      while (cursor + 1 < bytes->size() &&
             printable(std::to_integer<std::uint8_t>((*bytes)[cursor])) &&
             (*bytes)[cursor + 1] == std::byte{0}) {
        value.push_back(static_cast<char>(std::to_integer<std::uint8_t>((*bytes)[cursor])));
        cursor += 2;
      }
      if (value.size() >= minimum_length)
        index.strings.push_back({section.rva + static_cast<std::uint32_t>(start), "utf16le",
                                 std::move(value), cursor - start});
      cursor = cursor == start ? cursor + 1 : cursor;
    }
    index.bytes_scanned += bytes->size();
    if (index.strings.size() >= max_results) break;
  }
  index.truncated = index.strings.size() >= max_results ||
                    index.bytes_scanned >= max_scan_bytes;
  return index;
}

std::expected<std::vector<IndexedReference>, std::string> find_references(
    const BinaryImage& image, const disasm::Disassembler& disassembler,
    std::uint32_t target_rva, std::size_t max_scan_bytes,
    std::size_t max_results) {
  if (!image.contains_rva(target_rva)) return std::unexpected("Target RVA is outside the image");
  const auto mode = image.info().architecture == "x86_64"
                        ? disasm::Mode::x64 : disasm::Mode::x86;
  std::vector<IndexedReference> result;
  std::size_t scanned = 0;
  for (const auto& section : image.sections()) {
    if (!section.executable || section.raw_size == 0 || scanned >= max_scan_bytes) continue;
    auto bytes = image.bytes_at(section.rva,
        (std::min)(static_cast<std::size_t>(section.raw_size), max_scan_bytes - scanned));
    if (!bytes) continue;
    std::size_t offset = 0;
    while (offset < bytes->size() && result.size() < max_results) {
      const auto window = bytes->subspan(offset, (std::min)(std::size_t{15}, bytes->size() - offset));
      auto decoded = disassembler.decode(window,
          image.info().image_base + section.rva + offset, 1, mode, disasm::Syntax::intel);
      if (!decoded || decoded->empty()) { ++offset; continue; }
      const auto& instruction = decoded->front();
      for (const auto& operand : instruction.operands) {
        if (!operand.absolute_address) continue;
        auto normalized = image.normalize_address(*operand.absolute_address);
        if (normalized && *normalized == target_rva) {
          result.push_back({section.rva + static_cast<std::uint32_t>(offset),
                            target_rva, reference_type(instruction)});
          break;
        }
      }
      offset += instruction.size;
    }
    scanned += bytes->size();
    if (result.size() >= max_results) break;
  }
  return result;
}

std::expected<FunctionIndex, std::string> discover_functions(
    const BinaryImage& image, const disasm::Disassembler& disassembler,
    std::size_t max_functions, std::size_t max_total_bytes) {
  if (max_functions == 0 || max_functions > 100000)
    return std::unexpected("max_functions must be between 1 and 100000");
  if (max_total_bytes == 0 || max_total_bytes > 512U * 1024U * 1024U)
    return std::unexpected("max_total_bytes must be between 1 and 536870912");
  FunctionIndex result{};
  std::deque<std::uint32_t> pending;
  std::unordered_map<std::uint32_t, std::string> sources;
  std::unordered_set<std::uint32_t> analyzed;
  add_seed(image.info().entry_rva, "entry", image, pending, sources, max_functions);
  for (const auto& exported : image.exports())
    add_seed(exported.rva, "export", image, pending, sources, max_functions);
  for (const auto& function : image.runtime_functions()) {
    if (sources.size() >= max_functions) break;
    add_seed(function.begin_rva, "unwind", image, pending, sources, max_functions);
  }

  while (!pending.empty() && result.functions.size() < max_functions &&
         result.decoded_bytes < max_total_bytes) {
    const auto rva = pending.front();
    pending.pop_front();
    if (!analyzed.insert(rva).second) continue;
    const auto budget = (std::min)(std::size_t{65536}, max_total_bytes - result.decoded_bytes);
    auto function = analyze_function(image, disassembler, rva, budget, 1024);
    if (!function) continue;
    result.functions.push_back({rva, sources[rva], function->blocks.size(),
                                function->instruction_count, function->decoded_bytes,
                                function->truncated});
    result.decoded_bytes += function->decoded_bytes;
    for (const auto& reference : function->references) {
      result.references.push_back({reference.from_rva, reference.to_rva, reference.type});
      add_seed(reference.to_rva, reference.type, image, pending, sources, max_functions);
    }
  }
  std::ranges::sort(result.functions, {}, &IndexedFunction::rva);
  result.truncated = !pending.empty();
  return result;
}

}  // namespace reverseplugin::analysis
