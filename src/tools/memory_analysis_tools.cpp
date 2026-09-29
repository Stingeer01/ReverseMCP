#include "reverseplugin/tools.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>

#include "reverseplugin/memory/pattern.hpp"
#include "tool_support.hpp"

namespace reverseplugin {
namespace {

using mcp::Json;

const Json& mutation_annotations() {
  static const Json value{{"readOnlyHint", false}, {"destructiveHint", true},
                          {"idempotentHint", false}, {"openWorldHint", false}};
  return value;
}

class WriteMemoryTool final : public mcp::Tool {
 public:
  explicit WriteMemoryTool(std::shared_ptr<process::ProcessManager> processes)
      : processes_(std::move(processes)) {}
  std::string_view name() const noexcept override { return "write_memory"; }
  std::string_view description() const noexcept override {
    return "Write bytes only to already writable committed target memory. Returns the previous bytes and verifies the completed write by default; it never changes page protection.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"},
      {"properties", {{"session_id", tools::session_schema()},
        {"address", tools::address_schema()},
        {"hex", {{"type", "string"}, {"pattern", "^(?:[0-9a-fA-F]{2})+$"},
                 {"description", "Contiguous hexadecimal bytes to write, without 0x or separators; maximum 65536 bytes."}}},
        {"verify", {{"type", "boolean"}, {"default", true},
                    {"description", "Read the range back and fail if it differs."}}}}},
      {"required", {"session_id", "address", "hex"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"address", {{"type", "string"}}}, {"length", {{"type", "integer"}}},
      {"previous_hex", {{"type", "string"}}}, {"written_hex", {{"type", "string"}}},
      {"verified", {{"type", "boolean"}}}}},
      {"required", {"address", "length", "previous_hex", "written_hex", "verified"}}};
    return value;
  }
  const Json& annotations() const noexcept override { return mutation_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) return std::unexpected(tools::invalid("Arguments must be an object"));
    mcp::ToolError error{};
    const auto session = tools::require_session(arguments, processes_, error);
    if (!session) return std::unexpected(std::move(error));
    auto address = tools::unsigned_value(arguments, "address");
    if (!address) return std::unexpected(std::move(address.error()));
    const auto entry = arguments.find("hex");
    if (entry == arguments.end() || !entry->is_string())
      return std::unexpected(tools::invalid("hex must be a string"));
    auto bytes = tools::parse_hex_bytes(entry->get_ref<const std::string&>());
    if (!bytes) return std::unexpected(std::move(bytes.error()));
    auto previous = processes_->read(*session, *address, bytes->size());
    if (!previous) return std::unexpected(tools::process_error(previous.error()));
    auto written = processes_->write(*session, *address, *bytes);
    if (!written) return std::unexpected(tools::process_error(written.error()));
    const bool verify = arguments.value("verify", true);
    bool verified = false;
    if (verify) {
      auto observed = processes_->read(*session, *address, bytes->size());
      if (!observed) return std::unexpected(tools::process_error(observed.error()));
      verified = std::ranges::equal(*observed, *bytes);
      if (!verified)
        return std::unexpected(mcp::ToolError{mcp::ToolErrorCode::unavailable,
          "Write verification failed", {{"address", tools::hex_u64(*address)}}});
    }
    return Json{{"address", tools::hex_u64(*address)}, {"length", *written},
                {"previous_hex", tools::hex_bytes(*previous)},
                {"written_hex", tools::hex_bytes(*bytes)}, {"verified", verified}};
  }
 private:
  std::shared_ptr<process::ProcessManager> processes_;
};

std::expected<std::int64_t, mcp::ToolError> signed_offset(const Json& value) {
  if (value.is_number_integer()) return value.get<std::int64_t>();
  if (!value.is_string())
    return std::unexpected(tools::invalid("Each pointer offset must be an integer or signed hexadecimal string"));
  auto text = std::string_view{value.get_ref<const std::string&>()};
  bool negative = false;
  if (text.starts_with('-')) { negative = true; text.remove_prefix(1); }
  if (text.starts_with("0x") || text.starts_with("0X")) text.remove_prefix(2);
  std::uint64_t magnitude = 0;
  const auto [last, error] = std::from_chars(text.data(), text.data() + text.size(), magnitude, 16);
  constexpr auto max = static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
  if (error != std::errc{} || last != text.data() + text.size() ||
      magnitude > max + static_cast<std::uint64_t>(negative))
    return std::unexpected(tools::invalid("Invalid signed hexadecimal pointer offset"));
  if (negative && magnitude == max + 1) return (std::numeric_limits<std::int64_t>::min)();
  return negative ? -static_cast<std::int64_t>(magnitude)
                  : static_cast<std::int64_t>(magnitude);
}

class ReadPointerChainTool final : public mcp::Tool {
 public:
  explicit ReadPointerChainTool(std::shared_ptr<process::ProcessManager> processes)
      : processes_(std::move(processes)) {}
  std::string_view name() const noexcept override { return "read_pointer_chain"; }
  std::string_view description() const noexcept override {
    return "Resolve a runtime pointer chain. At each hop the current address is dereferenced, then the corresponding signed offset is added. Returns every intermediate address for diagnosis.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"session_id", tools::session_schema()}, {"base_address", tools::address_schema()},
      {"offsets", {{"type", "array"}, {"minItems", 1}, {"maxItems", 64},
        {"description", "Signed offsets applied after each dereference. Integers are decimal; strings may be 0x20 or -0x20."},
        {"items", {{"oneOf", {{{"type", "integer"}}, {{"type", "string"}}}}}}}},
      {"pointer_width", {{"type", "string"}, {"enum", {"auto", "32", "64"}},
        {"default", "auto"}, {"description", "Pointer width; auto uses target architecture."}}}}},
      {"required", {"session_id", "base_address", "offsets"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"base_address", {{"type", "string"}}}, {"pointer_width", {{"type", "integer"}}},
      {"hops", {{"type", "array"}}}, {"final_address", {{"type", "string"}}}}},
      {"required", {"base_address", "pointer_width", "hops", "final_address"}}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) return std::unexpected(tools::invalid("Arguments must be an object"));
    mcp::ToolError error{};
    const auto session = tools::require_session(arguments, processes_, error);
    if (!session) return std::unexpected(std::move(error));
    auto base = tools::unsigned_value(arguments, "base_address");
    if (!base) return std::unexpected(std::move(base.error()));
    const auto offsets = arguments.find("offsets");
    if (offsets == arguments.end() || !offsets->is_array() || offsets->empty() || offsets->size() > 64)
      return std::unexpected(tools::invalid("offsets must contain between 1 and 64 elements"));
    const auto width_name = arguments.value("pointer_width", std::string{"auto"});
    std::size_t width = 0;
    if (width_name == "32" || (width_name == "auto" && session->architecture() == process::Architecture::x86)) width = 4;
    if (width_name == "64" || (width_name == "auto" && session->architecture() == process::Architecture::x64)) width = 8;
    if (width == 0) return std::unexpected(tools::invalid("pointer_width is invalid or target architecture is unknown"));
    std::uint64_t current = *base;
    Json hops = Json::array();
    for (std::size_t index = 0; index < offsets->size(); ++index) {
      auto offset = signed_offset((*offsets)[index]);
      if (!offset) return std::unexpected(std::move(offset.error()));
      auto bytes = processes_->read(*session, current, width);
      if (!bytes) return std::unexpected(tools::process_error(bytes.error()));
      std::uint64_t pointer = 0;
      std::memcpy(&pointer, bytes->data(), width);
      std::uint64_t next = 0;
      if (*offset >= 0) {
        const auto positive = static_cast<std::uint64_t>(*offset);
        if (pointer > (std::numeric_limits<std::uint64_t>::max)() - positive)
          return std::unexpected(tools::invalid("Pointer-chain address overflow", {{"hop", index}}));
        next = pointer + positive;
      } else {
        const auto magnitude = static_cast<std::uint64_t>(-(*offset + 1)) + 1;
        if (pointer < magnitude)
          return std::unexpected(tools::invalid("Pointer-chain address underflow", {{"hop", index}}));
        next = pointer - magnitude;
      }
      hops.push_back({{"index", index}, {"dereference_address", tools::hex_u64(current)},
                      {"pointer_value", tools::hex_u64(pointer)}, {"offset", *offset},
                      {"result_address", tools::hex_u64(next)}});
      current = next;
    }
    return Json{{"base_address", tools::hex_u64(*base)}, {"pointer_width", width * 8},
                {"hops", std::move(hops)}, {"final_address", tools::hex_u64(current)}};
  }
 private:
  std::shared_ptr<process::ProcessManager> processes_;
};

class ScanMemoryPatternTool final : public mcp::Tool {
 public:
  explicit ScanMemoryPatternTool(std::shared_ptr<process::ProcessManager> processes)
      : processes_(std::move(processes)) {}
  std::string_view name() const noexcept override { return "scan_memory_pattern"; }
  std::string_view description() const noexcept override {
    return "Scan readable committed memory for an AOB signature with byte wildcards. Scans in bounded chunks, preserves cross-chunk matches, and can restrict results to executable regions.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"session_id", tools::session_schema()}, {"start_address", tools::address_schema()},
      {"size", {{"description", "Number of bytes to scan, at most 268435456 (256 MiB)."},
                  {"oneOf", {{{"type", "integer"}, {"minimum", 1}, {"maximum", 268435456}},
                              {{"type", "string"}, {"pattern", "^0[xX][0-9a-fA-F]+$"}}}}}},
      {"pattern", {{"type", "string"}, {"description", "Space-separated bytes such as '48 8B ?? ?? 89'. ? and ?? are wildcards."}}},
      {"executable_only", {{"type", "boolean"}, {"default", false},
                            {"description", "Scan only executable readable regions."}}},
      {"max_results", {{"type", "integer"}, {"minimum", 1}, {"maximum", 4096}, {"default", 256}}}}},
      {"required", {"session_id", "start_address", "size", "pattern"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"matches", {{"type", "array"}}}, {"match_count", {{"type", "integer"}}},
      {"bytes_scanned", {{"type", "integer"}}}, {"regions_scanned", {{"type", "integer"}}},
      {"truncated", {{"type", "boolean"}}}}},
      {"required", {"matches", "match_count", "bytes_scanned", "regions_scanned", "truncated"}}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) return std::unexpected(tools::invalid("Arguments must be an object"));
    mcp::ToolError error{};
    const auto session = tools::require_session(arguments, processes_, error);
    if (!session) return std::unexpected(std::move(error));
    auto start = tools::unsigned_value(arguments, "start_address");
    auto size = tools::unsigned_value(arguments, "size");
    if (!start) return std::unexpected(std::move(start.error()));
    if (!size) return std::unexpected(std::move(size.error()));
    if (*size == 0 || *size > 256ULL * 1024 * 1024 || *start > (std::numeric_limits<std::uint64_t>::max)() - *size)
      return std::unexpected(tools::invalid("size must be 1..268435456 and the address range must not overflow"));
    const auto pattern_text = arguments.find("pattern");
    if (pattern_text == arguments.end() || !pattern_text->is_string())
      return std::unexpected(tools::invalid("pattern must be a string"));
    auto pattern = memory::Pattern::parse(pattern_text->get_ref<const std::string&>());
    if (!pattern) return std::unexpected(tools::invalid(pattern.error()));
    const auto max_results = arguments.value("max_results", std::size_t{256});
    if (max_results == 0 || max_results > 4096)
      return std::unexpected(tools::invalid("max_results must be between 1 and 4096"));
    const bool executable_only = arguments.value("executable_only", false);
    const auto end = *start + *size;
    auto regions = processes_->query_regions(*session, *start, 65536);
    if (!regions) return std::unexpected(tools::process_error(regions.error()));
    Json matches = Json::array();
    std::uint64_t bytes_scanned = 0;
    std::size_t regions_scanned = 0;
    constexpr std::size_t chunk_size = 1024 * 1024;
    for (const auto& region : *regions) {
      if (region.base >= end || matches.size() >= max_results) break;
      const auto region_end = (std::min)(end, region.base + region.size);
      const auto region_start = (std::max)(*start, region.base);
      if (region_end <= region_start || !region.readable || (executable_only && !region.executable)) continue;
      ++regions_scanned;
      std::vector<std::byte> overlap;
      for (auto cursor = region_start; cursor < region_end && matches.size() < max_results;) {
        const auto amount = static_cast<std::size_t>((std::min<std::uint64_t>)(chunk_size, region_end - cursor));
        auto block = processes_->read(*session, cursor, amount);
        if (!block) break;
        std::vector<std::byte> window;
        window.reserve(overlap.size() + block->size());
        window.insert(window.end(), overlap.begin(), overlap.end());
        window.insert(window.end(), block->begin(), block->end());
        const auto window_base = cursor - overlap.size();
        for (const auto offset : pattern->find_all(window, max_results - matches.size())) {
          const auto address = window_base + offset;
          if (cursor == region_start || address + pattern->size() > cursor)
            matches.push_back(tools::hex_u64(address));
        }
        bytes_scanned += amount;
        const auto keep = (std::min)(pattern->size() - 1, window.size());
        overlap.assign(window.end() - static_cast<std::ptrdiff_t>(keep), window.end());
        cursor += amount;
      }
    }
    const auto match_count = matches.size();
    const bool truncated = match_count >= max_results;
    return Json{{"matches", std::move(matches)}, {"match_count", match_count},
                {"bytes_scanned", bytes_scanned}, {"regions_scanned", regions_scanned},
                {"truncated", truncated}};
  }
 private:
  std::shared_ptr<process::ProcessManager> processes_;
};

}  // namespace

void register_memory_analysis_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<process::ProcessManager>& processes) {
  if (!registry.add(std::make_unique<WriteMemoryTool>(processes)) ||
      !registry.add(std::make_unique<ReadPointerChainTool>(processes)) ||
      !registry.add(std::make_unique<ScanMemoryPatternTool>(processes)))
    std::terminate();
}

}  // namespace reverseplugin
