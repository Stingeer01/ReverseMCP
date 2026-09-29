#include "reverseplugin/tools.hpp"

#include <charconv>
#include <memory>
#include <mutex>
#include <string>

#include "reverseplugin/analysis/analysis_cache.hpp"
#include "reverseplugin/analysis/binary_store.hpp"
#include "reverseplugin/analysis/static_index.hpp"
#include "tool_support.hpp"

namespace reverseplugin {
namespace {

using mcp::Json;

std::shared_ptr<const analysis::BinaryImage> require_image(
    const Json& arguments, const std::shared_ptr<analysis::BinaryStore>& binaries,
    mcp::ToolError& error) {
  auto id = tools::unsigned_value(arguments, "binary_id");
  if (!id) { error = std::move(id.error()); return nullptr; }
  auto image = binaries->image(*id);
  if (!image) error = tools::invalid("Unknown or closed binary workspace");
  return image;
}

class FindBinaryStringsTool final : public mcp::Tool {
 public:
  FindBinaryStringsTool(std::shared_ptr<analysis::BinaryStore> binaries,
                        std::shared_ptr<analysis::AnalysisCache> cache)
      : binaries_(std::move(binaries)), cache_(std::move(cache)) {}
  std::string_view name() const noexcept override { return "find_binary_strings"; }
  std::string_view description() const noexcept override {
    return "Index bounded ASCII and UTF-16LE strings in readable PE sections. Results include encoding, byte length, RVA, virtual address, and persistent-cache state.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"binary_id", {{"type", "integer"}, {"minimum", 1}, {"description", "Identifier returned by open_binary."}}},
      {"minimum_length", {{"type", "integer"}, {"minimum", 3}, {"maximum", 1024}, {"default", 4},
        {"description", "Minimum printable characters in a result."}}},
      {"max_results", {{"type", "integer"}, {"minimum", 1}, {"maximum", 100000}, {"default", 10000},
        {"description", "Maximum indexed strings returned and cached."}}},
      {"max_scan_bytes", {{"type", "integer"}, {"minimum", 1}, {"maximum", 536870912}, {"default", 67108864},
        {"description", "Maximum readable file bytes scanned, capped at 512 MiB."}}},
      {"use_cache", {{"type", "boolean"}, {"default", true}}}}},
      {"required", {"binary_id"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value = [] {
      const Json item{{"type", "object"}, {"properties", {
        {"rva", {{"type", "string"}}}, {"address", {{"type", "string"}}},
        {"encoding", {{"type", "string"}}}, {"value", {{"type", "string"}}},
        {"byte_length", {{"type", "integer"}}}}},
        {"required", {"rva", "address", "encoding", "value", "byte_length"}}};
      return Json{{"type", "object"}, {"properties", {
        {"strings", {{"type", "array"}, {"items", item}}},
        {"string_count", {{"type", "integer"}}}, {"truncated", {{"type", "boolean"}}},
        {"bytes_scanned", {{"type", "integer"}}}, {"cache_hit", {{"type", "boolean"}}}}},
        {"required", {"strings", "string_count", "truncated", "bytes_scanned", "cache_hit"}},
        {"additionalProperties", false}};
    }();
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{}; auto image = require_image(arguments, binaries_, error);
    if (!image) return std::unexpected(std::move(error));
    const auto minimum = arguments.value("minimum_length", std::size_t{4});
    const auto maximum = arguments.value("max_results", std::size_t{10000});
    const auto scan_bytes = arguments.value("max_scan_bytes", std::size_t{67108864});
    if (minimum < 3 || minimum > 1024 || maximum == 0 || maximum > 100000 ||
        scan_bytes == 0 || scan_bytes > 536870912)
      return std::unexpected(tools::invalid("String scan limits are outside their schemas"));
    const bool use_cache = arguments.value("use_cache", true);
    const auto key = std::string{"strings_v2_"} + std::to_string(minimum) + "_" +
                     std::to_string(maximum) + "_" + std::to_string(scan_bytes);
    if (use_cache) if (auto cached = cache_->load(image->info().fingerprint, key)) {
      (*cached)["cache_hit"] = true; return std::move(*cached);
    }
    const auto indexed = analysis::scan_strings(*image, minimum, maximum, scan_bytes);
    Json strings = Json::array();
    for (const auto& item : indexed.strings)
      strings.push_back({{"rva", tools::hex_u64(item.rva)},
        {"address", tools::hex_u64(image->info().image_base + item.rva)},
        {"encoding", item.encoding}, {"value", item.value}, {"byte_length", item.byte_length}});
    const auto count = strings.size();
    Json result{{"strings", std::move(strings)}, {"string_count", count},
                {"truncated", indexed.truncated}, {"bytes_scanned", indexed.bytes_scanned},
                {"cache_hit", false}};
    if (use_cache) static_cast<void>(cache_->store(image->info().fingerprint, key, result));
    return result;
  }
 private:
  std::shared_ptr<analysis::BinaryStore> binaries_;
  std::shared_ptr<analysis::AnalysisCache> cache_;
};

class FindBinaryXrefsTool final : public mcp::Tool {
 public:
  FindBinaryXrefsTool(std::shared_ptr<analysis::BinaryStore> binaries,
                      std::shared_ptr<analysis::AnalysisCache> cache,
                      std::shared_ptr<disasm::Disassembler> disassembler)
      : binaries_(std::move(binaries)), cache_(std::move(cache)),
        disassembler_(std::move(disassembler)) {}
  std::string_view name() const noexcept override { return "find_binary_xrefs"; }
  std::string_view description() const noexcept override {
    return "Find direct code and RIP-relative data references to an RVA or virtual address by scanning executable PE sections with Zydis. Classifies call, jump, and data references.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"binary_id", {{"type", "integer"}, {"minimum", 1}}}, {"target", tools::address_schema()},
      {"max_scan_bytes", {{"type", "integer"}, {"minimum", 1}, {"maximum", 536870912}, {"default", 67108864},
        {"description", "Maximum executable bytes decoded while searching."}}},
      {"max_results", {{"type", "integer"}, {"minimum", 1}, {"maximum", 65536}, {"default", 4096}}},
      {"use_cache", {{"type", "boolean"}, {"default", true}}}}},
      {"required", {"binary_id", "target"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value = [] {
      const Json item{{"type", "object"}, {"properties", {
        {"from_rva", {{"type", "string"}}}, {"from_address", {{"type", "string"}}},
        {"type", {{"type", "string"}}}}},
        {"required", {"from_rva", "from_address", "type"}}};
      return Json{{"type", "object"}, {"properties", {
        {"target_rva", {{"type", "string"}}},
        {"references", {{"type", "array"}, {"items", item}}},
        {"reference_count", {{"type", "integer"}}}, {"truncated", {{"type", "boolean"}}},
        {"cache_hit", {{"type", "boolean"}}}}},
        {"required", {"target_rva", "references", "reference_count", "truncated", "cache_hit"}},
        {"additionalProperties", false}};
    }();
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{}; auto image = require_image(arguments, binaries_, error);
    if (!image) return std::unexpected(std::move(error));
    auto target = tools::unsigned_value(arguments, "target");
    if (!target) return std::unexpected(std::move(target.error()));
    auto rva = image->normalize_address(*target);
    if (!rva) return std::unexpected(tools::invalid(rva.error()));
    const auto scan = arguments.value("max_scan_bytes", std::size_t{67108864});
    const auto maximum = arguments.value("max_results", std::size_t{4096});
    if (scan == 0 || scan > 536870912 || maximum == 0 || maximum > 65536)
      return std::unexpected(tools::invalid("Xref scan limits are outside their schemas"));
    const bool use_cache = arguments.value("use_cache", true);
    const auto key = std::string{"xrefs_v1_"} + std::to_string(*rva) + "_" +
                     std::to_string(scan) + "_" + std::to_string(maximum);
    if (use_cache) if (auto cached = cache_->load(image->info().fingerprint, key)) {
      (*cached)["cache_hit"] = true; return std::move(*cached);
    }
    auto found = analysis::find_references(*image, *disassembler_, *rva, scan, maximum);
    if (!found) return std::unexpected(tools::invalid(found.error()));
    Json references = Json::array();
    for (const auto& reference : *found)
      references.push_back({{"from_rva", tools::hex_u64(reference.from_rva)},
        {"from_address", tools::hex_u64(image->info().image_base + reference.from_rva)},
        {"type", reference.type}});
    const auto count = references.size();
    Json result{{"target_rva", tools::hex_u64(*rva)}, {"references", std::move(references)},
                {"reference_count", count}, {"truncated", count >= maximum}, {"cache_hit", false}};
    if (use_cache) static_cast<void>(cache_->store(image->info().fingerprint, key, result));
    return result;
  }
 private:
  std::shared_ptr<analysis::BinaryStore> binaries_;
  std::shared_ptr<analysis::AnalysisCache> cache_;
  std::shared_ptr<disasm::Disassembler> disassembler_;
};

class DiscoverBinaryFunctionsTool final : public mcp::Tool {
 public:
  DiscoverBinaryFunctionsTool(std::shared_ptr<analysis::BinaryStore> binaries,
                              std::shared_ptr<analysis::AnalysisCache> cache,
                              std::shared_ptr<disasm::Disassembler> disassembler)
      : binaries_(std::move(binaries)), cache_(std::move(cache)),
        disassembler_(std::move(disassembler)) {}
  std::string_view name() const noexcept override { return "discover_binary_functions"; }
  std::string_view description() const noexcept override {
    return "Discover PE functions from the entry point, exports, x64 unwind records, and recursively reached direct calls. Returns provenance, bounded CFG metrics, call graph edges, and cache state.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"binary_id", {{"type", "integer"}, {"minimum", 1}}},
      {"max_functions", {{"type", "integer"}, {"minimum", 1}, {"maximum", 100000}, {"default", 10000}}},
      {"max_total_bytes", {{"type", "integer"}, {"minimum", 1}, {"maximum", 536870912}, {"default", 67108864},
        {"description", "Global decoded-byte budget across all functions."}}},
      {"use_cache", {{"type", "boolean"}, {"default", true}}}}},
      {"required", {"binary_id"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value = [] {
      const Json item{{"type", "object"}, {"properties", {
        {"rva", {{"type", "string"}}}, {"address", {{"type", "string"}}},
        {"source", {{"type", "string"}}}, {"block_count", {{"type", "integer"}}},
        {"instruction_count", {{"type", "integer"}}},
        {"decoded_bytes", {{"type", "integer"}}}, {"truncated", {{"type", "boolean"}}}}},
        {"required", {"rva", "address", "source", "block_count", "instruction_count",
                      "decoded_bytes", "truncated"}}};
      return Json{{"type", "object"}, {"properties", {
        {"functions", {{"type", "array"}, {"items", item}}},
        {"call_edges", {{"type", "array"}}}, {"function_count", {{"type", "integer"}}},
        {"decoded_bytes", {{"type", "integer"}}}, {"truncated", {{"type", "boolean"}}},
        {"cache_hit", {{"type", "boolean"}}}}},
        {"required", {"functions", "call_edges", "function_count", "decoded_bytes", "truncated", "cache_hit"}},
        {"additionalProperties", false}};
    }();
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{}; auto image = require_image(arguments, binaries_, error);
    if (!image) return std::unexpected(std::move(error));
    const auto maximum = arguments.value("max_functions", std::size_t{10000});
    const auto bytes = arguments.value("max_total_bytes", std::size_t{67108864});
    const bool use_cache = arguments.value("use_cache", true);
    const auto key = std::string{"functions_v1_"} + std::to_string(maximum) + "_" + std::to_string(bytes);
    if (use_cache) if (auto cached = cache_->load(image->info().fingerprint, key)) {
      (*cached)["cache_hit"] = true; return std::move(*cached);
    }
    auto indexed = analysis::discover_functions(*image, *disassembler_, maximum, bytes);
    if (!indexed) return std::unexpected(tools::invalid(indexed.error()));
    Json functions = Json::array();
    for (const auto& function : indexed->functions)
      functions.push_back({{"rva", tools::hex_u64(function.rva)},
        {"address", tools::hex_u64(image->info().image_base + function.rva)},
        {"source", function.source}, {"block_count", function.block_count},
        {"instruction_count", function.instruction_count}, {"decoded_bytes", function.decoded_bytes},
        {"truncated", function.truncated}});
    Json edges = Json::array();
    for (const auto& reference : indexed->references)
      edges.push_back({{"from_rva", tools::hex_u64(reference.from_rva)},
                       {"to_rva", tools::hex_u64(reference.to_rva)}, {"type", reference.type}});
    const auto count = functions.size();
    Json result{{"functions", std::move(functions)}, {"call_edges", std::move(edges)},
                {"function_count", count}, {"decoded_bytes", indexed->decoded_bytes},
                {"truncated", indexed->truncated}, {"cache_hit", false}};
    if (use_cache) static_cast<void>(cache_->store(image->info().fingerprint, key, result));
    return result;
  }
 private:
  std::shared_ptr<analysis::BinaryStore> binaries_;
  std::shared_ptr<analysis::AnalysisCache> cache_;
  std::shared_ptr<disasm::Disassembler> disassembler_;
};

class SetBinaryAnnotationTool final : public mcp::Tool {
 public:
  SetBinaryAnnotationTool(std::shared_ptr<analysis::BinaryStore> binaries,
                          std::shared_ptr<analysis::AnalysisCache> cache,
                          std::shared_ptr<std::mutex> mutex)
      : binaries_(std::move(binaries)), cache_(std::move(cache)), mutex_(std::move(mutex)) {}
  std::string_view name() const noexcept override { return "set_binary_annotation"; }
  std::string_view description() const noexcept override {
    return "Persist an analyst-assigned name, comment, or type at an RVA. Empty fields clear their values; remove deletes the complete annotation. Data is isolated by binary SHA-256.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"binary_id", {{"type", "integer"}, {"minimum", 1}}}, {"address", tools::address_schema()},
      {"name", {{"type", "string"}, {"maxLength", 1024}}},
      {"comment", {{"type", "string"}, {"maxLength", 65536}}},
      {"type", {{"type", "string"}, {"maxLength", 4096}, {"description", "User-defined declaration or type expression."}}},
      {"remove", {{"type", "boolean"}, {"default", false}}}}},
      {"required", {"binary_id", "address"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"rva", {{"type", "string"}}}, {"stored", {{"type", "boolean"}}},
      {"removed", {{"type", "boolean"}}}, {"annotation", {{"type", "object"}}}}},
      {"required", {"rva", "stored", "removed", "annotation"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& annotations() const noexcept override {
    static const Json value{{"readOnlyHint", false}, {"destructiveHint", false},
      {"idempotentHint", true}, {"openWorldHint", false}}; return value;
  }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{}; auto image = require_image(arguments, binaries_, error);
    if (!image) return std::unexpected(std::move(error));
    auto address = tools::unsigned_value(arguments, "address");
    if (!address) return std::unexpected(std::move(address.error()));
    auto rva = image->normalize_address(*address);
    if (!rva) return std::unexpected(tools::invalid(rva.error()));
    const bool remove = arguments.value("remove", false);
    if (!remove && !arguments.contains("name") && !arguments.contains("comment") && !arguments.contains("type"))
      return std::unexpected(tools::invalid("Provide name, comment, type, or remove=true"));
    const auto key = std::to_string(*rva);
    std::lock_guard lock(*mutex_);
    auto database = cache_->load(image->info().fingerprint, "annotations_v1")
                        .value_or(Json{{"entries", Json::object()}});
    auto& entries = database["entries"];
    if (!entries.is_object()) entries = Json::object();
    Json annotation = entries.value(key, Json::object());
    if (!annotation.is_object()) annotation = Json::object();
    if (remove) entries.erase(key);
    else {
      for (const auto* field : {"name", "comment", "type"}) {
        if (!arguments.contains(field)) continue;
        if (!arguments[field].is_string()) return std::unexpected(tools::invalid(std::string{field} + " must be a string"));
        const auto& value = arguments[field].get_ref<const std::string&>();
        const auto maximum = std::string_view{field} == "comment" ? std::size_t{65536}
                             : std::string_view{field} == "type" ? std::size_t{4096}
                                                                  : std::size_t{1024};
        if (value.size() > maximum)
          return std::unexpected(tools::invalid(std::string{field} + " exceeds its length limit"));
        if (value.empty()) annotation.erase(field); else annotation[field] = value;
      }
      if (annotation.empty()) entries.erase(key); else entries[key] = annotation;
    }
    const bool stored = cache_->store(image->info().fingerprint, "annotations_v1", database);
    if (!stored) return std::unexpected(mcp::ToolError{mcp::ToolErrorCode::unavailable,
      "Could not persist binary annotation", {}});
    return Json{{"rva", tools::hex_u64(*rva)}, {"stored", true}, {"removed", remove},
                {"annotation", remove ? Json::object() : std::move(annotation)}};
  }
 private:
  std::shared_ptr<analysis::BinaryStore> binaries_;
  std::shared_ptr<analysis::AnalysisCache> cache_;
  std::shared_ptr<std::mutex> mutex_;
};

class GetBinaryAnnotationsTool final : public mcp::Tool {
 public:
  GetBinaryAnnotationsTool(std::shared_ptr<analysis::BinaryStore> binaries,
                           std::shared_ptr<analysis::AnalysisCache> cache,
                           std::shared_ptr<std::mutex> mutex)
      : binaries_(std::move(binaries)), cache_(std::move(cache)), mutex_(std::move(mutex)) {}
  std::string_view name() const noexcept override { return "get_binary_annotations"; }
  std::string_view description() const noexcept override {
    return "Return persistent analyst names, comments, and types for the exact SHA-256 binary identity.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"binary_id", {{"type", "integer"}, {"minimum", 1}}},
      {"offset", {{"type", "integer"}, {"minimum", 0}, {"default", 0}}},
      {"limit", {{"type", "integer"}, {"minimum", 1}, {"maximum", 10000}, {"default", 1000}}}}},
      {"required", {"binary_id"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"annotations", {{"type", "array"}}}, {"total", {{"type", "integer"}}},
      {"truncated", {{"type", "boolean"}}}}},
      {"required", {"annotations", "total", "truncated"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{}; auto image = require_image(arguments, binaries_, error);
    if (!image) return std::unexpected(std::move(error));
    const auto offset = arguments.value("offset", std::size_t{0});
    const auto limit = arguments.value("limit", std::size_t{1000});
    if (limit == 0 || limit > 10000) return std::unexpected(tools::invalid("limit must be between 1 and 10000"));
    std::lock_guard lock(*mutex_);
    const auto database = cache_->load(image->info().fingerprint, "annotations_v1");
    auto entries = database ? database->value("entries", Json::object()) : Json::object();
    if (!entries.is_object()) entries = Json::object();
    Json output = Json::array();
    std::size_t index = 0;
    for (auto it = entries.begin(); it != entries.end(); ++it, ++index) {
      if (index < offset || output.size() >= limit) continue;
      std::uint64_t rva = 0;
      const auto& key = it.key();
      const auto [end, parse_error] = std::from_chars(key.data(), key.data() + key.size(), rva);
      if (parse_error != std::errc{} || end != key.data() + key.size() || !it.value().is_object())
        continue;
      auto value = it.value(); value["rva"] = tools::hex_u64(rva);
      output.push_back(std::move(value));
    }
    return Json{{"annotations", std::move(output)}, {"total", entries.size()},
                {"truncated", offset + limit < entries.size()}};
  }
 private:
  std::shared_ptr<analysis::BinaryStore> binaries_;
  std::shared_ptr<analysis::AnalysisCache> cache_;
  std::shared_ptr<std::mutex> mutex_;
};

}  // namespace

void register_binary_index_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<analysis::BinaryStore>& binaries,
    const std::shared_ptr<analysis::AnalysisCache>& cache,
    const std::shared_ptr<disasm::Disassembler>& disassembler) {
  auto annotation_mutex = std::make_shared<std::mutex>();
  if (!registry.add(std::make_unique<FindBinaryStringsTool>(binaries, cache)) ||
      !registry.add(std::make_unique<FindBinaryXrefsTool>(binaries, cache, disassembler)) ||
      !registry.add(std::make_unique<DiscoverBinaryFunctionsTool>(binaries, cache, disassembler)) ||
      !registry.add(std::make_unique<SetBinaryAnnotationTool>(binaries, cache, annotation_mutex)) ||
      !registry.add(std::make_unique<GetBinaryAnnotationsTool>(binaries, cache, annotation_mutex)))
    std::terminate();
}

}  // namespace reverseplugin
