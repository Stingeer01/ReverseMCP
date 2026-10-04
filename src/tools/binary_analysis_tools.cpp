#include "reverseplugin/tools.hpp"

#include <algorithm>
#include <filesystem>
#include <memory>
#include <string>

#include "reverseplugin/analysis/analysis_cache.hpp"
#include "reverseplugin/analysis/binary_store.hpp"
#include "reverseplugin/analysis/function_analyzer.hpp"
#include "tool_support.hpp"

namespace reverseplugin {
namespace {

using mcp::Json;

Json instruction_json(const disasm::Instruction& instruction) {
  Json operands = Json::array();
  for (const auto& operand : instruction.operands) {
    Json value{{"type", operand.type}, {"visibility", operand.visibility},
               {"actions", operand.actions}, {"size_bits", operand.size_bits}};
    if (!operand.register_name.empty()) value["register"] = operand.register_name;
    if (operand.memory)
      value["memory"] = {{"segment", operand.memory->segment}, {"base", operand.memory->base},
                          {"index", operand.memory->index}, {"scale", operand.memory->scale},
                          {"displacement", operand.memory->displacement}};
    if (operand.immediate) value["immediate"] = *operand.immediate;
    if (operand.absolute_address)
      value["absolute_address"] = tools::hex_u64(*operand.absolute_address);
    operands.push_back(std::move(value));
  }
  return {{"address", tools::hex_u64(instruction.address)}, {"size", instruction.size},
          {"bytes", tools::hex_bytes(instruction.bytes)}, {"text", instruction.text},
          {"mnemonic", instruction.mnemonic}, {"category", instruction.category},
          {"branch_type", instruction.branch_type}, {"operands", std::move(operands)},
          {"registers_read", instruction.registers_read},
          {"registers_written", instruction.registers_written}};
}

std::filesystem::path path_from_utf8(std::string_view text) {
  std::u8string utf8;
  utf8.reserve(text.size());
  for (const auto byte : text) utf8.push_back(static_cast<char8_t>(byte));
  return std::filesystem::path{utf8};
}

std::string path_to_utf8(const std::filesystem::path& path) {
  const auto utf8 = path.generic_u8string();
  return {reinterpret_cast<const char*>(utf8.data()), utf8.size()};
}

Json summary_json(std::uint64_t id, const analysis::BinaryImage& image, bool cache_hit) {
  const auto& info = image.info();
  return {{"binary_id", id}, {"path", path_to_utf8(info.path)},
          {"fingerprint", info.fingerprint}, {"format", info.format},
          {"architecture", info.architecture}, {"image_base", tools::hex_u64(info.image_base)},
          {"entry_rva", tools::hex_u64(info.entry_rva)}, {"image_size", info.image_size},
          {"file_size", info.file_size}, {"section_count", image.sections().size()},
          {"import_count", image.imports().size()}, {"export_count", image.exports().size()},
          {"cache_hit", cache_hit}};
}

std::shared_ptr<const analysis::BinaryImage> require_binary(
    const Json& arguments, const std::shared_ptr<analysis::BinaryStore>& binaries,
    mcp::ToolError& error, std::uint64_t& id) {
  auto parsed = tools::unsigned_value(arguments, "binary_id");
  if (!parsed) {
    error = std::move(parsed.error());
    return nullptr;
  }
  id = *parsed;
  auto image = binaries->image(id);
  if (!image) error = tools::invalid("Unknown or closed binary workspace", {{"binary_id", id}});
  return image;
}

class OpenBinaryTool final : public mcp::Tool {
 public:
  explicit OpenBinaryTool(std::shared_ptr<analysis::BinaryStore> binaries)
      : binaries_(std::move(binaries)) {}
  std::string_view name() const noexcept override { return "open_binary"; }
  std::string_view description() const noexcept override {
    return "Open and validate a PE32/PE32+ binary for immutable static analysis. Reuses an unchanged in-memory image and returns its architecture, image layout, entry point, imports, exports, and content fingerprint.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"path", {{"type", "string"}, {"minLength", 1},
        {"description", "Absolute or workspace-relative path to a PE executable or DLL."}}}}},
      {"required", {"path"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"binary_id", {{"type", "integer"}, {"description", "Opaque workspace identifier."}}},
      {"path", {{"type", "string"}}}, {"fingerprint", {{"type", "string"}}},
      {"format", {{"type", "string"}}}, {"architecture", {{"type", "string"}}},
      {"image_base", {{"type", "string"}}}, {"entry_rva", {{"type", "string"}}},
      {"image_size", {{"type", "integer"}}}, {"file_size", {{"type", "integer"}}},
      {"section_count", {{"type", "integer"}}}, {"import_count", {{"type", "integer"}}},
      {"export_count", {{"type", "integer"}}},
      {"cache_hit", {{"type", "boolean"}, {"description", "True when an unchanged parsed image was reused."}}}}},
      {"required", {"binary_id", "path", "fingerprint", "format", "architecture", "image_base",
                    "entry_rva", "image_size", "file_size", "section_count", "import_count",
                    "export_count", "cache_hit"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) return std::unexpected(tools::invalid("Arguments must be an object"));
    const auto found = arguments.find("path");
    if (found == arguments.end() || !found->is_string() || found->get_ref<const std::string&>().empty())
      return std::unexpected(tools::invalid("path must be a non-empty string"));
    auto opened = binaries_->open(path_from_utf8(found->get_ref<const std::string&>()));
    if (!opened) return std::unexpected(tools::invalid(opened.error()));
    return summary_json(opened->id, *opened->image, opened->cache_hit);
  }
 private:
  std::shared_ptr<analysis::BinaryStore> binaries_;
};

class GetBinaryIndexTool final : public mcp::Tool {
 public:
  explicit GetBinaryIndexTool(std::shared_ptr<analysis::BinaryStore> binaries)
      : binaries_(std::move(binaries)) {}
  std::string_view name() const noexcept override { return "get_binary_index"; }
  std::string_view description() const noexcept override {
    return "Page through normalized PE sections, imports, or exports without reparsing the binary. Entries use RVAs so results remain stable across ASLR.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"binary_id", {{"type", "integer"}, {"minimum", 1}, {"description", "Identifier returned by open_binary."}}},
      {"kind", {{"type", "string"}, {"enum", {"sections", "imports", "exports"}},
        {"description", "Index family to return."}}},
      {"offset", {{"type", "integer"}, {"minimum", 0}, {"default", 0}, {"description", "Zero-based page offset."}}},
      {"limit", {{"type", "integer"}, {"minimum", 1}, {"maximum", 4096}, {"default", 256},
        {"description", "Maximum entries returned."}}}}},
      {"required", {"binary_id", "kind"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"kind", {{"type", "string"}}}, {"offset", {{"type", "integer"}}},
      {"total", {{"type", "integer"}, {"description", "Total entries in the selected index."}}},
      {"entries", {{"type", "array"}, {"description", "Normalized section, import, or export records."},
        {"items", {{"type", "object"}, {"properties", {
          {"name", {{"type", "string"}, {"description", "Section or symbol name; empty for unnamed ordinal exports."}}},
          {"module", {{"type", "string"}, {"description", "Importing module name."}}},
          {"rva", {{"type", "string"}, {"description", "ASLR-stable relative virtual address."}}},
          {"iat_rva", {{"type", "string"}, {"description", "Import address table slot RVA."}}},
          {"ordinal", {{"type", "integer"}}}, {"by_ordinal", {{"type", "boolean"}}},
          {"forwarder", {{"type", "string"}, {"description", "Forwarded export target when present."}}},
          {"virtual_size", {{"type", "integer"}}}, {"raw_offset", {{"type", "integer"}}},
          {"raw_size", {{"type", "integer"}}}, {"readable", {{"type", "boolean"}}},
          {"writable", {{"type", "boolean"}}}, {"executable", {{"type", "boolean"}}}}},
          {"additionalProperties", false}}}}},
      {"truncated", {{"type", "boolean"}}}}},
      {"required", {"kind", "offset", "total", "entries", "truncated"}},
      {"additionalProperties", false}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{};
    std::uint64_t id = 0;
    auto image = require_binary(arguments, binaries_, error, id);
    if (!image) return std::unexpected(std::move(error));
    const auto kind = arguments.value("kind", std::string{});
    const auto offset = arguments.value("offset", std::size_t{0});
    const auto limit = arguments.value("limit", std::size_t{256});
    if (limit == 0 || limit > 4096) return std::unexpected(tools::invalid("limit must be between 1 and 4096"));
    Json entries = Json::array();
    std::size_t total = 0;
    if (kind == "sections") {
      total = image->sections().size();
      for (std::size_t i = offset; i < total && entries.size() < limit; ++i) {
        const auto& section = image->sections()[i];
        entries.push_back({{"name", section.name}, {"rva", tools::hex_u64(section.rva)},
          {"virtual_size", section.virtual_size}, {"raw_offset", section.raw_offset},
          {"raw_size", section.raw_size}, {"readable", section.readable},
          {"writable", section.writable}, {"executable", section.executable}});
      }
    } else if (kind == "imports") {
      total = image->imports().size();
      for (std::size_t i = offset; i < total && entries.size() < limit; ++i) {
        const auto& imported = image->imports()[i];
        entries.push_back({{"module", imported.module}, {"name", imported.name},
          {"ordinal", imported.ordinal}, {"by_ordinal", imported.by_ordinal},
          {"iat_rva", tools::hex_u64(imported.iat_rva)}});
      }
    } else if (kind == "exports") {
      total = image->exports().size();
      for (std::size_t i = offset; i < total && entries.size() < limit; ++i) {
        const auto& exported = image->exports()[i];
        entries.push_back({{"name", exported.name}, {"ordinal", exported.ordinal},
          {"rva", tools::hex_u64(exported.rva)}, {"forwarder", exported.forwarder}});
      }
    } else {
      return std::unexpected(tools::invalid("kind must be sections, imports, or exports"));
    }
    return Json{{"kind", kind}, {"offset", offset}, {"total", total},
                {"entries", std::move(entries)}, {"truncated", offset + limit < total}};
  }
 private:
  std::shared_ptr<analysis::BinaryStore> binaries_;
};

class AnalyzeBinaryFunctionTool final : public mcp::Tool {
 public:
  AnalyzeBinaryFunctionTool(std::shared_ptr<analysis::BinaryStore> binaries,
                            std::shared_ptr<analysis::AnalysisCache> cache,
                            std::shared_ptr<disasm::Disassembler> disassembler)
      : binaries_(std::move(binaries)), cache_(std::move(cache)),
        disassembler_(std::move(disassembler)) {}
  std::string_view name() const noexcept override { return "analyze_binary_function"; }
  std::string_view description() const noexcept override {
    return "Recover a bounded function control-flow graph from a PE RVA or virtual address. Returns basic blocks, structured Zydis instructions, direct call references, and typed CFG edges; deterministic results are persisted by content fingerprint.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"binary_id", {{"type", "integer"}, {"minimum", 1}, {"description", "Identifier returned by open_binary."}}},
      {"address", tools::address_schema()},
      {"max_bytes", {{"type", "integer"}, {"minimum", 1}, {"maximum", 1048576}, {"default", 65536},
        {"description", "Maximum total instruction bytes decoded across all blocks."}}},
      {"max_blocks", {{"type", "integer"}, {"minimum", 1}, {"maximum", 4096}, {"default", 1024},
        {"description", "Maximum basic blocks recovered."}}},
      {"use_cache", {{"type", "boolean"}, {"default", true},
        {"description", "Load and persist deterministic results under the binary fingerprint."}}}}},
      {"required", {"binary_id", "address"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value = [] {
      const Json instruction{{"type", "object"}, {"properties", {
        {"address", {{"type", "string"}}}, {"size", {{"type", "integer"}}},
        {"bytes", {{"type", "string"}}}, {"text", {{"type", "string"}}},
        {"mnemonic", {{"type", "string"}}}, {"category", {{"type", "string"}}},
        {"branch_type", {{"type", "string"}}}, {"operands", {{"type", "array"}}},
        {"registers_read", {{"type", "array"}}},
        {"registers_written", {{"type", "array"}}}}},
        {"required", {"address", "size", "bytes", "text", "mnemonic", "category",
                      "branch_type", "operands", "registers_read", "registers_written"}}};
      const Json block{{"type", "object"}, {"properties", {
        {"rva", {{"type", "string"}}}, {"address", {{"type", "string"}}},
        {"instructions", {{"type", "array"}, {"items", instruction}}}}},
        {"required", {"rva", "address", "instructions"}}, {"additionalProperties", false}};
      const Json edge{{"type", "object"}, {"properties", {
        {"from_rva", {{"type", "string"}}}, {"to_rva", {{"type", "string"}}},
        {"type", {{"type", "string"}}}}},
        {"required", {"from_rva", "to_rva", "type"}}, {"additionalProperties", false}};
      return Json{{"type", "object"}, {"properties", {
        {"entry_rva", {{"type", "string"}}}, {"entry_address", {{"type", "string"}}},
        {"blocks", {{"type", "array"}, {"description", "Basic blocks with ordered structured instructions."}, {"items", block}}},
        {"edges", {{"type", "array"}, {"description", "Typed control-flow edges."}, {"items", edge}}},
        {"references", {{"type", "array"}, {"description", "Direct call references."}, {"items", edge}}},
        {"instruction_count", {{"type", "integer"}}}, {"decoded_bytes", {{"type", "integer"}}},
        {"truncated", {{"type", "boolean"}}},
        {"cache_hit", {{"type", "boolean"}, {"description", "True when loaded from persistent cache."}}}}},
        {"required", {"entry_rva", "entry_address", "blocks", "edges", "references",
                      "instruction_count", "decoded_bytes", "truncated", "cache_hit"}},
        {"additionalProperties", false}};
    }();
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{};
    std::uint64_t id = 0;
    auto image = require_binary(arguments, binaries_, error, id);
    if (!image) return std::unexpected(std::move(error));
    auto address = tools::unsigned_value(arguments, "address");
    if (!address) return std::unexpected(std::move(address.error()));
    auto rva = image->normalize_address(*address);
    if (!rva) return std::unexpected(tools::invalid(rva.error()));
    const auto max_bytes = arguments.value("max_bytes", std::size_t{65536});
    const auto max_blocks = arguments.value("max_blocks", std::size_t{1024});
    const bool use_cache = arguments.value("use_cache", true);
    const auto key = std::string{"function_"} + std::to_string(*rva) + "_" +
                     std::to_string(max_bytes) + "_" + std::to_string(max_blocks);
    if (use_cache) {
      if (auto cached = cache_->load(image->info().fingerprint, key)) {
        (*cached)["cache_hit"] = true;
        return std::move(*cached);
      }
    }
    auto analyzed = analysis::analyze_function(*image, *disassembler_, *rva, max_bytes, max_blocks);
    if (!analyzed) return std::unexpected(tools::invalid(analyzed.error()));
    Json blocks = Json::array();
    for (const auto& block : analyzed->blocks) {
      Json instructions = Json::array();
      for (const auto& instruction : block.instructions)
        instructions.push_back(instruction_json(instruction));
      blocks.push_back({{"rva", tools::hex_u64(block.rva)},
                        {"address", tools::hex_u64(image->info().image_base + block.rva)},
                        {"instructions", std::move(instructions)}});
    }
    Json edges = Json::array();
    for (const auto& edge : analyzed->edges)
      edges.push_back({{"from_rva", tools::hex_u64(edge.from_rva)},
                       {"to_rva", tools::hex_u64(edge.to_rva)}, {"type", edge.type}});
    Json references = Json::array();
    for (const auto& reference : analyzed->references)
      references.push_back({{"from_rva", tools::hex_u64(reference.from_rva)},
                            {"to_rva", tools::hex_u64(reference.to_rva)},
                            {"type", reference.type}});
    Json result{{"entry_rva", tools::hex_u64(*rva)},
                {"entry_address", tools::hex_u64(image->info().image_base + *rva)},
                {"blocks", std::move(blocks)}, {"edges", std::move(edges)},
                {"references", std::move(references)},
                {"instruction_count", analyzed->instruction_count},
                {"decoded_bytes", analyzed->decoded_bytes},
                {"truncated", analyzed->truncated}, {"cache_hit", false}};
    if (use_cache) static_cast<void>(cache_->store(image->info().fingerprint, key, result));
    return result;
  }
 private:
  std::shared_ptr<analysis::BinaryStore> binaries_;
  std::shared_ptr<analysis::AnalysisCache> cache_;
  std::shared_ptr<disasm::Disassembler> disassembler_;
};

class CloseBinaryTool final : public mcp::Tool {
 public:
  explicit CloseBinaryTool(std::shared_ptr<analysis::BinaryStore> binaries)
      : binaries_(std::move(binaries)) {}
  std::string_view name() const noexcept override { return "close_binary"; }
  std::string_view description() const noexcept override {
    return "Release an in-memory static-analysis workspace. Persistent fingerprinted analysis results remain reusable when the unchanged binary is opened again.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"binary_id", {{"type", "integer"}, {"minimum", 1}, {"description", "Identifier returned by open_binary."}}}}},
      {"required", {"binary_id"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"closed", {{"type", "boolean"}, {"description", "True when a live workspace was released."}}}}},
      {"required", {"closed"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    auto id = tools::unsigned_value(arguments, "binary_id");
    if (!id) return std::unexpected(std::move(id.error()));
    return Json{{"closed", binaries_->close(*id)}};
  }
 private:
  std::shared_ptr<analysis::BinaryStore> binaries_;
};

}  // namespace

void register_binary_navigation_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<analysis::BinaryStore>& binaries,
    const std::shared_ptr<disasm::Disassembler>& disassembler);
void register_binary_index_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<analysis::BinaryStore>& binaries,
    const std::shared_ptr<analysis::AnalysisCache>& cache,
    const std::shared_ptr<disasm::Disassembler>& disassembler);
void register_binary_decompiler_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<analysis::BinaryStore>& binaries,
    const std::shared_ptr<analysis::AnalysisCache>& cache,
    const std::shared_ptr<disasm::Disassembler>& disassembler);

void register_binary_analysis_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<disasm::Disassembler>& disassembler) {
  auto binaries = std::make_shared<analysis::BinaryStore>();
  auto cache = std::make_shared<analysis::AnalysisCache>();
  if (!registry.add(std::make_unique<OpenBinaryTool>(binaries)) ||
      !registry.add(std::make_unique<GetBinaryIndexTool>(binaries)) ||
      !registry.add(std::make_unique<AnalyzeBinaryFunctionTool>(binaries, cache, disassembler)) ||
      !registry.add(std::make_unique<CloseBinaryTool>(binaries)))
    std::terminate();
  register_binary_navigation_tools(registry, binaries, disassembler);
  register_binary_index_tools(registry, binaries, cache, disassembler);
  register_binary_decompiler_tools(registry, binaries, cache, disassembler);
}

}  // namespace reverseplugin
