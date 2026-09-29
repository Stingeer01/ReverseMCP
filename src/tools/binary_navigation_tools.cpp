#include "reverseplugin/tools.hpp"

#include <algorithm>
#include <memory>

#include "reverseplugin/analysis/binary_store.hpp"
#include "reverseplugin/memory/pattern.hpp"
#include "tool_support.hpp"

namespace reverseplugin {
namespace {

using mcp::Json;

std::shared_ptr<const analysis::BinaryImage> binary(
    const Json& arguments, const std::shared_ptr<analysis::BinaryStore>& binaries,
    mcp::ToolError& error) {
  auto id = tools::unsigned_value(arguments, "binary_id");
  if (!id) { error = std::move(id.error()); return nullptr; }
  auto image = binaries->image(*id);
  if (!image) error = tools::invalid("Unknown or closed binary workspace");
  return image;
}

Json operand_json(const disasm::Operand& operand) {
  Json result{{"type", operand.type}, {"visibility", operand.visibility},
              {"actions", operand.actions}, {"size_bits", operand.size_bits}};
  if (!operand.register_name.empty()) result["register"] = operand.register_name;
  if (operand.memory)
    result["memory"] = {{"segment", operand.memory->segment}, {"base", operand.memory->base},
                         {"index", operand.memory->index}, {"scale", operand.memory->scale},
                         {"displacement", operand.memory->displacement}};
  if (operand.immediate) result["immediate"] = *operand.immediate;
  if (operand.absolute_address) result["absolute_address"] = tools::hex_u64(*operand.absolute_address);
  return result;
}

Json instruction_json(const disasm::Instruction& instruction) {
  Json operands = Json::array();
  for (const auto& operand : instruction.operands) operands.push_back(operand_json(operand));
  return {{"address", tools::hex_u64(instruction.address)}, {"size", instruction.size},
          {"bytes", tools::hex_bytes(instruction.bytes)}, {"text", instruction.text},
          {"mnemonic", instruction.mnemonic}, {"category", instruction.category},
          {"branch_type", instruction.branch_type}, {"operands", std::move(operands)},
          {"registers_read", instruction.registers_read},
          {"registers_written", instruction.registers_written}};
}

class ReadBinaryBytesTool final : public mcp::Tool {
 public:
  explicit ReadBinaryBytesTool(std::shared_ptr<analysis::BinaryStore> binaries)
      : binaries_(std::move(binaries)) {}
  std::string_view name() const noexcept override { return "read_binary_bytes"; }
  std::string_view description() const noexcept override {
    return "Read exact file-backed bytes from a static binary workspace by RVA or virtual address without accessing a live process.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"binary_id", {{"type", "integer"}, {"minimum", 1}, {"description", "Identifier returned by open_binary."}}},
      {"address", tools::address_schema()},
      {"length", {{"type", "integer"}, {"minimum", 1}, {"maximum", 1048576},
        {"description", "Number of file-backed bytes to read, capped at 1 MiB."}}}}},
      {"required", {"binary_id", "address", "length"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"rva", {{"type", "string"}}}, {"address", {{"type", "string"}}},
      {"length", {{"type", "integer"}}}, {"hex", {{"type", "string"}}}}},
      {"required", {"rva", "address", "length", "hex"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{}; auto image = binary(arguments, binaries_, error);
    if (!image) return std::unexpected(std::move(error));
    auto address = tools::unsigned_value(arguments, "address");
    auto length = tools::unsigned_value(arguments, "length");
    if (!address) return std::unexpected(std::move(address.error()));
    if (!length) return std::unexpected(std::move(length.error()));
    if (*length == 0 || *length > 1048576) return std::unexpected(tools::invalid("length must be between 1 and 1048576"));
    auto rva = image->normalize_address(*address);
    if (!rva) return std::unexpected(tools::invalid(rva.error()));
    auto bytes = image->bytes_at(*rva, static_cast<std::size_t>(*length));
    if (!bytes) return std::unexpected(tools::invalid(bytes.error()));
    return Json{{"rva", tools::hex_u64(*rva)},
                {"address", tools::hex_u64(image->info().image_base + *rva)},
                {"length", bytes->size()}, {"hex", tools::hex_bytes(*bytes)}};
  }
 private: std::shared_ptr<analysis::BinaryStore> binaries_;
};

class DisassembleBinaryTool final : public mcp::Tool {
 public:
  DisassembleBinaryTool(std::shared_ptr<analysis::BinaryStore> binaries,
                        std::shared_ptr<disasm::Disassembler> disassembler)
      : binaries_(std::move(binaries)), disassembler_(std::move(disassembler)) {}
  std::string_view name() const noexcept override { return "disassemble_binary"; }
  std::string_view description() const noexcept override {
    return "Decode file-backed PE code by RVA or virtual address with structured Zydis operands, absolute targets, register access, categories, and exact bytes.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"binary_id", {{"type", "integer"}, {"minimum", 1}}}, {"address", tools::address_schema()},
      {"max_bytes", {{"type", "integer"}, {"minimum", 1}, {"maximum", 1048576}, {"default", 4096},
        {"description", "Maximum file-backed bytes exposed to the decoder."}}},
      {"max_instructions", {{"type", "integer"}, {"minimum", 1}, {"maximum", 65536}, {"default", 256},
        {"description", "Maximum decoded instructions returned."}}}}},
      {"required", {"binary_id", "address"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"rva", {{"type", "string"}}}, {"instructions", {{"type", "array"}}},
      {"instruction_count", {{"type", "integer"}}}}},
      {"required", {"rva", "instructions", "instruction_count"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{}; auto image = binary(arguments, binaries_, error);
    if (!image) return std::unexpected(std::move(error));
    auto address = tools::unsigned_value(arguments, "address");
    if (!address) return std::unexpected(std::move(address.error()));
    auto rva = image->normalize_address(*address);
    if (!rva) return std::unexpected(tools::invalid(rva.error()));
    const auto max_bytes = arguments.value("max_bytes", std::size_t{4096});
    const auto max_instructions = arguments.value("max_instructions", std::size_t{256});
    if (max_bytes == 0 || max_bytes > 1048576 || max_instructions == 0 || max_instructions > 65536)
      return std::unexpected(tools::invalid("Disassembly limits are outside their schemas"));
    auto bytes = image->bytes_at(*rva, max_bytes);
    if (!bytes) return std::unexpected(tools::invalid(bytes.error()));
    const auto mode = image->info().architecture == "x86_64" ? disasm::Mode::x64 : disasm::Mode::x86;
    auto decoded = disassembler_->decode(*bytes, image->info().image_base + *rva,
                                         max_instructions, mode, disasm::Syntax::intel);
    if (!decoded) return std::unexpected(tools::invalid(decoded.error().message,
                                                        {{"offset", decoded.error().offset}}));
    Json instructions = Json::array();
    for (const auto& instruction : *decoded) instructions.push_back(instruction_json(instruction));
    const auto count = instructions.size();
    return Json{{"rva", tools::hex_u64(*rva)}, {"instructions", std::move(instructions)},
                {"instruction_count", count}};
  }
 private:
  std::shared_ptr<analysis::BinaryStore> binaries_;
  std::shared_ptr<disasm::Disassembler> disassembler_;
};

class ScanBinaryPatternTool final : public mcp::Tool {
 public:
  explicit ScanBinaryPatternTool(std::shared_ptr<analysis::BinaryStore> binaries)
      : binaries_(std::move(binaries)) {}
  std::string_view name() const noexcept override { return "scan_binary_pattern"; }
  std::string_view description() const noexcept override {
    return "Search file-backed PE sections for an AOB signature with wildcards and return ASLR-stable RVAs plus virtual addresses.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"binary_id", {{"type", "integer"}, {"minimum", 1}}},
      {"pattern", {{"type", "string"}, {"description", "Space-separated bytes such as '48 8B ?? ?? 89'."}}},
      {"executable_only", {{"type", "boolean"}, {"default", false}}},
      {"max_results", {{"type", "integer"}, {"minimum", 1}, {"maximum", 65536}, {"default", 1024}}}}},
      {"required", {"binary_id", "pattern"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"matches", {{"type", "array"}}}, {"match_count", {{"type", "integer"}}},
      {"truncated", {{"type", "boolean"}}}}},
      {"required", {"matches", "match_count", "truncated"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{}; auto image = binary(arguments, binaries_, error);
    if (!image) return std::unexpected(std::move(error));
    const auto entry = arguments.find("pattern");
    if (entry == arguments.end() || !entry->is_string()) return std::unexpected(tools::invalid("pattern must be a string"));
    auto pattern = memory::Pattern::parse(entry->get_ref<const std::string&>());
    if (!pattern) return std::unexpected(tools::invalid(pattern.error()));
    const bool executable_only = arguments.value("executable_only", false);
    const auto max_results = arguments.value("max_results", std::size_t{1024});
    if (max_results == 0 || max_results > 65536) return std::unexpected(tools::invalid("max_results must be between 1 and 65536"));
    Json matches = Json::array();
    for (const auto& section : image->sections()) {
      if (section.raw_size == 0 || (executable_only && !section.executable)) continue;
      auto bytes = image->bytes_at(section.rva, section.raw_size);
      if (!bytes) continue;
      for (const auto offset : pattern->find_all(*bytes, max_results - matches.size())) {
        const auto rva = section.rva + offset;
        matches.push_back({{"rva", tools::hex_u64(rva)},
                           {"address", tools::hex_u64(image->info().image_base + rva)},
                           {"section", section.name}});
      }
      if (matches.size() >= max_results) break;
    }
    const auto count = matches.size();
    return Json{{"matches", std::move(matches)}, {"match_count", count},
                {"truncated", count >= max_results}};
  }
 private: std::shared_ptr<analysis::BinaryStore> binaries_;
};

}  // namespace

void register_binary_navigation_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<analysis::BinaryStore>& binaries,
    const std::shared_ptr<disasm::Disassembler>& disassembler) {
  if (!registry.add(std::make_unique<ReadBinaryBytesTool>(binaries)) ||
      !registry.add(std::make_unique<DisassembleBinaryTool>(binaries, disassembler)) ||
      !registry.add(std::make_unique<ScanBinaryPatternTool>(binaries)))
    std::terminate();
}

}  // namespace reverseplugin
