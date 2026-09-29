#include "reverseplugin/tools.hpp"

#include <algorithm>
#include <limits>
#include <memory>

#include "tool_support.hpp"

namespace reverseplugin {
namespace {

using mcp::Json;

std::string_view state_name(std::uint32_t state) noexcept {
  switch (state) {
    case MEM_COMMIT:
      return "committed";
    case MEM_RESERVE:
      return "reserved";
    case MEM_FREE:
      return "free";
    default:
      return "unknown";
  }
}

std::string_view type_name(std::uint32_t type) noexcept {
  switch (type) {
    case MEM_IMAGE:
      return "image";
    case MEM_MAPPED:
      return "mapped";
    case MEM_PRIVATE:
      return "private";
    default:
      return "none";
  }
}

Json region_json(const process::MemoryRegion& region) {
  return {{"base_address", tools::hex_u64(region.base)},
          {"end_address", tools::hex_u64(region.base + region.size)},
          {"size", region.size},
          {"state", state_name(region.state)},
          {"type", type_name(region.type)},
          {"protection", region.protection},
          {"readable", region.readable},
          {"writable", region.writable},
          {"executable", region.executable}};
}

Json operand_json(const disasm::Operand& operand) {
  Json result{{"type", operand.type},
              {"visibility", operand.visibility},
              {"actions", operand.actions},
              {"size_bits", operand.size_bits}};
  if (!operand.register_name.empty()) {
    result["register"] = operand.register_name;
  }
  if (operand.memory) {
    result["memory"] = {{"segment", operand.memory->segment},
                        {"base", operand.memory->base},
                        {"index", operand.memory->index},
                        {"scale", operand.memory->scale},
                        {"displacement", operand.memory->displacement}};
  }
  if (operand.immediate) {
    result["immediate"] = *operand.immediate;
  }
  if (operand.absolute_address) {
    result["absolute_address"] = tools::hex_u64(*operand.absolute_address);
  }
  return result;
}

Json instruction_json(const disasm::Instruction& instruction) {
  Json operands = Json::array();
  for (const auto& operand : instruction.operands) {
    operands.push_back(operand_json(operand));
  }
  return {{"address", tools::hex_u64(instruction.address)},
          {"size", instruction.size},
          {"bytes", tools::hex_bytes(instruction.bytes)},
          {"text", instruction.text},
          {"mnemonic", instruction.mnemonic},
          {"category", instruction.category},
          {"branch_type", instruction.branch_type},
          {"operands", std::move(operands)},
          {"registers_read", instruction.registers_read},
          {"registers_written", instruction.registers_written}};
}

class QueryMemoryRegionsTool final : public mcp::Tool {
 public:
  explicit QueryMemoryRegionsTool(std::shared_ptr<process::ProcessManager> processes)
      : processes_(std::move(processes)) {}
  std::string_view name() const noexcept override { return "query_memory_regions"; }
  std::string_view description() const noexcept override {
    return "Walk the target process virtual address space from a starting address and return region boundaries, allocation state, type, and normalized read/write/execute permissions.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{
        {"type", "object"},
        {"properties", {{"session_id", tools::session_schema()},
                        {"start_address", tools::address_schema()},
                        {"max_regions", {{"type", "integer"}, {"minimum", 1},
                                         {"maximum", 512}, {"default", 64},
                                         {"description", "Maximum consecutive virtual memory regions returned."}}}}},
        {"required", {"session_id"}},
        {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"},
                            {"properties", {{"regions", {{"type", "array"}}},
                                            {"returned", {{"type", "integer"}}}}},
                            {"required", {"regions", "returned"}}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) {
      return std::unexpected(tools::invalid("Arguments must be an object"));
    }
    mcp::ToolError error{};
    const auto session = tools::require_session(arguments, processes_, error);
    if (!session) {
      return std::unexpected(std::move(error));
    }
    std::uint64_t start = 0;
    if (arguments.contains("start_address")) {
      auto parsed = tools::unsigned_value(arguments, "start_address");
      if (!parsed) {
        return std::unexpected(std::move(parsed.error()));
      }
      start = *parsed;
    }
    const auto count = arguments.value("max_regions", std::size_t{64});
    if (count == 0 || count > 512) {
      return std::unexpected(tools::invalid("max_regions must be between 1 and 512"));
    }
    auto regions = processes_->query_regions(*session, start, count);
    if (!regions) {
      return std::unexpected(tools::process_error(regions.error()));
    }
    Json items = Json::array();
    for (const auto& region : *regions) {
      items.push_back(region_json(region));
    }
    const auto returned = items.size();
    return Json{{"regions", std::move(items)}, {"returned", returned}};
  }

 private:
  std::shared_ptr<process::ProcessManager> processes_;
};

class ReadMemoryTool final : public mcp::Tool {
 public:
  explicit ReadMemoryTool(std::shared_ptr<process::ProcessManager> processes)
      : processes_(std::move(processes)) {}
  std::string_view name() const noexcept override { return "read_memory"; }
  std::string_view description() const noexcept override {
    return "Read an exact validated virtual-memory range from an attached process. The request fails safely if any byte crosses an uncommitted, guarded, or unreadable region.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{
        {"type", "object"},
        {"properties", {{"session_id", tools::session_schema()},
                        {"address", tools::address_schema()},
                        {"length", {{"type", "integer"}, {"minimum", 1},
                                    {"maximum", 65536},
                                    {"description", "Number of bytes to read; capped at 65536 per call."}}}}},
        {"required", {"session_id", "address", "length"}},
        {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"},
                            {"properties", {{"address", {{"type", "string"}}},
                                            {"length", {{"type", "integer"}}},
                                            {"hex", {{"type", "string"}}}}},
                            {"required", {"address", "length", "hex"}}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) {
      return std::unexpected(tools::invalid("Arguments must be an object"));
    }
    mcp::ToolError error{};
    const auto session = tools::require_session(arguments, processes_, error);
    if (!session) {
      return std::unexpected(std::move(error));
    }
    auto address = tools::unsigned_value(arguments, "address");
    auto length = tools::unsigned_value(arguments, "length");
    if (!address) {
      return std::unexpected(std::move(address.error()));
    }
    if (!length) {
      return std::unexpected(std::move(length.error()));
    }
    if (*length == 0 || *length > 65536) {
      return std::unexpected(tools::invalid("length must be between 1 and 65536"));
    }
    if (*address > std::numeric_limits<std::uint64_t>::max() - *length) {
      return std::unexpected(tools::invalid("Address range overflows 64-bit virtual address space"));
    }
    auto bytes = processes_->read(*session, *address, static_cast<std::size_t>(*length));
    if (!bytes) {
      return std::unexpected(tools::process_error(bytes.error()));
    }
    return Json{{"address", tools::hex_u64(*address)},
                {"length", bytes->size()},
                {"hex", tools::hex_bytes(*bytes)}};
  }

 private:
  std::shared_ptr<process::ProcessManager> processes_;
};

class DisassembleMemoryTool final : public mcp::Tool {
 public:
  DisassembleMemoryTool(std::shared_ptr<process::ProcessManager> processes,
                        std::shared_ptr<disasm::Disassembler> disassembler)
      : processes_(std::move(processes)), disassembler_(std::move(disassembler)) {}
  std::string_view name() const noexcept override { return "disassemble_memory"; }
  std::string_view description() const noexcept override {
    return "Decode live x86/x64 process memory with Zydis. Returns instruction bytes, formatted text, semantic category, branch type, structured operands, resolved relative targets, and registers read or written.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{
        {"type", "object"},
        {"properties", {{"session_id", tools::session_schema()},
                        {"address", tools::address_schema()},
                        {"instruction_count", {{"type", "integer"}, {"minimum", 1},
                                               {"maximum", 512}, {"default", 32},
                                               {"description", "Maximum decoded instruction count."}}},
                        {"mode", {{"type", "string"}, {"enum", {"auto", "x86", "x64"}},
                                  {"default", "auto"}, {"description", "Decoder mode; auto uses the attached process architecture."}}},
                        {"syntax", {{"type", "string"}, {"enum", {"intel", "att"}},
                                    {"default", "intel"}, {"description", "Rendered assembly syntax. Structured operands are syntax-independent."}}}}},
        {"required", {"session_id", "address"}},
        {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"},
                            {"properties", {{"start_address", {{"type", "string"}}},
                                            {"mode", {{"type", "string"}}},
                                            {"instructions", {{"type", "array"}}}}},
                            {"required", {"start_address", "mode", "instructions"}}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) {
      return std::unexpected(tools::invalid("Arguments must be an object"));
    }
    mcp::ToolError error{};
    const auto session = tools::require_session(arguments, processes_, error);
    if (!session) {
      return std::unexpected(std::move(error));
    }
    auto address = tools::unsigned_value(arguments, "address");
    if (!address) {
      return std::unexpected(std::move(address.error()));
    }
    const auto count = arguments.value("instruction_count", std::size_t{32});
    if (count == 0 || count > 512) {
      return std::unexpected(tools::invalid("instruction_count must be between 1 and 512"));
    }
    const auto mode_name = arguments.value("mode", std::string{"auto"});
    const auto syntax_name = arguments.value("syntax", std::string{"intel"});
    disasm::Mode mode{};
    if (mode_name == "x86" || (mode_name == "auto" && session->architecture() == process::Architecture::x86)) {
      mode = disasm::Mode::x86;
    } else if (mode_name == "x64" || (mode_name == "auto" && session->architecture() == process::Architecture::x64)) {
      mode = disasm::Mode::x64;
    } else {
      return std::unexpected(tools::invalid("Zydis supports x86/x64 sessions; specify mode when auto detection is unavailable",
                                            {{"detected_architecture", process::to_string(session->architecture())}}));
    }
    if (syntax_name != "intel" && syntax_name != "att") {
      return std::unexpected(tools::invalid("syntax must be intel or att"));
    }

    auto regions = processes_->query_regions(*session, *address, 1);
    if (!regions || regions->empty()) {
      return std::unexpected(regions ? tools::invalid("Address is outside the target address space")
                                     : tools::process_error(regions.error()));
    }
    const auto& region = regions->front();
    if (!region.readable || *address < region.base) {
      return std::unexpected(tools::invalid("Address does not reference readable committed memory",
                                            {{"address", tools::hex_u64(*address)}}));
    }
    const auto available = region.base + region.size - *address;
    constexpr std::uint64_t max_instruction_bytes = 15;
    const auto requested = std::min<std::uint64_t>(count * max_instruction_bytes, 65536);
    const auto byte_count = static_cast<std::size_t>(std::min(available, requested));
    auto bytes = processes_->read(*session, *address, byte_count);
    if (!bytes) {
      return std::unexpected(tools::process_error(bytes.error()));
    }
    const auto syntax = syntax_name == "intel" ? disasm::Syntax::intel : disasm::Syntax::att;
    auto decoded = disassembler_->decode(*bytes, *address, count, mode, syntax);
    if (!decoded) {
      return std::unexpected(mcp::ToolError{
          .code = mcp::ToolErrorCode::invalid_arguments,
          .message = decoded.error().message,
          .details = {{"failure_address", tools::hex_u64(*address + decoded.error().offset)},
                      {"decoded_offset", decoded.error().offset}}});
    }
    Json instructions = Json::array();
    for (const auto& instruction : *decoded) {
      instructions.push_back(instruction_json(instruction));
    }
    return Json{{"start_address", tools::hex_u64(*address)},
                {"mode", mode == disasm::Mode::x64 ? "x64" : "x86"},
                {"syntax", syntax_name},
                {"instructions", std::move(instructions)}};
  }

 private:
  std::shared_ptr<process::ProcessManager> processes_;
  std::shared_ptr<disasm::Disassembler> disassembler_;
};

}  // namespace

void register_memory_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<process::ProcessManager>& processes,
    const std::shared_ptr<disasm::Disassembler>& disassembler) {
  const bool added = registry.add(std::make_unique<QueryMemoryRegionsTool>(processes)) &&
                     registry.add(std::make_unique<ReadMemoryTool>(processes)) &&
                     registry.add(std::make_unique<DisassembleMemoryTool>(processes, disassembler));
  if (!added) {
    std::terminate();
  }
}

}  // namespace reverseplugin
