#include "reverseplugin/tools.hpp"

#include <memory>

namespace reverseplugin {
namespace {

class ServerInfoTool final : public mcp::Tool {
 public:
  [[nodiscard]] std::string_view name() const noexcept override {
    return "get_server_info";
  }

  [[nodiscard]] std::string_view description() const noexcept override {
    return "Return the native MCP server version, supported feature modules, "
           "and runtime architecture. Use this before selecting advanced "
           "reverse-engineering tools.";
  }

  [[nodiscard]] const mcp::Json& input_schema() const noexcept override {
    static const mcp::Json schema{{"type", "object"},
                                  {"properties", mcp::Json::object()},
                                  {"additionalProperties", false}};
    return schema;
  }

  [[nodiscard]] const mcp::Json& output_schema() const noexcept override {
    static const mcp::Json schema{
        {"type", "object"},
        {"properties",
         {{"name", {{"type", "string"}, {"description", "Server identifier."}}},
          {"version", {{"type", "string"}, {"description", "Semantic version."}}},
          {"language", {{"type", "string"}, {"description", "Implementation language standard."}}},
          {"transport", {{"type", "string"}, {"description", "Active MCP transport."}}},
          {"execution", {{"type", "string"}, {"description", "Tool scheduling model."}}},
          {"modules", {{"type", "array"},
                       {"description", "Feature modules compiled into this server."},
                       {"items", {{"type", "string"}}}}}}},
        {"required", {"name", "version", "language", "transport", "execution", "modules"}},
        {"additionalProperties", false}};
    return schema;
  }

  [[nodiscard]] const mcp::Json& annotations() const noexcept override {
    static const mcp::Json value{{"title", "Get server information"},
                                 {"readOnlyHint", true},
                                 {"destructiveHint", false},
                                 {"idempotentHint", true},
                                 {"openWorldHint", false}};
    return value;
  }

  [[nodiscard]] mcp::ToolResult invoke(const mcp::Json& arguments) const override {
    if (!arguments.is_object() || !arguments.empty()) {
      return std::unexpected(mcp::ToolError{
          .code = mcp::ToolErrorCode::invalid_arguments,
          .message = "get_server_info does not accept arguments",
          .details = {{"received", arguments}},
      });
    }

    return mcp::Json{{"name", "reverseplugin"},
                     {"version", REVERSEPLUGIN_VERSION},
                     {"language", "C++23"},
                     {"transport", "stdio"},
                     {"execution", "fixed worker pool"},
                     {"modules", mcp::Json::array({"mcp_core", "process", "memory",
                                                   "memory_snapshots", "zydis", "debugger",
                                                   "stack_walking", "symbols", "pe_loader",
                                                   "static_cfg", "function_index", "xrefs",
                                                   "semantic_lifter", "c_like_pseudocode",
                                                   "string_index", "annotations", "persistent_cache",
                                                   "il2cpp_v38_v39", "il2cpp_native_mapping",
                                                   "engine_detection", "engine_artifact_index"})}};
  }
};

}  // namespace

void register_process_control_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<process::ProcessManager>& processes);
void register_memory_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<process::ProcessManager>& processes,
    const std::shared_ptr<disasm::Disassembler>& disassembler);
void register_memory_analysis_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<process::ProcessManager>& processes);
void register_memory_snapshot_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<process::ProcessManager>& processes);
void register_debug_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<debug::DebugEngine>& debugger);
void register_debug_execution_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<debug::DebugEngine>& debugger);
void register_debug_stack_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<debug::DebugEngine>& debugger);
void register_binary_analysis_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<disasm::Disassembler>& disassembler);
void register_il2cpp_tools(mcp::ToolRegistry& registry);
void register_engine_tools(mcp::ToolRegistry& registry);

void register_builtin_tools(
    mcp::ToolRegistry& registry,
    std::shared_ptr<process::ProcessManager> processes,
    std::shared_ptr<disasm::Disassembler> disassembler,
    std::shared_ptr<debug::DebugEngine> debugger) {
  if (!registry.add(std::make_unique<ServerInfoTool>())) {
    std::terminate();
  }
  register_process_control_tools(registry, processes);
  register_memory_tools(registry, processes, disassembler);
  register_memory_analysis_tools(registry, processes);
  register_memory_snapshot_tools(registry, processes);
  register_debug_tools(registry, debugger);
  register_debug_execution_tools(registry, debugger);
  register_debug_stack_tools(registry, debugger);
  register_binary_analysis_tools(registry, disassembler);
  register_engine_tools(registry);
  register_il2cpp_tools(registry);
}

}  // namespace reverseplugin
