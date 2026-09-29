#include "reverseplugin/tools.hpp"

#include <limits>
#include <memory>

#include "tool_support.hpp"

namespace reverseplugin {
namespace {

using mcp::Json;

class GetStackTraceTool final : public mcp::Tool {
 public:
  explicit GetStackTraceTool(std::shared_ptr<debug::DebugEngine> debugger)
      : debugger_(std::move(debugger)) {}
  std::string_view name() const noexcept override { return "get_stack_trace"; }
  std::string_view description() const noexcept override {
    return "Walk a paused x86/x64 target thread with Windows unwind metadata and DbgHelp symbols. Returns exact frame addresses, stack/frame pointers, module bases, symbols, and symbol displacements.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"debug_session_id", {{"type", "integer"}, {"minimum", 1},
        {"description", "Debugger session identifier returned by debug_attach."}}},
      {"thread_id", {{"type", "integer"}, {"minimum", 0}, {"default", 0},
        {"description", "Paused thread identifier, or 0 for the thread that produced the current event."}}},
      {"max_frames", {{"type", "integer"}, {"minimum", 1}, {"maximum", 256},
        {"default", 64}, {"description", "Maximum unwind frames to return."}}}}},
      {"required", {"debug_session_id"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"thread_id", {{"type", "integer"}, {"description", "Resolved paused thread identifier."}}},
      {"frames", {{"type", "array"}, {"description", "Frames ordered from the current instruction outward."},
        {"items", {{"type", "object"}, {"properties", {
          {"index", {{"type", "integer"}, {"description", "Zero-based frame depth."}}},
          {"address", {{"type", "string"}, {"description", "Exact frame instruction address."}}},
          {"stack_pointer", {{"type", "string"}, {"description", "Stack pointer at this frame."}}},
          {"frame_pointer", {{"type", "string"}, {"description", "Frame pointer reported by the unwinder."}}},
          {"module_base", {{"type", "string"}, {"description", "Owning module base, or 0x0 when unresolved."}}},
          {"module", {{"type", "string"}, {"description", "DbgHelp module name when available."}}},
          {"symbol", {{"type", "string"}, {"description", "Undecorated symbol name when available."}}},
          {"symbol_displacement", {{"type", "integer"}, {"description", "Byte displacement from the symbol."}}}}},
          {"required", {"index", "address", "stack_pointer", "frame_pointer", "module_base", "module", "symbol", "symbol_displacement"}},
          {"additionalProperties", false}}}}},
      {"frame_count", {{"type", "integer"}, {"description", "Number of returned frames."}}}}},
      {"required", {"thread_id", "frames", "frame_count"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object())
      return std::unexpected(tools::invalid("Arguments must be an object"));
    auto session_id = tools::unsigned_value(arguments, "debug_session_id");
    if (!session_id) return std::unexpected(std::move(session_id.error()));
    auto session = debugger_->session(*session_id);
    if (!session)
      return std::unexpected(tools::invalid("Unknown or detached debugger session"));
    auto thread_id = arguments.value("thread_id", std::uint32_t{0});
    const auto max_frames = arguments.value("max_frames", std::size_t{64});
    if (thread_id == 0) {
      auto current = session->paused_thread_id();
      if (!current)
        return std::unexpected(mcp::ToolError{mcp::ToolErrorCode::unavailable,
          current.error().message, {{"native_code", current.error().native_code}}});
      thread_id = *current;
    }
    auto frames = session->stack_trace(thread_id, max_frames);
    if (!frames)
      return std::unexpected(mcp::ToolError{mcp::ToolErrorCode::unavailable,
        frames.error().message, {{"native_code", frames.error().native_code}}});
    Json result = Json::array();
    for (std::size_t index = 0; index < frames->size(); ++index) {
      const auto& frame = (*frames)[index];
      result.push_back({{"index", index}, {"address", tools::hex_u64(frame.address)},
        {"stack_pointer", tools::hex_u64(frame.stack_pointer)},
        {"frame_pointer", tools::hex_u64(frame.frame_pointer)},
        {"module_base", tools::hex_u64(frame.module_base)}, {"module", frame.module},
        {"symbol", frame.symbol}, {"symbol_displacement", frame.displacement}});
    }
    const auto count = result.size();
    return Json{{"thread_id", thread_id}, {"frames", std::move(result)},
                {"frame_count", count}};
  }
 private:
  std::shared_ptr<debug::DebugEngine> debugger_;
};

}  // namespace

void register_debug_stack_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<debug::DebugEngine>& debugger) {
  if (!registry.add(std::make_unique<GetStackTraceTool>(debugger))) std::terminate();
}

}  // namespace reverseplugin
