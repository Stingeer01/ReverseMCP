#include "reverseplugin/tools.hpp"

#include <memory>
#include <limits>
#include <optional>

#include "tool_support.hpp"

namespace reverseplugin {
namespace {

using mcp::Json;

std::shared_ptr<debug::DebugSession> debug_session(
    const Json& arguments, const std::shared_ptr<debug::DebugEngine>& engine,
    mcp::ToolError& error) {
  auto id = tools::unsigned_value(arguments, "debug_session_id");
  if (!id) {
    error = std::move(id.error());
    return nullptr;
  }
  auto session = engine->session(*id);
  if (!session)
    error = tools::invalid("Unknown or detached debugger session",
                           {{"debug_session_id", *id}});
  return session;
}

Json session_property() {
  return {{"type", "integer"}, {"minimum", 1},
          {"description", "Debugger session identifier returned by debug_attach."}};
}

class ListDebugThreadsTool final : public mcp::Tool {
 public:
  explicit ListDebugThreadsTool(std::shared_ptr<debug::DebugEngine> engine)
      : engine_(std::move(engine)) {}
  std::string_view name() const noexcept override { return "list_debug_threads"; }
  std::string_view description() const noexcept override {
    return "List every thread owned by the debug target. Use these thread identifiers for register contexts and per-thread hardware breakpoints.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"},
                            {"properties", {{"debug_session_id", session_property()}}},
                            {"required", {"debug_session_id"}},
                            {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"},
                            {"properties", {{"threads", {{"type", "array"}}}}},
                            {"required", {"threads"}}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{};
    auto session = debug_session(arguments, engine_, error);
    if (!session) return std::unexpected(std::move(error));
    auto threads = session->threads();
    if (!threads)
      return std::unexpected(mcp::ToolError{mcp::ToolErrorCode::unavailable,
                                             threads.error().message,
                                             {{"native_code", threads.error().native_code}}});
    Json result = Json::array();
    for (const auto& thread : *threads)
      result.push_back({{"thread_id", thread.id},
                        {"base_priority", thread.base_priority}});
    return Json{{"threads", std::move(result)}};
  }
 private:
  std::shared_ptr<debug::DebugEngine> engine_;
};

class SingleStepTool final : public mcp::Tool {
 public:
  explicit SingleStepTool(std::shared_ptr<debug::DebugEngine> engine)
      : engine_(std::move(engine)) {}
  std::string_view name() const noexcept override { return "single_step"; }
  std::string_view description() const noexcept override {
    return "Execute exactly one instruction in the thread that produced the current paused event. For software breakpoints the engine also restores and reinserts INT3 correctly.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"},
                            {"properties", {{"debug_session_id", session_property()}}},
                            {"required", {"debug_session_id"}},
                            {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"},
                            {"properties", {{"stepping", {{"type", "boolean"}}}}},
                            {"required", {"stepping"}}};
    return value;
  }
  const Json& annotations() const noexcept override {
    static const Json value{{"readOnlyHint", false}, {"destructiveHint", false},
                            {"idempotentHint", false}, {"openWorldHint", false}};
    return value;
  }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{};
    auto session = debug_session(arguments, engine_, error);
    if (!session) return std::unexpected(std::move(error));
    auto stepped = session->single_step();
    if (!stepped)
      return std::unexpected(mcp::ToolError{mcp::ToolErrorCode::unavailable,
                                             stepped.error().message,
                                             {{"native_code", stepped.error().native_code}}});
    return Json{{"stepping", true}};
  }
 private:
  std::shared_ptr<debug::DebugEngine> engine_;
};

class SetHardwareBreakpointTool final : public mcp::Tool {
 public:
  explicit SetHardwareBreakpointTool(std::shared_ptr<debug::DebugEngine> engine)
      : engine_(std::move(engine)) {}
  std::string_view name() const noexcept override { return "set_hardware_breakpoint"; }
  std::string_view description() const noexcept override {
    return "Configure one of the CPU's four per-thread debug-register breakpoints without modifying target code. Supports execute, write, and read/write access traps with validated size and alignment.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"debug_session_id", session_property()},
      {"thread_id", {{"type", "integer"}, {"minimum", 1}, {"description", "Target thread identifier returned by list_debug_threads."}}},
      {"address", tools::address_schema()},
      {"access", {{"type", "string"}, {"enum", {"execute", "write", "read_write"}},
                   {"default", "execute"}, {"description", "Memory access that triggers the breakpoint."}}},
      {"size", {{"type", "integer"}, {"enum", {1, 2, 4, 8}}, {"default", 1},
                 {"description", "Watched byte width. Execute requires 1; data addresses must be naturally aligned."}}},
      {"slot", {{"type", "integer"}, {"minimum", 0}, {"maximum", 3},
                 {"description", "Optional DR0..DR3 slot. Omit to select the first free slot."}}}}},
      {"required", {"debug_session_id", "thread_id", "address"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"breakpoint_id", {{"type", "integer"}}}, {"thread_id", {{"type", "integer"}}},
      {"slot", {{"type", "integer"}}}, {"address", {{"type", "string"}}},
      {"access", {{"type", "string"}}}, {"size", {{"type", "integer"}}}}},
      {"required", {"breakpoint_id", "thread_id", "slot", "address", "access", "size"}}};
    return value;
  }
  const Json& annotations() const noexcept override {
    static const Json value{{"readOnlyHint", false}, {"destructiveHint", false},
                            {"idempotentHint", false}, {"openWorldHint", false}};
    return value;
  }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) return std::unexpected(tools::invalid("Arguments must be an object"));
    mcp::ToolError error{};
    auto session = debug_session(arguments, engine_, error);
    if (!session) return std::unexpected(std::move(error));
    auto thread_id = tools::unsigned_value(arguments, "thread_id");
    auto address = tools::unsigned_value(arguments, "address");
    if (!thread_id) return std::unexpected(std::move(thread_id.error()));
    if (!address) return std::unexpected(std::move(address.error()));
    if (*thread_id > (std::numeric_limits<std::uint32_t>::max)())
      return std::unexpected(tools::invalid("thread_id exceeds 32 bits"));
    const auto access_name = arguments.value("access", std::string{"execute"});
    debug::HardwareBreakpointAccess access{};
    if (access_name == "execute") access = debug::HardwareBreakpointAccess::execute;
    else if (access_name == "write") access = debug::HardwareBreakpointAccess::write;
    else if (access_name == "read_write") access = debug::HardwareBreakpointAccess::read_write;
    else return std::unexpected(tools::invalid("access must be execute, write, or read_write"));
    const auto size = arguments.value("size", std::uint8_t{1});
    std::optional<std::uint8_t> slot;
    if (arguments.contains("slot")) {
      const auto value = arguments.at("slot").get<std::uint32_t>();
      if (value > 3) return std::unexpected(tools::invalid("slot must be 0..3"));
      slot = static_cast<std::uint8_t>(value);
    }
    auto breakpoint = session->add_hardware_breakpoint(
        static_cast<std::uint32_t>(*thread_id), *address, access, size, slot);
    if (!breakpoint)
      return std::unexpected(mcp::ToolError{mcp::ToolErrorCode::unavailable,
        breakpoint.error().message, {{"native_code", breakpoint.error().native_code}}});
    return Json{{"breakpoint_id", breakpoint->id}, {"thread_id", breakpoint->thread_id},
                {"slot", breakpoint->slot}, {"address", tools::hex_u64(breakpoint->address)},
                {"access", debug::to_string(breakpoint->access)}, {"size", breakpoint->size}};
  }
 private:
  std::shared_ptr<debug::DebugEngine> engine_;
};

class RemoveHardwareBreakpointTool final : public mcp::Tool {
 public:
  explicit RemoveHardwareBreakpointTool(std::shared_ptr<debug::DebugEngine> engine)
      : engine_(std::move(engine)) {}
  std::string_view name() const noexcept override { return "remove_hardware_breakpoint"; }
  std::string_view description() const noexcept override {
    return "Clear a hardware breakpoint and release its per-thread debug-register slot.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"debug_session_id", session_property()}, {"breakpoint_id", {{"type", "integer"}, {"minimum", 1},
       {"description", "Identifier returned by set_hardware_breakpoint."}}}}},
      {"required", {"debug_session_id", "breakpoint_id"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {{"removed", {{"type", "boolean"}}}}},
                            {"required", {"removed"}}}; return value;
  }
  const Json& annotations() const noexcept override {
    static const Json value{{"readOnlyHint", false}, {"destructiveHint", false},
                            {"idempotentHint", true}, {"openWorldHint", false}}; return value;
  }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{}; auto session = debug_session(arguments, engine_, error);
    if (!session) return std::unexpected(std::move(error));
    auto id = tools::unsigned_value(arguments, "breakpoint_id");
    if (!id) return std::unexpected(std::move(id.error()));
    auto removed = session->remove_hardware_breakpoint(*id);
    if (!removed) return std::unexpected(mcp::ToolError{mcp::ToolErrorCode::unavailable,
      removed.error().message, {{"native_code", removed.error().native_code}}});
    return Json{{"removed", *removed}};
  }
 private: std::shared_ptr<debug::DebugEngine> engine_;
};

class ThreadStateTool final : public mcp::Tool {
 public:
  ThreadStateTool(std::shared_ptr<debug::DebugEngine> engine, bool suspend)
      : engine_(std::move(engine)), suspend_(suspend) {}
  std::string_view name() const noexcept override {
    return suspend_ ? "suspend_debug_thread" : "resume_debug_thread";
  }
  std::string_view description() const noexcept override {
    return suspend_ ? "Increment a target thread's suspend count and track ownership so debugger detach can safely undo it."
                    : "Resume one suspension previously created by this debugger session; refuses to alter suspension counts it does not own.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"debug_session_id", session_property()}, {"thread_id", {{"type", "integer"}, {"minimum", 1},
       {"description", "Target thread identifier returned by list_debug_threads."}}}}},
      {"required", {"debug_session_id", "thread_id"}}, {"additionalProperties", false}}; return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"thread_id", {{"type", "integer"}}}, {"previous_suspend_count", {{"type", "integer"}}},
      {"state", {{"type", "string"}}}}}, {"required", {"thread_id", "previous_suspend_count", "state"}}}; return value;
  }
  const Json& annotations() const noexcept override {
    static const Json value{{"readOnlyHint", false}, {"destructiveHint", false},
                            {"idempotentHint", false}, {"openWorldHint", false}}; return value;
  }
  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{}; auto session = debug_session(arguments, engine_, error);
    if (!session) return std::unexpected(std::move(error));
    auto id = tools::unsigned_value(arguments, "thread_id");
    if (!id || *id > (std::numeric_limits<std::uint32_t>::max)())
      return std::unexpected(id ? tools::invalid("thread_id exceeds 32 bits") : std::move(id.error()));
    auto result = suspend_ ? session->suspend_thread(static_cast<std::uint32_t>(*id))
                           : session->resume_thread(static_cast<std::uint32_t>(*id));
    if (!result) return std::unexpected(mcp::ToolError{mcp::ToolErrorCode::unavailable,
      result.error().message, {{"native_code", result.error().native_code}}});
    return Json{{"thread_id", *id}, {"previous_suspend_count", *result},
                {"state", suspend_ ? "suspended" : "resumed"}};
  }
 private:
  std::shared_ptr<debug::DebugEngine> engine_; bool suspend_;
};

}  // namespace

void register_debug_execution_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<debug::DebugEngine>& debugger) {
  if (!registry.add(std::make_unique<ListDebugThreadsTool>(debugger)) ||
      !registry.add(std::make_unique<SingleStepTool>(debugger)) ||
      !registry.add(std::make_unique<SetHardwareBreakpointTool>(debugger)) ||
      !registry.add(std::make_unique<RemoveHardwareBreakpointTool>(debugger)) ||
      !registry.add(std::make_unique<ThreadStateTool>(debugger, true)) ||
      !registry.add(std::make_unique<ThreadStateTool>(debugger, false)))
    std::terminate();
}

}  // namespace reverseplugin
