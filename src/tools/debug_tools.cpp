#include "reverseplugin/tools.hpp"

#include <chrono>
#include <functional>
#include <limits>
#include <memory>

#include "tool_support.hpp"

namespace reverseplugin {
namespace {

using mcp::Json;
using Handler = std::function<mcp::ToolResult(const Json&)>;

class DebugTool final : public mcp::Tool {
 public:
  DebugTool(std::string name, std::string description, Json input, Json output,
            Json annotations, Handler handler)
      : name_(std::move(name)), description_(std::move(description)),
        input_(std::move(input)), output_(std::move(output)),
        annotations_(std::move(annotations)), handler_(std::move(handler)) {}

  std::string_view name() const noexcept override { return name_; }
  std::string_view description() const noexcept override { return description_; }
  const Json& input_schema() const noexcept override { return input_; }
  const Json& output_schema() const noexcept override { return output_; }
  const Json& annotations() const noexcept override { return annotations_; }
  mcp::ToolResult invoke(const Json& arguments) const override {
    return handler_(arguments);
  }

 private:
  std::string name_;
  std::string description_;
  Json input_;
  Json output_;
  Json annotations_;
  Handler handler_;
};

Json debugger_annotations(bool idempotent) {
  return {{"readOnlyHint", false}, {"destructiveHint", false},
          {"idempotentHint", idempotent}, {"openWorldHint", false}};
}

Json debug_session_schema() {
  return {{"type", "integer"}, {"minimum", 1},
          {"description", "Debugger session identifier returned by debug_attach."}};
}

std::shared_ptr<debug::DebugSession> require_debug_session(
    const Json& arguments, const std::shared_ptr<debug::DebugEngine>& debugger,
    mcp::ToolError& error) {
  auto id = tools::unsigned_value(arguments, "debug_session_id");
  if (!id) {
    error = std::move(id.error());
    return nullptr;
  }
  auto session = debugger->session(*id);
  if (!session) {
    error = tools::invalid("Unknown or detached debugger session",
                           {{"debug_session_id", *id}});
  }
  return session;
}

mcp::ToolError debug_error(const debug::Error& error) {
  return {.code = mcp::ToolErrorCode::unavailable,
          .message = error.message,
          .details = {{"native_code", error.native_code}}};
}

Json event_json(const debug::Event& event) {
  Json result{{"sequence", event.sequence}, {"type", event.type},
              {"process_id", event.process_id}, {"thread_id", event.thread_id},
              {"exception_code", event.exception_code},
              {"address", tools::hex_u64(event.address)},
              {"first_chance", event.first_chance}};
  if (event.breakpoint_id) {
    result["breakpoint_id"] = *event.breakpoint_id;
  }
  return result;
}

Json object_schema(Json properties, Json required = Json::array()) {
  Json result{{"type", "object"}, {"properties", std::move(properties)},
              {"additionalProperties", false}};
  if (!required.empty()) {
    result["required"] = std::move(required);
  }
  return result;
}

Json generic_output(std::initializer_list<std::string_view> required) {
  Json names = Json::array();
  for (const auto name : required) {
    names.push_back(name);
  }
  return {{"type", "object"}, {"required", std::move(names)}};
}

}  // namespace

void register_debug_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<debug::DebugEngine>& debugger) {
  auto attach = std::make_unique<DebugTool>(
      "debug_attach",
      "Attach the native Windows debugger to a running x86/x64 process. This creates a dedicated event-loop thread and does not terminate the target when the MCP server exits.",
      object_schema({{"pid", {{"type", "integer"}, {"minimum", 1},
                               {"description", "Windows process identifier to debug."}}}}, {"pid"}),
      generic_output({"debug_session_id", "pid"}), debugger_annotations(false),
      [debugger](const Json& arguments) -> mcp::ToolResult {
        if (!arguments.is_object()) {
          return std::unexpected(tools::invalid("Arguments must be an object"));
        }
        auto pid = tools::unsigned_value(arguments, "pid");
        if (!pid) {
          return std::unexpected(std::move(pid.error()));
        }
        if (*pid == 0 || *pid > std::numeric_limits<std::uint32_t>::max()) {
          return std::unexpected(tools::invalid("pid is outside the Windows PID range"));
        }
        auto session = debugger->attach(static_cast<std::uint32_t>(*pid));
        if (!session) {
          return std::unexpected(debug_error(session.error()));
        }
        return Json{{"debug_session_id", (*session)->id()}, {"pid", (*session)->pid()}};
      });

  auto detach = std::make_unique<DebugTool>(
      "debug_detach",
      "Restore all active software breakpoints, continue any paused event, detach the debugger, and leave the target process running.",
      object_schema({{"debug_session_id", debug_session_schema()}}, {"debug_session_id"}),
      generic_output({"detached"}), debugger_annotations(true),
      [debugger](const Json& arguments) -> mcp::ToolResult {
        auto id = tools::unsigned_value(arguments, "debug_session_id");
        if (!id) {
          return std::unexpected(std::move(id.error()));
        }
        auto detached = debugger->detach(*id);
        if (!detached) {
          return std::unexpected(debug_error(detached.error()));
        }
        return Json{{"detached", *detached}};
      });

  auto set_breakpoint = std::make_unique<DebugTool>(
      "set_software_breakpoint",
      "Install a managed INT3 software breakpoint at an executable virtual address. The original byte is cached, restored on hit, and reinserted after an internal single-step.",
      object_schema({{"debug_session_id", debug_session_schema()},
                     {"address", tools::address_schema()}},
                    {"debug_session_id", "address"}),
      generic_output({"breakpoint_id", "address", "enabled"}),
      debugger_annotations(false),
      [debugger](const Json& arguments) -> mcp::ToolResult {
        mcp::ToolError error{};
        auto session = require_debug_session(arguments, debugger, error);
        if (!session) {
          return std::unexpected(std::move(error));
        }
        auto address = tools::unsigned_value(arguments, "address");
        if (!address) {
          return std::unexpected(std::move(address.error()));
        }
        auto breakpoint = session->add_breakpoint(*address);
        if (!breakpoint) {
          return std::unexpected(debug_error(breakpoint.error()));
        }
        return Json{{"breakpoint_id", breakpoint->id},
                    {"address", tools::hex_u64(breakpoint->address)},
                    {"enabled", breakpoint->enabled}};
      });

  auto remove_breakpoint = std::make_unique<DebugTool>(
      "remove_breakpoint",
      "Remove a managed software breakpoint and restore its original instruction byte. Returns false when the identifier is already absent.",
      object_schema({{"debug_session_id", debug_session_schema()},
                     {"breakpoint_id", {{"type", "integer"}, {"minimum", 1},
                                        {"description", "Breakpoint identifier returned by set_software_breakpoint."}}}},
                    {"debug_session_id", "breakpoint_id"}),
      generic_output({"removed"}), debugger_annotations(true),
      [debugger](const Json& arguments) -> mcp::ToolResult {
        mcp::ToolError error{};
        auto session = require_debug_session(arguments, debugger, error);
        if (!session) {
          return std::unexpected(std::move(error));
        }
        auto id = tools::unsigned_value(arguments, "breakpoint_id");
        if (!id) {
          return std::unexpected(std::move(id.error()));
        }
        auto removed = session->remove_breakpoint(*id);
        if (!removed) {
          return std::unexpected(debug_error(removed.error()));
        }
        return Json{{"removed", *removed}};
      });

  auto wait_event = std::make_unique<DebugTool>(
      "wait_debug_event",
      "Wait for the next queued debugger event without blocking the MCP input loop. Breakpoint and exception events leave the target paused until continue_debug_event is called.",
      object_schema({{"debug_session_id", debug_session_schema()},
                     {"timeout_ms", {{"type", "integer"}, {"minimum", 0},
                                     {"maximum", 30000}, {"default", 1000},
                                     {"description", "Maximum wait in milliseconds."}}}},
                    {"debug_session_id"}),
      generic_output({"timed_out"}), tools::read_only_annotations(),
      [debugger](const Json& arguments) -> mcp::ToolResult {
        mcp::ToolError error{};
        auto session = require_debug_session(arguments, debugger, error);
        if (!session) {
          return std::unexpected(std::move(error));
        }
        const auto timeout = arguments.value("timeout_ms", std::uint32_t{1000});
        if (timeout > 30000) {
          return std::unexpected(tools::invalid("timeout_ms must not exceed 30000"));
        }
        auto event = session->wait_event(std::chrono::milliseconds{timeout});
        if (!event) {
          return std::unexpected(debug_error(event.error()));
        }
        if (!*event) {
          return Json{{"timed_out", true}, {"event", nullptr}};
        }
        return Json{{"timed_out", false}, {"event", event_json(**event)}};
      });

  auto resume = std::make_unique<DebugTool>(
      "continue_debug_event",
      "Continue the currently paused debugger event. For managed breakpoint hits this performs the required trap-step and breakpoint reinsertion automatically.",
      object_schema({{"debug_session_id", debug_session_schema()},
                     {"handled", {{"type", "boolean"}, {"default", true},
                                  {"description", "Report an exception as handled; use false to pass unknown exceptions to the target."}}}},
                    {"debug_session_id"}),
      generic_output({"continued"}), debugger_annotations(false),
      [debugger](const Json& arguments) -> mcp::ToolResult {
        mcp::ToolError error{};
        auto session = require_debug_session(arguments, debugger, error);
        if (!session) {
          return std::unexpected(std::move(error));
        }
        const auto handled = arguments.value("handled", true);
        auto continued = session->resume(handled);
        if (!continued) {
          return std::unexpected(debug_error(continued.error()));
        }
        return Json{{"continued", true}};
      });

  auto get_context = std::make_unique<DebugTool>(
      "get_thread_context",
      "Read integer and control registers while the target is paused at a breakpoint or exception. Omit thread_id to inspect the thread that produced the current event.",
      object_schema({{"debug_session_id", debug_session_schema()},
                     {"thread_id", {{"type", "integer"}, {"minimum", 0}, {"default", 0},
                                    {"description", "Paused thread identifier, or 0 for the event thread."}}}},
                    {"debug_session_id"}),
      generic_output({"architecture", "registers"}), tools::read_only_annotations(),
      [debugger](const Json& arguments) -> mcp::ToolResult {
        mcp::ToolError error{};
        auto session = require_debug_session(arguments, debugger, error);
        if (!session) {
          return std::unexpected(std::move(error));
        }
        const auto thread_id = arguments.value("thread_id", std::uint32_t{0});
        auto context = session->registers(thread_id);
        if (!context) {
          return std::unexpected(debug_error(context.error()));
        }
        Json registers = Json::object();
        for (const auto& [name, value] : context->registers) {
          registers[name] = tools::hex_u64(value);
        }
        return Json{{"architecture", context->architecture},
                    {"registers", std::move(registers)}};
      });

  const bool added = registry.add(std::move(attach)) &&
                     registry.add(std::move(detach)) &&
                     registry.add(std::move(set_breakpoint)) &&
                     registry.add(std::move(remove_breakpoint)) &&
                     registry.add(std::move(wait_event)) &&
                     registry.add(std::move(resume)) &&
                     registry.add(std::move(get_context));
  if (!added) {
    std::terminate();
  }
}

}  // namespace reverseplugin
