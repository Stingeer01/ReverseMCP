#include "reverseplugin/tools.hpp"

#include <algorithm>
#include <cctype>
#include <memory>

#include "tool_support.hpp"

namespace reverseplugin {
namespace {

using mcp::Json;

std::string lowercase(std::string value) {
  std::ranges::transform(value, value.begin(), [](unsigned char character) {
    return static_cast<char>(std::tolower(character));
  });
  return value;
}

class ListProcessesTool final : public mcp::Tool {
 public:
  explicit ListProcessesTool(std::shared_ptr<process::ProcessManager> processes)
      : processes_(std::move(processes)) {}

  std::string_view name() const noexcept override { return "list_processes"; }
  std::string_view description() const noexcept override {
    return "List running Windows processes with PID, parent PID, thread count, and executable name. Use name_contains to narrow large process lists before attach_process.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{
        {"type", "object"},
        {"properties",
         {{"name_contains", {{"type", "string"},
                             {"description", "Optional case-insensitive executable-name substring."}}},
          {"limit", {{"type", "integer"}, {"minimum", 1}, {"maximum", 1000},
                     {"default", 100}, {"description", "Maximum number of matching processes returned."}}}}},
        {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{
        {"type", "object"},
        {"properties", {{"processes", {{"type", "array"}}},
                        {"returned", {{"type", "integer"}}},
                        {"truncated", {{"type", "boolean"}}}}},
        {"required", {"processes", "returned", "truncated"}}};
    return value;
  }
  const Json& annotations() const noexcept override {
    return tools::read_only_annotations();
  }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) {
      return std::unexpected(tools::invalid("Arguments must be an object"));
    }
    const auto limit = arguments.value("limit", std::size_t{100});
    if (limit == 0 || limit > 1000) {
      return std::unexpected(tools::invalid("limit must be between 1 and 1000"));
    }
    std::string filter;
    if (const auto entry = arguments.find("name_contains"); entry != arguments.end()) {
      if (!entry->is_string()) {
        return std::unexpected(tools::invalid("name_contains must be a string"));
      }
      filter = lowercase(entry->get<std::string>());
    }

    auto processes = processes_->list_processes();
    if (!processes) {
      return std::unexpected(tools::process_error(processes.error()));
    }
    Json items = Json::array();
    bool truncated = false;
    for (const auto& process : *processes) {
      if (!filter.empty() && lowercase(process.name).find(filter) == std::string::npos) {
        continue;
      }
      if (items.size() == limit) {
        truncated = true;
        break;
      }
      items.push_back({{"pid", process.pid},
                       {"parent_pid", process.parent_pid},
                       {"thread_count", process.thread_count},
                       {"name", process.name}});
    }
    const auto returned = items.size();
    return Json{{"processes", std::move(items)},
                {"returned", returned},
                {"truncated", truncated}};
  }

 private:
  std::shared_ptr<process::ProcessManager> processes_;
};

class AttachProcessTool final : public mcp::Tool {
 public:
  explicit AttachProcessTool(std::shared_ptr<process::ProcessManager> processes)
      : processes_(std::move(processes)) {}

  std::string_view name() const noexcept override { return "attach_process"; }
  std::string_view description() const noexcept override {
    return "Open a reusable read-only process session. The server requests query and memory-read rights only; this does not start a debugger or modify the process.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"},
                            {"properties", {{"pid", {{"type", "integer"}, {"minimum", 1},
                                                       {"description", "Windows process identifier from list_processes."}}}}},
                            {"required", {"pid"}},
                            {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"},
                            {"properties", {{"session_id", tools::session_schema()},
                                            {"pid", {{"type", "integer"}}},
                                            {"architecture", {{"type", "string"}}},
                                            {"image_path", {{"type", "string"}}}}},
                            {"required", {"session_id", "pid", "architecture", "image_path"}}};
    return value;
  }
  const Json& annotations() const noexcept override {
    static const Json value{{"readOnlyHint", true}, {"destructiveHint", false},
                            {"idempotentHint", false}, {"openWorldHint", false}};
    return value;
  }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) {
      return std::unexpected(tools::invalid("Arguments must be an object"));
    }
    auto pid = tools::unsigned_value(arguments, "pid");
    if (!pid || *pid == 0 || *pid > std::numeric_limits<std::uint32_t>::max()) {
      return std::unexpected(pid ? tools::invalid("pid is outside the Windows PID range")
                                 : std::move(pid.error()));
    }
    auto session = processes_->attach(static_cast<std::uint32_t>(*pid));
    if (!session) {
      return std::unexpected(tools::process_error(session.error()));
    }
    return Json{{"session_id", (*session)->id()},
                {"pid", (*session)->pid()},
                {"architecture", process::to_string((*session)->architecture())},
                {"image_path", (*session)->image_path()}};
  }

 private:
  std::shared_ptr<process::ProcessManager> processes_;
};

class DetachProcessTool final : public mcp::Tool {
 public:
  explicit DetachProcessTool(std::shared_ptr<process::ProcessManager> processes)
      : processes_(std::move(processes)) {}
  std::string_view name() const noexcept override { return "detach_process"; }
  std::string_view description() const noexcept override {
    return "Close a process session and release its cached Windows handle. Calls already running against the session finish safely.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"},
                            {"properties", {{"session_id", tools::session_schema()}}},
                            {"required", {"session_id"}},
                            {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"},
                            {"properties", {{"detached", {{"type", "boolean"}}}}},
                            {"required", {"detached"}}};
    return value;
  }
  const Json& annotations() const noexcept override {
    static const Json value{{"readOnlyHint", true}, {"destructiveHint", false},
                            {"idempotentHint", true}, {"openWorldHint", false}};
    return value;
  }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) {
      return std::unexpected(tools::invalid("Arguments must be an object"));
    }
    auto id = tools::unsigned_value(arguments, "session_id");
    if (!id) {
      return std::unexpected(std::move(id.error()));
    }
    return Json{{"detached", processes_->detach(*id)}};
  }

 private:
  std::shared_ptr<process::ProcessManager> processes_;
};

class ListModulesTool final : public mcp::Tool {
 public:
  explicit ListModulesTool(std::shared_ptr<process::ProcessManager> processes)
      : processes_(std::move(processes)) {}
  std::string_view name() const noexcept override { return "list_modules"; }
  std::string_view description() const noexcept override {
    return "List executable images and DLLs loaded in an attached process, including exact base address, image size, and path.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"},
                            {"properties", {{"session_id", tools::session_schema()}}},
                            {"required", {"session_id"}},
                            {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"},
                            {"properties", {{"modules", {{"type", "array"}}}}},
                            {"required", {"modules"}}};
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
    auto modules = processes_->list_modules(*session);
    if (!modules) {
      return std::unexpected(tools::process_error(modules.error()));
    }
    Json items = Json::array();
    for (const auto& module : *modules) {
      items.push_back({{"name", module.name}, {"path", module.path},
                       {"base_address", tools::hex_u64(module.base)},
                       {"size", module.size},
                       {"end_address", tools::hex_u64(module.base + module.size)}});
    }
    return Json{{"modules", std::move(items)}};
  }

 private:
  std::shared_ptr<process::ProcessManager> processes_;
};

}  // namespace

void register_process_control_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<process::ProcessManager>& processes) {
  const bool added = registry.add(std::make_unique<ListProcessesTool>(processes)) &&
                     registry.add(std::make_unique<AttachProcessTool>(processes)) &&
                     registry.add(std::make_unique<DetachProcessTool>(processes)) &&
                     registry.add(std::make_unique<ListModulesTool>(processes));
  if (!added) {
    std::terminate();
  }
}

}  // namespace reverseplugin
