#include "reverseplugin/mcp/server.hpp"

#include <algorithm>
#include <array>
#include <ranges>
#include <string_view>
#include <utility>

namespace reverseplugin::mcp {
namespace {

constexpr std::array supported_protocols{
    std::string_view{"2025-11-25"}, std::string_view{"2025-06-18"},
    std::string_view{"2025-03-26"}, std::string_view{"2024-11-05"}};

Json tool_error_json(const ToolError& error) {
  std::string_view code;
  switch (error.code) {
    case ToolErrorCode::invalid_arguments:
      code = "invalid_arguments";
      break;
    case ToolErrorCode::unavailable:
      code = "unavailable";
      break;
    case ToolErrorCode::internal:
      code = "internal";
      break;
  }
  return {{"code", code}, {"message", error.message}, {"details", error.details}};
}

Json tool_response(Json structured, bool is_error) {
  const auto text = structured.dump();
  return {{"content", {{{"type", "text"}, {"text", text}}}},
          {"structuredContent", std::move(structured)},
          {"isError", is_error}};
}

}  // namespace

Server::Server(ToolRegistry registry, std::istream& input, std::ostream& output,
               std::size_t worker_count)
    : registry_(std::move(registry)),
      input_(input),
      output_(output),
      workers_(worker_count) {}

int Server::run() {
  std::string message;
  message.reserve(4096);
  while (read_message(message)) {
    auto request = Json::parse(message, nullptr, false);
    if (request.is_discarded()) {
      write(error(nullptr, -32700, "Invalid JSON"));
      continue;
    }
    dispatch(std::move(request));
  }
  return input_.bad() ? 1 : 0;
}

bool Server::read_message(std::string& message) {
  message.clear();
  bool overflow = false;
  for (char value = 0; input_.get(value);) {
    if (value == '\n') {
      if (!message.empty() && message.back() == '\r') {
        message.pop_back();
      }
      if (overflow) {
        write(error(nullptr, -32600, "Message exceeds 8 MiB limit"));
        message.clear();
        overflow = false;
        continue;
      }
      if (!message.empty()) {
        return true;
      }
      continue;
    }
    if (message.size() < max_message_bytes) {
      message.push_back(value);
    } else {
      overflow = true;
    }
  }
  return !overflow && !message.empty();
}

void Server::dispatch(Json request) {
  if (!request.is_object()) {
    write(error(nullptr, -32600, "Invalid JSON-RPC request"));
    return;
  }

  const auto version = request.find("jsonrpc");
  if (version == request.end() || !version->is_string() || *version != "2.0") {
    write(error(request.value("id", Json{nullptr}), -32600,
                "JSON-RPC version must be '2.0'"));
    return;
  }

  const auto method = request.find("method");
  if (method == request.end() || !method->is_string()) {
    write(error(request.value("id", Json{nullptr}), -32600,
                "Request method must be a string"));
    return;
  }

  if (!request.contains("id")) {
    return;
  }

  auto id = request["id"];
  const auto params = request.value("params", Json::object());
  const auto& name = method->get_ref<const std::string&>();
  if (name == "initialize") {
    write(success(std::move(id), initialize(params)));
  } else if (name == "ping") {
    write(success(std::move(id), Json::object()));
  } else if (name == "tools/list") {
    write(success(std::move(id), {{"tools", registry_.describe()}}));
  } else if (name == "tools/call") {
    handle_tool_call(std::move(id), params);
  } else {
    write(error(std::move(id), -32601, "Method not found", {{"method", name}}));
  }
}

void Server::handle_tool_call(Json id, Json params) {
  if (!params.is_object()) {
    write(error(std::move(id), -32602, "Tool call params must be an object"));
    return;
  }
  const auto name = params.find("name");
  if (name == params.end() || !name->is_string()) {
    write(error(std::move(id), -32602, "Tool name must be a string"));
    return;
  }

  auto arguments = params.value("arguments", Json::object());
  auto tool_name = name->get<std::string>();
  workers_.submit([this, id = std::move(id), tool_name = std::move(tool_name),
                   arguments = std::move(arguments)]() mutable {
    write(success(std::move(id), call_tool(tool_name, arguments)));
  });
}

Json Server::initialize(const Json& params) const {
  auto selected = supported_protocols.front();
  if (const auto version = params.find("protocolVersion");
      version != params.end() && version->is_string()) {
    const auto requested = std::string_view{version->get_ref<const std::string&>()};
    if (std::ranges::find(supported_protocols, requested) != supported_protocols.end()) {
      selected = requested;
    }
  }
  return {{"protocolVersion", selected},
          {"capabilities", {{"tools", {{"listChanged", false}}}}},
          {"serverInfo", {{"name", "reverseplugin"},
                          {"version", REVERSEPLUGIN_VERSION}}}};
}

Json Server::call_tool(std::string_view name, const Json& arguments) const {
  const auto* tool = registry_.find(name);
  if (tool == nullptr) {
    return tool_response({{"code", "unknown_tool"},
                          {"message", "The requested tool is not registered"},
                          {"details", {{"name", name}}}}, true);
  }

  try {
    auto result = tool->invoke(arguments);
    if (!result) {
      return tool_response(tool_error_json(result.error()), true);
    }
    return tool_response(std::move(*result), false);
  } catch (const std::exception& exception) {
    return tool_response({{"code", "internal"},
                          {"message", "Tool execution failed safely"},
                          {"details", {{"reason", exception.what()}}}}, true);
  } catch (...) {
    return tool_response({{"code", "internal"},
                          {"message", "Tool execution failed safely"},
                          {"details", Json::object()}}, true);
  }
}

void Server::write(Json response) {
  std::lock_guard lock(output_mutex_);
  output_ << response.dump() << '\n';
  output_.flush();
}

Json Server::success(Json id, Json result) {
  return {{"jsonrpc", "2.0"}, {"id", std::move(id)}, {"result", std::move(result)}};
}

Json Server::error(Json id, int code, std::string message, Json data) {
  Json body{{"code", code}, {"message", std::move(message)}};
  if (!data.is_null()) {
    body["data"] = std::move(data);
  }
  return {{"jsonrpc", "2.0"}, {"id", std::move(id)}, {"error", std::move(body)}};
}

}  // namespace reverseplugin::mcp
