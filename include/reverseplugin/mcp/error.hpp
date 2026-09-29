#pragma once

#include <string>

#include <nlohmann/json.hpp>

namespace reverseplugin::mcp {

enum class ToolErrorCode { invalid_arguments, unavailable, internal };

struct ToolError final {
  ToolErrorCode code;
  std::string message;
  nlohmann::json details = nlohmann::json::object();
};

}  // namespace reverseplugin::mcp
