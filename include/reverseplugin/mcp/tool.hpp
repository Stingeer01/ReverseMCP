#pragma once

#include <expected>
#include <string_view>

#include <nlohmann/json.hpp>

#include "reverseplugin/mcp/error.hpp"

namespace reverseplugin::mcp {

using Json = nlohmann::json;
using ToolResult = std::expected<Json, ToolError>;

class Tool {
 public:
  virtual ~Tool() = default;

  [[nodiscard]] virtual std::string_view name() const noexcept = 0;
  [[nodiscard]] virtual std::string_view description() const noexcept = 0;
  [[nodiscard]] virtual const Json& input_schema() const noexcept = 0;
  [[nodiscard]] virtual const Json& output_schema() const noexcept = 0;
  [[nodiscard]] virtual const Json& annotations() const noexcept = 0;
  [[nodiscard]] virtual ToolResult invoke(const Json& arguments) const = 0;
};

}  // namespace reverseplugin::mcp
