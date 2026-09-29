#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

#include "reverseplugin/mcp/tool.hpp"

namespace reverseplugin::mcp {

struct TransparentStringHash final {
  using is_transparent = void;
  [[nodiscard]] std::size_t operator()(std::string_view value) const noexcept;
  [[nodiscard]] std::size_t operator()(const std::string& value) const noexcept;
};

class ToolRegistry final {
 public:
  [[nodiscard]] bool add(std::unique_ptr<Tool> tool);
  [[nodiscard]] const Tool* find(std::string_view name) const noexcept;
  [[nodiscard]] Json describe() const;

 private:
  std::unordered_map<std::string, std::unique_ptr<Tool>, TransparentStringHash,
                     std::equal_to<>> tools_;
};

}  // namespace reverseplugin::mcp
