#include "reverseplugin/mcp/tool_registry.hpp"

#include <functional>
#include <utility>

namespace reverseplugin::mcp {

std::size_t TransparentStringHash::operator()(std::string_view value) const noexcept {
  return std::hash<std::string_view>{}(value);
}

std::size_t TransparentStringHash::operator()(const std::string& value) const noexcept {
  return (*this)(std::string_view{value});
}

bool ToolRegistry::add(std::unique_ptr<Tool> tool) {
  if (!tool || tool->name().empty()) {
    return false;
  }
  const std::string name{tool->name()};
  return tools_.emplace(name, std::move(tool)).second;
}

const Tool* ToolRegistry::find(std::string_view name) const noexcept {
  const auto entry = tools_.find(name);
  return entry == tools_.end() ? nullptr : entry->second.get();
}

Json ToolRegistry::describe() const {
  Json result = Json::array();
  for (const auto& [name, tool] : tools_) {
    result.push_back({{"name", name},
                      {"description", tool->description()},
                      {"inputSchema", tool->input_schema()},
                      {"outputSchema", tool->output_schema()},
                      {"annotations", tool->annotations()}});
  }
  return result;
}

}  // namespace reverseplugin::mcp
