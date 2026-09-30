#pragma once

#include <expected>
#include <filesystem>
#include <string>

#include <nlohmann/json.hpp>

#include "reverseplugin/engine/workspace.hpp"

namespace reverseplugin::engine {

[[nodiscard]] std::expected<nlohmann::json, std::string> inspect_artifact(
    const Workspace& workspace, const Artifact& artifact);

}  // namespace reverseplugin::engine
