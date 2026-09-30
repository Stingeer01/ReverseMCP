#include "reverseplugin/tools.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <memory>
#include <ranges>
#include <string>
#include <string_view>

#include "reverseplugin/engine/artifact_inspector.hpp"
#include "reverseplugin/engine/workspace.hpp"
#include "tool_support.hpp"

namespace reverseplugin {
namespace {

using mcp::Json;

std::filesystem::path path_from_utf8(std::string_view text) {
  std::u8string utf8;
  utf8.reserve(text.size());
  for (const auto byte : text) utf8.push_back(static_cast<char8_t>(byte));
  return std::filesystem::path{utf8};
}

std::string path_to_utf8(const std::filesystem::path& path) {
  const auto utf8 = path.generic_u8string();
  return {reinterpret_cast<const char*>(utf8.data()), utf8.size()};
}

bool contains_ascii(std::string_view value, std::string_view filter) {
  if (filter.empty()) return true;
  return std::ranges::search(value, filter, [](unsigned char left,
                                               unsigned char right) {
    return std::tolower(left) == std::tolower(right);
  }).begin() != value.end();
}

std::shared_ptr<const engine::Workspace> require_workspace(
    const Json& arguments, const std::shared_ptr<engine::WorkspaceStore>& store,
    mcp::ToolError& error) {
  auto id = tools::unsigned_value(arguments, "workspace_id");
  if (!id) {
    error = std::move(id.error());
    return nullptr;
  }
  auto workspace = store->workspace(*id);
  if (!workspace)
    error = tools::invalid("Unknown or closed engine workspace",
                           {{"workspace_id", *id}});
  return workspace;
}

Json artifact_json(const engine::Artifact& artifact) {
  return {{"artifact_id", artifact.id},
          {"path", path_to_utf8(artifact.relative_path)},
          {"size", artifact.size},
          {"kind", engine::name(artifact.kind)},
          {"format", artifact.format}};
}

class OpenEngineWorkspaceTool final : public mcp::Tool {
 public:
  explicit OpenEngineWorkspaceTool(std::shared_ptr<engine::WorkspaceStore> store)
      : store_(std::move(store)) {}

  std::string_view name() const noexcept override { return "open_engine_workspace"; }
  std::string_view description() const noexcept override {
    return "Scan a game installation without executing it, identify Unity, Unreal Engine, Godot, Source, Source 2, CryEngine, or Cocos2d-x from independent artifacts, and build a bounded index of modules, containers, metadata, assets, scripts, shaders, symbols, and configuration files.";
  }
  const Json& input_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"root_path", {{"type", "string"}, {"minLength", 1},
        {"description", "Game installation or unpacked project root. The directory is traversed read-only."}}},
      {"max_depth", {{"type", "integer"}, {"minimum", 0}, {"maximum", 32}, {"default", 8},
        {"description", "Maximum directory recursion depth."}}},
      {"max_files", {{"type", "integer"}, {"minimum", 1}, {"maximum", 1000000}, {"default", 250000},
        {"description", "Maximum regular files examined before the scan is marked truncated."}}},
      {"max_artifacts", {{"type", "integer"}, {"minimum", 1}, {"maximum", 250000}, {"default", 100000},
        {"description", "Maximum recognized engine artifacts retained in memory."}}}}},
      {"required", {"root_path"}}, {"additionalProperties", false}};
    return schema;
  }
  const Json& output_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"workspace_id", {{"type", "integer"}}}, {"root_path", {{"type", "string"}}},
      {"engine", {{"type", "string"}}}, {"confidence", {{"type", "string"}}},
      {"scripting_backend", {{"type", {"string", "null"}}}},
      {"scanned_files", {{"type", "integer"}}}, {"artifact_count", {{"type", "integer"}}},
      {"artifact_bytes", {{"type", "integer"}}}, {"scan_truncated", {{"type", "boolean"}}},
      {"evidence", {{"type", "array"}}}, {"candidates", {{"type", "array"}}},
      {"artifact_counts", {{"type", "object"}}}}},
      {"required", {"workspace_id", "root_path", "engine", "confidence",
                    "scripting_backend", "scanned_files", "artifact_count",
                    "artifact_bytes", "scan_truncated", "evidence", "candidates",
                    "artifact_counts"}}, {"additionalProperties", false}};
    return schema;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }

  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object())
      return std::unexpected(tools::invalid("Arguments must be an object"));
    const auto root = arguments.find("root_path");
    if (root == arguments.end() || !root->is_string() ||
        root->get_ref<const std::string&>().empty())
      return std::unexpected(tools::invalid("root_path must be a non-empty string"));
    engine::OpenOptions options;
    try {
      options.max_depth = arguments.value("max_depth", options.max_depth);
      options.max_files = arguments.value("max_files", options.max_files);
      options.max_artifacts = arguments.value("max_artifacts", options.max_artifacts);
    } catch (const Json::exception&) {
      return std::unexpected(tools::invalid("Engine scan limits must be integers"));
    }
    auto opened = store_->open(path_from_utf8(root->get_ref<const std::string&>()),
                               options);
    if (!opened) return std::unexpected(tools::invalid(opened.error()));
    const auto& workspace = **opened;
    Json candidates = Json::array();
    for (const auto& candidate : workspace.candidates)
      candidates.push_back({{"engine", engine::name(candidate.kind)},
                            {"score", candidate.score}});
    Json counts = Json::object();
    for (const auto& artifact : workspace.artifacts) {
      const std::string key{engine::name(artifact.kind)};
      counts[key] = counts.value(key, std::size_t{0}) + 1;
    }
    return Json{{"workspace_id", workspace.id},
                {"root_path", path_to_utf8(workspace.root)},
                {"engine", engine::name(workspace.engine)},
                {"confidence", workspace.confidence},
                {"scripting_backend", workspace.scripting_backend.empty()
                    ? Json(nullptr) : Json(workspace.scripting_backend)},
                {"scanned_files", workspace.scanned_files},
                {"artifact_count", workspace.artifacts.size()},
                {"artifact_bytes", workspace.artifact_bytes},
                {"scan_truncated", workspace.scan_truncated},
                {"evidence", workspace.evidence},
                {"candidates", std::move(candidates)},
                {"artifact_counts", std::move(counts)}};
  }

 private:
  std::shared_ptr<engine::WorkspaceStore> store_;
};

class ListEngineArtifactsTool final : public mcp::Tool {
 public:
  explicit ListEngineArtifactsTool(std::shared_ptr<engine::WorkspaceStore> store)
      : store_(std::move(store)) {}
  std::string_view name() const noexcept override { return "list_engine_artifacts"; }
  std::string_view description() const noexcept override {
    return "Page through an engine workspace with optional artifact-kind, format, and case-insensitive path filters. Use artifact IDs with inspect_engine_artifact or pass native modules to open_binary.";
  }
  const Json& input_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"workspace_id", {{"type", "integer"}, {"minimum", 1},
        {"description", "Identifier returned by open_engine_workspace."}}},
      {"kind", {{"type", "string"},
        {"enum", {"native_module", "managed_assembly", "container", "asset", "configuration", "metadata", "symbol", "script", "shader"}},
        {"description", "Optional exact artifact category."}}},
      {"format", {{"type", "string"}, {"description", "Optional exact format label returned by the index."}}},
      {"path_contains", {{"type", "string"}, {"description", "Optional case-insensitive relative-path substring."}}},
      {"offset", {{"type", "integer"}, {"minimum", 0}, {"default", 0}}},
      {"limit", {{"type", "integer"}, {"minimum", 1}, {"maximum", 5000}, {"default", 250}}}}},
      {"required", {"workspace_id"}}, {"additionalProperties", false}};
    return schema;
  }
  const Json& output_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"offset", {{"type", "integer"}}}, {"total_matching", {{"type", "integer"}}},
      {"artifacts", {{"type", "array"}}}, {"truncated", {{"type", "boolean"}}}}},
      {"required", {"offset", "total_matching", "artifacts", "truncated"}},
      {"additionalProperties", false}};
    return schema;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }

  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{};
    auto workspace = require_workspace(arguments, store_, error);
    if (!workspace) return std::unexpected(std::move(error));
    const auto kind = arguments.value("kind", std::string{});
    const auto format = arguments.value("format", std::string{});
    const auto path_filter = arguments.value("path_contains", std::string{});
    const auto offset = arguments.value("offset", std::size_t{0});
    const auto limit = arguments.value("limit", std::size_t{250});
    if (limit == 0 || limit > 5000)
      return std::unexpected(tools::invalid("limit is outside its schema bounds"));
    Json artifacts = Json::array();
    std::size_t matched = 0;
    for (const auto& artifact : workspace->artifacts) {
      if (!kind.empty() && engine::name(artifact.kind) != kind) continue;
      if (!format.empty() && artifact.format != format) continue;
      const auto path = path_to_utf8(artifact.relative_path);
      if (!contains_ascii(path, path_filter)) continue;
      if (matched++ < offset || artifacts.size() >= limit) continue;
      artifacts.push_back(artifact_json(artifact));
    }
    return Json{{"offset", offset}, {"total_matching", matched},
                {"artifacts", std::move(artifacts)},
                {"truncated", offset + limit < matched}};
  }

 private:
  std::shared_ptr<engine::WorkspaceStore> store_;
};

class InspectEngineArtifactTool final : public mcp::Tool {
 public:
  explicit InspectEngineArtifactTool(std::shared_ptr<engine::WorkspaceStore> store)
      : store_(std::move(store)) {}
  std::string_view name() const noexcept override { return "inspect_engine_artifact"; }
  std::string_view description() const noexcept override {
    return "Validate and inspect one indexed engine artifact without extraction or execution. Recognizes PE files, Valve VPK headers, standalone or executable-embedded Godot PCK headers, and Unreal container families; returns bounded header and trailer samples.";
  }
  const Json& input_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"workspace_id", {{"type", "integer"}, {"minimum", 1},
        {"description", "Identifier returned by open_engine_workspace."}}},
      {"artifact_id", {{"type", "integer"}, {"minimum", 1},
        {"description", "Artifact identifier returned by list_engine_artifacts."}}}}},
      {"required", {"workspace_id", "artifact_id"}}, {"additionalProperties", false}};
    return schema;
  }
  const Json& output_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"artifact_id", {{"type", "integer"}}}, {"path", {{"type", "string"}}},
      {"kind", {{"type", "string"}}}, {"format", {{"type", "string"}}},
      {"size", {{"type", "integer"}}}, {"header_hex", {{"type", "string"}}},
      {"trailer_hex", {{"type", "string"}}}, {"signature", {{"type", {"string", "null"}}}},
      {"details", {{"type", "object"}}}}},
      {"required", {"artifact_id", "path", "kind", "format", "size",
                    "header_hex", "trailer_hex", "signature", "details"}},
      {"additionalProperties", false}};
    return schema;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }

  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{};
    auto workspace = require_workspace(arguments, store_, error);
    if (!workspace) return std::unexpected(std::move(error));
    auto id = tools::unsigned_value(arguments, "artifact_id");
    if (!id) return std::unexpected(std::move(id.error()));
    if (*id == 0 || *id > workspace->artifacts.size())
      return std::unexpected(tools::invalid("artifact_id is outside this workspace"));
    auto result = engine::inspect_artifact(*workspace, workspace->artifacts[*id - 1]);
    if (!result) return std::unexpected(tools::invalid(result.error()));
    return std::move(*result);
  }

 private:
  std::shared_ptr<engine::WorkspaceStore> store_;
};

class CloseEngineWorkspaceTool final : public mcp::Tool {
 public:
  explicit CloseEngineWorkspaceTool(std::shared_ptr<engine::WorkspaceStore> store)
      : store_(std::move(store)) {}
  std::string_view name() const noexcept override { return "close_engine_workspace"; }
  std::string_view description() const noexcept override {
    return "Release a game-engine artifact index. Input files are never modified.";
  }
  const Json& input_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"workspace_id", {{"type", "integer"}, {"minimum", 1},
        {"description", "Identifier returned by open_engine_workspace."}}}}},
      {"required", {"workspace_id"}}, {"additionalProperties", false}};
    return schema;
  }
  const Json& output_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"closed", {{"type", "boolean"}}}}}, {"required", {"closed"}},
      {"additionalProperties", false}};
    return schema;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    auto id = tools::unsigned_value(arguments, "workspace_id");
    if (!id) return std::unexpected(std::move(id.error()));
    return Json{{"closed", store_->close(*id)}};
  }

 private:
  std::shared_ptr<engine::WorkspaceStore> store_;
};

}  // namespace

void register_engine_tools(mcp::ToolRegistry& registry) {
  auto store = std::make_shared<engine::WorkspaceStore>();
  if (!registry.add(std::make_unique<OpenEngineWorkspaceTool>(store)) ||
      !registry.add(std::make_unique<ListEngineArtifactsTool>(store)) ||
      !registry.add(std::make_unique<InspectEngineArtifactTool>(store)) ||
      !registry.add(std::make_unique<CloseEngineWorkspaceTool>(store)))
    std::terminate();
}

}  // namespace reverseplugin
