#include "reverseplugin/tools.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <ranges>
#include <string>
#include <string_view>

#include "reverseplugin/il2cpp/workspace_store.hpp"
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

char lower_ascii(unsigned char value) noexcept {
  return static_cast<char>(std::tolower(value));
}

bool contains_ascii(std::string_view value, std::string_view filter) {
  if (filter.empty()) return true;
  return std::ranges::search(value, filter, [](char left, char right) {
    return lower_ascii(static_cast<unsigned char>(left)) ==
           lower_ascii(static_cast<unsigned char>(right));
  }).begin() != value.end();
}

bool equal_ascii(std::string_view left, std::string_view right) {
  return std::ranges::equal(left, right, [](char lhs, char rhs) {
    return lower_ascii(static_cast<unsigned char>(lhs)) ==
           lower_ascii(static_cast<unsigned char>(rhs));
  });
}

std::expected<std::string, std::string> metadata_string(
    const il2cpp::Metadata& metadata, std::uint32_t index) {
  auto value = metadata.string_at(index);
  if (!value) return std::unexpected(std::move(value.error()));
  return std::string{*value};
}

std::shared_ptr<const il2cpp::Workspace> require_workspace(
    const Json& arguments, const std::shared_ptr<il2cpp::WorkspaceStore>& store,
    mcp::ToolError& error) {
  auto id = tools::unsigned_value(arguments, "workspace_id");
  if (!id) {
    error = std::move(id.error());
    return nullptr;
  }
  auto workspace = store->workspace(*id);
  if (!workspace)
    error = tools::invalid("Unknown or closed IL2CPP workspace", {{"workspace_id", *id}});
  return workspace;
}

std::expected<Json, std::string> type_json(
    const il2cpp::Metadata& metadata, std::size_t type_index,
    std::string_view image_name, const il2cpp::GameAssemblyInfo* game_assembly,
    bool include_fields, bool include_methods, std::size_t member_limit) {
  auto type = metadata.type(type_index);
  if (!type) return std::unexpected(std::move(type.error()));
  auto name = metadata_string(metadata, type->name_index);
  auto namespc = metadata_string(metadata, type->namespace_index);
  if (!name || !namespc)
    return std::unexpected(name ? std::move(namespc.error()) : std::move(name.error()));

  std::string full_name;
  if (!namespc->empty()) full_name = *namespc + '.';
  full_name += *name;
  Json result{{"index", type_index}, {"image", image_name},
              {"namespace", *namespc}, {"name", *name},
              {"full_name", std::move(full_name)},
              {"token", tools::hex_u64(type->token)}, {"flags", type->flags},
              {"is_value_type", (type->bitfield & 1U) != 0},
              {"is_enum", (type->bitfield & 2U) != 0},
              {"field_count", type->field_count},
              {"method_count", type->method_count}};

  bool truncated = false;
  if (include_fields) {
    Json fields = Json::array();
    const auto count = (std::min)(static_cast<std::size_t>(type->field_count), member_limit);
    for (std::size_t i = 0; i < count; ++i) {
      auto field = metadata.field(static_cast<std::size_t>(type->field_start) + i);
      if (!field) return std::unexpected(std::move(field.error()));
      auto field_name = metadata_string(metadata, field->name_index);
      if (!field_name) return std::unexpected(std::move(field_name.error()));
      fields.push_back({{"index", static_cast<std::size_t>(type->field_start) + i},
                        {"name", *field_name}, {"type_index", field->type_index},
                        {"token", tools::hex_u64(field->token)}});
    }
    truncated = truncated || count < type->field_count;
    result["fields"] = std::move(fields);
  }

  if (include_methods) {
    Json methods = Json::array();
    const auto count = (std::min)(static_cast<std::size_t>(type->method_count), member_limit);
    for (std::size_t i = 0; i < count; ++i) {
      auto method = metadata.method(static_cast<std::size_t>(type->method_start) + i);
      if (!method) return std::unexpected(std::move(method.error()));
      auto method_name = metadata_string(metadata, method->name_index);
      if (!method_name) return std::unexpected(std::move(method_name.error()));
      Json parameters = Json::array();
      for (std::size_t parameter_index = 0;
           parameter_index < method->parameter_count; ++parameter_index) {
        auto parameter = metadata.parameter(
            static_cast<std::size_t>(method->parameter_start) + parameter_index);
        if (!parameter) return std::unexpected(std::move(parameter.error()));
        auto parameter_name = metadata_string(metadata, parameter->name_index);
        if (!parameter_name) return std::unexpected(std::move(parameter_name.error()));
        parameters.push_back({{"name", *parameter_name},
                              {"type_index", parameter->type_index},
                              {"token", tools::hex_u64(parameter->token)}});
      }
      Json native_rva = nullptr;
      Json native_address = nullptr;
      if (game_assembly) {
        if (const auto rva = game_assembly->method_rva(image_name, method->token)) {
          native_rva = tools::hex_u64(*rva);
          native_address = tools::hex_u64(game_assembly->image_base + *rva);
        }
      }
      methods.push_back({{"index", static_cast<std::size_t>(type->method_start) + i},
                         {"name", *method_name}, {"token", tools::hex_u64(method->token)},
                         {"native_rva", std::move(native_rva)},
                         {"native_address", std::move(native_address)},
                         {"return_type_index", method->return_type},
                         {"flags", method->flags}, {"slot", method->slot},
                         {"parameter_count", method->parameter_count},
                         {"parameters", std::move(parameters)}});
    }
    truncated = truncated || count < type->method_count;
    result["methods"] = std::move(methods);
  }
  result["members_truncated"] = truncated;
  return result;
}

class OpenIl2CppWorkspaceTool final : public mcp::Tool {
 public:
  explicit OpenIl2CppWorkspaceTool(std::shared_ptr<il2cpp::WorkspaceStore> store)
      : store_(std::move(store)) {}

  std::string_view name() const noexcept override { return "open_il2cpp_workspace"; }
  std::string_view description() const noexcept override {
    return "Open compact Unity IL2CPP metadata v38/v39 and a matching Windows GameAssembly.dll. Locates IL2CPP code-registration tables, maps method tokens to native RVAs, fingerprints both files, and reuses unchanged workspaces without executing the game.";
  }
  const Json& input_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"metadata_path", {{"type", "string"}, {"minLength", 1},
        {"description", "Path to the Unity global-metadata.dat file."}}},
      {"game_assembly_path", {{"type", "string"}, {"minLength", 1},
        {"description", "Optional path to the matching x86-64 GameAssembly.dll. It is parsed statically and never executed."}}}}},
      {"required", {"metadata_path"}}, {"additionalProperties", false}};
    return schema;
  }
  const Json& output_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"workspace_id", {{"type", "integer"}}}, {"metadata_path", {{"type", "string"}}},
      {"metadata_version", {{"type", "integer"}}}, {"metadata_sha256", {{"type", "string"}}},
      {"game_assembly", {{"type", {"object", "null"}}}},
      {"image_count", {{"type", "integer"}}}, {"type_count", {{"type", "integer"}}},
      {"method_count", {{"type", "integer"}}}, {"field_count", {{"type", "integer"}}},
      {"images", {{"type", "array"}}}, {"native_mapping_available", {{"type", "boolean"}}},
      {"cache_hit", {{"type", "boolean"}}}}},
      {"required", {"workspace_id", "metadata_path", "metadata_version", "metadata_sha256",
                    "game_assembly", "image_count", "type_count", "method_count", "field_count",
                    "images", "native_mapping_available", "cache_hit"}},
      {"additionalProperties", false}};
    return schema;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }

  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) return std::unexpected(tools::invalid("Arguments must be an object"));
    const auto metadata_entry = arguments.find("metadata_path");
    if (metadata_entry == arguments.end() || !metadata_entry->is_string() ||
        metadata_entry->get_ref<const std::string&>().empty())
      return std::unexpected(tools::invalid("metadata_path must be a non-empty string"));
    std::filesystem::path game_assembly;
    if (const auto entry = arguments.find("game_assembly_path"); entry != arguments.end()) {
      if (!entry->is_string() || entry->get_ref<const std::string&>().empty())
        return std::unexpected(tools::invalid("game_assembly_path must be a non-empty string"));
      game_assembly = path_from_utf8(entry->get_ref<const std::string&>());
    }
    auto opened = store_->open(path_from_utf8(metadata_entry->get_ref<const std::string&>()),
                               game_assembly);
    if (!opened) return std::unexpected(tools::invalid(opened.error()));
    const auto& workspace = *opened->workspace;
    const auto& info = workspace.metadata->info();
    Json image_list = Json::array();
    for (std::size_t i = 0; i < info.image_count; ++i) {
      auto image = workspace.metadata->image(i);
      if (!image) return std::unexpected(tools::invalid(image.error()));
      auto name = metadata_string(*workspace.metadata, image->name_index);
      if (!name) return std::unexpected(tools::invalid(name.error()));
      image_list.push_back({{"index", i}, {"name", *name},
                            {"assembly_index", image->assembly_index},
                            {"type_start", image->type_start},
                            {"type_count", image->type_count},
                            {"token", tools::hex_u64(image->token)}});
    }
    Json assembly = nullptr;
    if (workspace.game_assembly) {
      assembly = {{"path", path_to_utf8(workspace.game_assembly->path)},
                  {"sha256", workspace.game_assembly->fingerprint},
                  {"architecture", workspace.game_assembly->architecture},
                  {"file_size", workspace.game_assembly->file_size},
                  {"image_base", tools::hex_u64(workspace.game_assembly->image_base)},
                  {"image_size", workspace.game_assembly->image_size},
                  {"code_registration_rva",
                   tools::hex_u64(workspace.game_assembly->code_registration_rva)},
                  {"mapped_module_count", workspace.game_assembly->method_rvas.size()}};
    }
    return Json{{"workspace_id", workspace.id}, {"metadata_path", path_to_utf8(info.path)},
                {"metadata_version", info.version}, {"metadata_sha256", info.fingerprint},
                {"game_assembly", std::move(assembly)}, {"image_count", info.image_count},
                {"type_count", info.type_count}, {"method_count", info.method_count},
                {"field_count", info.field_count}, {"images", std::move(image_list)},
                {"native_mapping_available", workspace.game_assembly != nullptr},
                {"cache_hit", opened->cache_hit}};
  }

 private:
  std::shared_ptr<il2cpp::WorkspaceStore> store_;
};

class DumpIl2CppTypesTool final : public mcp::Tool {
 public:
  explicit DumpIl2CppTypesTool(std::shared_ptr<il2cpp::WorkspaceStore> store)
      : store_(std::move(store)) {}

  std::string_view name() const noexcept override { return "dump_il2cpp_types"; }
  std::string_view description() const noexcept override {
    return "Return a bounded structured page of IL2CPP types, fields, methods, parameters, and native method RVAs from an opened workspace. Supports image, namespace, and type-name filters; unresolved native pointers are returned as null.";
  }
  const Json& input_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"workspace_id", {{"type", "integer"}, {"minimum", 1},
        {"description", "Identifier returned by open_il2cpp_workspace."}}},
      {"image", {{"type", "string"}, {"description", "Optional exact image name such as Assembly-CSharp.dll."}}},
      {"namespace_contains", {{"type", "string"}, {"description", "Optional case-insensitive namespace substring."}}},
      {"type_name_contains", {{"type", "string"}, {"description", "Optional case-insensitive type-name substring."}}},
      {"offset", {{"type", "integer"}, {"minimum", 0}, {"default", 0},
        {"description", "Offset within the filtered type sequence."}}},
      {"limit", {{"type", "integer"}, {"minimum", 1}, {"maximum", 2000}, {"default", 200},
        {"description", "Maximum matching types returned."}}},
      {"include_fields", {{"type", "boolean"}, {"default", true},
        {"description", "Include field names, metadata type indices, and tokens."}}},
      {"include_methods", {{"type", "boolean"}, {"default", true},
        {"description", "Include method signatures, parameters, tokens, and resolved native addresses."}}},
      {"max_members_per_type", {{"type", "integer"}, {"minimum", 1}, {"maximum", 4096}, {"default", 256},
        {"description", "Independent cap applied to fields and methods of each returned type."}}}}},
      {"required", {"workspace_id"}}, {"additionalProperties", false}};
    return schema;
  }
  const Json& output_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"offset", {{"type", "integer"}}}, {"total_matching_types", {{"type", "integer"}}},
      {"types", {{"type", "array"}}}, {"truncated", {{"type", "boolean"}}},
      {"native_mapping_available", {{"type", "boolean"}}}}},
      {"required", {"offset", "total_matching_types", "types", "truncated", "native_mapping_available"}},
      {"additionalProperties", false}};
    return schema;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }

  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{};
    auto workspace = require_workspace(arguments, store_, error);
    if (!workspace) return std::unexpected(std::move(error));
    const auto image_filter = arguments.value("image", std::string{});
    const auto namespace_filter = arguments.value("namespace_contains", std::string{});
    const auto name_filter = arguments.value("type_name_contains", std::string{});
    const auto offset = arguments.value("offset", std::size_t{0});
    const auto limit = arguments.value("limit", std::size_t{200});
    const auto member_limit = arguments.value("max_members_per_type", std::size_t{256});
    if (limit == 0 || limit > 2000 || member_limit == 0 || member_limit > 4096)
      return std::unexpected(tools::invalid("limit or max_members_per_type is outside its schema bounds"));
    const bool include_fields = arguments.value("include_fields", true);
    const bool include_methods = arguments.value("include_methods", true);

    Json entries = Json::array();
    std::size_t matched = 0;
    const auto& metadata = *workspace->metadata;
    for (std::size_t image_index = 0; image_index < metadata.info().image_count; ++image_index) {
      auto image = metadata.image(image_index);
      if (!image) return std::unexpected(tools::invalid(image.error()));
      auto image_name = metadata_string(metadata, image->name_index);
      if (!image_name) return std::unexpected(tools::invalid(image_name.error()));
      if (!image_filter.empty() && !equal_ascii(*image_name, image_filter)) continue;
      for (std::size_t local = 0; local < image->type_count; ++local) {
        const auto index = static_cast<std::size_t>(image->type_start) + local;
        auto type = metadata.type(index);
        if (!type) return std::unexpected(tools::invalid(type.error()));
        auto type_name = metadata_string(metadata, type->name_index);
        auto namespc = metadata_string(metadata, type->namespace_index);
        if (!type_name || !namespc)
          return std::unexpected(tools::invalid(type_name ? namespc.error() : type_name.error()));
        if (!contains_ascii(*type_name, name_filter) ||
            !contains_ascii(*namespc, namespace_filter)) continue;
        if (matched++ < offset || entries.size() >= limit) continue;
        auto value = type_json(metadata, index, *image_name,
                               workspace->game_assembly.get(), include_fields,
                               include_methods, member_limit);
        if (!value) return std::unexpected(tools::invalid(value.error()));
        entries.push_back(std::move(*value));
      }
    }
    return Json{{"offset", offset}, {"total_matching_types", matched},
                {"types", std::move(entries)}, {"truncated", offset + limit < matched},
                {"native_mapping_available", workspace->game_assembly != nullptr}};
  }

 private:
  std::shared_ptr<il2cpp::WorkspaceStore> store_;
};

class ExportIl2CppJsonlTool final : public mcp::Tool {
 public:
  explicit ExportIl2CppJsonlTool(std::shared_ptr<il2cpp::WorkspaceStore> store)
      : store_(std::move(store)) {}

  std::string_view name() const noexcept override { return "export_il2cpp_jsonl"; }
  std::string_view description() const noexcept override {
    return "Stream a complete or image-filtered IL2CPP dump to an atomic JSON Lines file. Each method includes its token and statically resolved GameAssembly RVA/VA when present in the code-generation module.";
  }
  const Json& input_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"workspace_id", {{"type", "integer"}, {"minimum", 1},
        {"description", "Identifier returned by open_il2cpp_workspace."}}},
      {"output_path", {{"type", "string"}, {"minLength", 1},
        {"description", "Destination JSONL path. Parent directory must already exist."}}},
      {"image", {{"type", "string"}, {"description", "Optional exact image name such as Assembly-CSharp.dll; omit it to export every image."}}},
      {"overwrite", {{"type", "boolean"}, {"default", false},
        {"description", "Replace an existing destination only after the temporary export has flushed successfully."}}}}},
      {"required", {"workspace_id", "output_path"}}, {"additionalProperties", false}};
    return schema;
  }
  const Json& output_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"path", {{"type", "string"}}}, {"bytes_written", {{"type", "integer"}}},
      {"type_count", {{"type", "integer"}}}, {"method_count", {{"type", "integer"}}},
      {"field_count", {{"type", "integer"}}}, {"native_mapping_available", {{"type", "boolean"}}}}},
      {"required", {"path", "bytes_written", "type_count", "method_count", "field_count",
                    "native_mapping_available"}}, {"additionalProperties", false}};
    return schema;
  }
  const Json& annotations() const noexcept override {
    static const Json annotations{{"readOnlyHint", false}, {"destructiveHint", true},
                                  {"idempotentHint", true}, {"openWorldHint", false}};
    return annotations;
  }

  mcp::ToolResult invoke(const Json& arguments) const override {
    mcp::ToolError error{};
    auto workspace = require_workspace(arguments, store_, error);
    if (!workspace) return std::unexpected(std::move(error));
    const auto output_entry = arguments.find("output_path");
    if (output_entry == arguments.end() || !output_entry->is_string() ||
        output_entry->get_ref<const std::string&>().empty())
      return std::unexpected(tools::invalid("output_path must be a non-empty string"));
    std::error_code ec;
    const auto output = std::filesystem::absolute(
        path_from_utf8(output_entry->get_ref<const std::string&>()), ec).lexically_normal();
    if (ec || output.filename().empty() || !std::filesystem::is_directory(output.parent_path(), ec))
      return std::unexpected(tools::invalid("output_path parent directory does not exist"));
    const bool overwrite = arguments.value("overwrite", false);
    if (std::filesystem::exists(output, ec) && !overwrite)
      return std::unexpected(tools::invalid("output_path already exists; set overwrite to true to replace it"));
    if (std::filesystem::equivalent(output, workspace->metadata->info().path, ec) && !ec)
      return std::unexpected(tools::invalid("output_path must not replace global-metadata.dat"));
    ec.clear();
    if (workspace->game_assembly &&
        std::filesystem::equivalent(output, workspace->game_assembly->path, ec) && !ec)
      return std::unexpected(tools::invalid("output_path must not replace GameAssembly.dll"));

    auto temporary = output;
    temporary += L"." + std::to_wstring(GetCurrentProcessId()) + L"." +
                 std::to_wstring(GetCurrentThreadId()) + L".tmp";
    struct TemporaryGuard final {
      std::filesystem::path path;
      bool active{true};
      ~TemporaryGuard() {
        if (!active) return;
        std::error_code error;
        std::filesystem::remove(path, error);
      }
    } temporary_guard{temporary};
    std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
    if (!stream) return std::unexpected(tools::invalid("Could not create temporary dump file"));
    const auto& metadata = *workspace->metadata;
    Json header{{"kind", "il2cpp_dump_header"},
                {"metadata_version", metadata.info().version},
                {"metadata_sha256", metadata.info().fingerprint},
                {"game_assembly_sha256", workspace->game_assembly
                    ? Json(workspace->game_assembly->fingerprint) : Json(nullptr)},
                {"native_mapping_available", workspace->game_assembly != nullptr}};
    stream << header.dump() << '\n';
    const auto image_filter = arguments.value("image", std::string{});
    std::size_t types = 0;
    std::size_t methods_written = 0;
    std::size_t fields_written = 0;
    for (std::size_t image_index = 0; image_index < metadata.info().image_count; ++image_index) {
      auto image = metadata.image(image_index);
      if (!image) return std::unexpected(tools::invalid(image.error()));
      auto image_name = metadata_string(metadata, image->name_index);
      if (!image_name) return std::unexpected(tools::invalid(image_name.error()));
      if (!image_filter.empty() && !equal_ascii(*image_name, image_filter)) continue;
      for (std::size_t local = 0; local < image->type_count; ++local) {
        const auto type_index = static_cast<std::size_t>(image->type_start) + local;
        auto type = metadata.type(type_index);
        if (!type) return std::unexpected(tools::invalid(type.error()));
        auto value = type_json(metadata, type_index, *image_name,
                               workspace->game_assembly.get(), true, true,
                               std::numeric_limits<std::size_t>::max());
        if (!value) return std::unexpected(tools::invalid(value.error()));
        (*value)["kind"] = "type";
        stream << value->dump() << '\n';
        if (!stream) {
          stream.close();
          std::filesystem::remove(temporary, ec);
          return std::unexpected(tools::invalid("Could not write the complete IL2CPP dump"));
        }
        ++types;
        methods_written += type->method_count;
        fields_written += type->field_count;
      }
    }
    stream.flush();
    stream.close();
    if (!stream) {
      std::filesystem::remove(temporary, ec);
      return std::unexpected(tools::invalid("Could not flush the IL2CPP dump"));
    }
    if (MoveFileExW(temporary.c_str(), output.c_str(),
                    (overwrite ? MOVEFILE_REPLACE_EXISTING : 0) |
                        MOVEFILE_WRITE_THROUGH) == 0) {
      const auto native_error = GetLastError();
      std::filesystem::remove(temporary, ec);
      return std::unexpected(tools::invalid("Could not atomically publish the IL2CPP dump",
                                            {{"native_code", native_error}}));
    }
    temporary_guard.active = false;
    const auto bytes_written = std::filesystem::file_size(output, ec);
    if (ec) return std::unexpected(tools::invalid("Could not inspect the completed dump"));
    return Json{{"path", path_to_utf8(output)}, {"bytes_written", bytes_written},
                {"type_count", types}, {"method_count", methods_written},
                {"field_count", fields_written},
                {"native_mapping_available", workspace->game_assembly != nullptr}};
  }

 private:
  std::shared_ptr<il2cpp::WorkspaceStore> store_;
};

class CloseIl2CppWorkspaceTool final : public mcp::Tool {
 public:
  explicit CloseIl2CppWorkspaceTool(std::shared_ptr<il2cpp::WorkspaceStore> store)
      : store_(std::move(store)) {}
  std::string_view name() const noexcept override { return "close_il2cpp_workspace"; }
  std::string_view description() const noexcept override {
    return "Release an in-memory IL2CPP metadata workspace and its cached file buffers.";
  }
  const Json& input_schema() const noexcept override {
    static const Json schema{{"type", "object"}, {"properties", {
      {"workspace_id", {{"type", "integer"}, {"minimum", 1},
        {"description", "Identifier returned by open_il2cpp_workspace."}}}}},
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
  std::shared_ptr<il2cpp::WorkspaceStore> store_;
};

}  // namespace

void register_il2cpp_tools(mcp::ToolRegistry& registry) {
  auto store = std::make_shared<il2cpp::WorkspaceStore>();
  if (!registry.add(std::make_unique<OpenIl2CppWorkspaceTool>(store)) ||
      !registry.add(std::make_unique<DumpIl2CppTypesTool>(store)) ||
      !registry.add(std::make_unique<ExportIl2CppJsonlTool>(store)) ||
      !registry.add(std::make_unique<CloseIl2CppWorkspaceTool>(store)))
    std::terminate();
}

}  // namespace reverseplugin
