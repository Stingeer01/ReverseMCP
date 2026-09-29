#include "reverseplugin/tools.hpp"

#include <memory>

#include "reverseplugin/memory/snapshot_store.hpp"
#include "tool_support.hpp"

namespace reverseplugin {
namespace {

using mcp::Json;

std::optional<memory::ValueType> value_type(std::string_view name) {
  if (name == "u8") return memory::ValueType::u8;
  if (name == "u16") return memory::ValueType::u16;
  if (name == "u32") return memory::ValueType::u32;
  if (name == "u64") return memory::ValueType::u64;
  if (name == "i8") return memory::ValueType::i8;
  if (name == "i16") return memory::ValueType::i16;
  if (name == "i32") return memory::ValueType::i32;
  if (name == "i64") return memory::ValueType::i64;
  if (name == "f32") return memory::ValueType::f32;
  if (name == "f64") return memory::ValueType::f64;
  return std::nullopt;
}

std::optional<memory::Comparison> comparison(std::string_view name) {
  if (name == "changed") return memory::Comparison::changed;
  if (name == "unchanged") return memory::Comparison::unchanged;
  if (name == "increased") return memory::Comparison::increased;
  if (name == "decreased") return memory::Comparison::decreased;
  return std::nullopt;
}

class CreateMemorySnapshotTool final : public mcp::Tool {
 public:
  CreateMemorySnapshotTool(std::shared_ptr<process::ProcessManager> processes,
                           std::shared_ptr<memory::SnapshotStore> snapshots)
      : processes_(std::move(processes)), snapshots_(std::move(snapshots)) {}
  std::string_view name() const noexcept override { return "create_memory_snapshot"; }
  std::string_view description() const noexcept override {
    return "Capture a bounded readable memory range as typed candidates for iterative unknown-value searches. Supports integer and floating-point widths with packed or naturally aligned scanning.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"session_id", tools::session_schema()}, {"address", tools::address_schema()},
      {"length", {{"type", "integer"}, {"minimum", 1}, {"maximum", 67108864},
        {"description", "Readable snapshot size, capped at 64 MiB."}}},
      {"value_type", {{"type", "string"},
        {"enum", {"u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64"}},
        {"default", "u32"}, {"description", "Typed interpretation used for later comparisons."}}},
      {"alignment", {{"type", "string"}, {"enum", {"natural", "packed"}},
        {"default", "natural"}, {"description", "Natural advances by value width; packed tests every byte offset."}}}}},
      {"required", {"session_id", "address", "length"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"snapshot_id", {{"type", "integer"}, {"description", "Stable identifier for comparisons and deletion."}}},
      {"address", {{"type", "string"}, {"description", "Snapshot base address as exact hexadecimal text."}}},
      {"length", {{"type", "integer"}, {"description", "Captured byte length."}}},
      {"value_type", {{"type", "string"}, {"description", "Typed interpretation of each candidate."}}},
      {"step", {{"type", "integer"}, {"description", "Byte distance between candidate starts."}}},
      {"candidate_count", {{"type", "integer"}, {"description", "Initial typed candidate count."}}}}},
      {"required", {"snapshot_id", "address", "length", "value_type", "step", "candidate_count"}},
      {"additionalProperties", false}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) return std::unexpected(tools::invalid("Arguments must be an object"));
    mcp::ToolError error{};
    auto session = tools::require_session(arguments, processes_, error);
    if (!session) return std::unexpected(std::move(error));
    auto address = tools::unsigned_value(arguments, "address");
    auto length = tools::unsigned_value(arguments, "length");
    if (!address) return std::unexpected(std::move(address.error()));
    if (!length) return std::unexpected(std::move(length.error()));
    if (*length == 0 || *length > 64ULL * 1024 * 1024)
      return std::unexpected(tools::invalid("length must be between 1 and 67108864"));
    const auto type_name = arguments.value("value_type", std::string{"u32"});
    const auto type = value_type(type_name);
    if (!type) return std::unexpected(tools::invalid("Unknown value_type"));
    const auto alignment = arguments.value("alignment", std::string{"natural"});
    if (alignment != "natural" && alignment != "packed")
      return std::unexpected(tools::invalid("alignment must be natural or packed"));
    auto bytes = processes_->read(*session, *address, static_cast<std::size_t>(*length));
    if (!bytes) return std::unexpected(tools::process_error(bytes.error()));
    const auto step = alignment == "packed" ? std::size_t{1} : memory::width(*type);
    auto snapshot = snapshots_->create(session->id(), *address, std::move(*bytes), *type, step);
    if (!snapshot) return std::unexpected(tools::invalid(snapshot.error()));
    return Json{{"snapshot_id", snapshot->id}, {"address", tools::hex_u64(snapshot->address)},
      {"length", snapshot->length}, {"value_type", memory::to_string(snapshot->type)},
      {"step", snapshot->step}, {"candidate_count", snapshot->candidates}};
  }
 private:
  std::shared_ptr<process::ProcessManager> processes_;
  std::shared_ptr<memory::SnapshotStore> snapshots_;
};

class CompareMemorySnapshotTool final : public mcp::Tool {
 public:
  CompareMemorySnapshotTool(std::shared_ptr<process::ProcessManager> processes,
                            std::shared_ptr<memory::SnapshotStore> snapshots)
      : processes_(std::move(processes)), snapshots_(std::move(snapshots)) {}
  std::string_view name() const noexcept override { return "compare_memory_snapshot"; }
  std::string_view description() const noexcept override {
    return "Compare current memory with a typed snapshot and optionally retain only matching candidates for the next iteration. Use repeated changed/unchanged/increased/decreased filters to locate unknown runtime values.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"session_id", tools::session_schema()},
      {"snapshot_id", {{"type", "integer"}, {"minimum", 1}, {"description", "Snapshot identifier returned by create_memory_snapshot."}}},
      {"comparison", {{"type", "string"}, {"enum", {"changed", "unchanged", "increased", "decreased"}},
        {"description", "Typed comparison against the previous baseline."}}},
      {"refine", {{"type", "boolean"}, {"default", true},
        {"description", "Discard non-matching candidates and replace the baseline for iterative filtering."}}},
      {"max_results", {{"type", "integer"}, {"minimum", 1}, {"maximum", 4096}, {"default", 256},
        {"description", "Maximum candidate details returned; total candidate_count is always reported."}}}}},
      {"required", {"session_id", "snapshot_id", "comparison"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"snapshot_id", {{"type", "integer"}, {"description", "Compared snapshot identifier."}}},
      {"candidate_count", {{"type", "integer"}, {"description", "Total matches, including omitted details."}}},
      {"matches", {{"type", "array"}, {"description", "Bounded matching candidate details."},
        {"items", {{"type", "object"}, {"properties", {
          {"address", {{"type", "string"}, {"description", "Exact candidate virtual address."}}},
          {"offset", {{"type", "integer"}, {"description", "Byte offset from the snapshot base."}}},
          {"before_hex", {{"type", "string"}, {"description", "Previous typed bytes in memory order."}}},
          {"after_hex", {{"type", "string"}, {"description", "Current typed bytes in memory order."}}}}},
          {"required", {"address", "offset", "before_hex", "after_hex"}},
          {"additionalProperties", false}}}}},
      {"truncated", {{"type", "boolean"}, {"description", "True when some matching details were omitted."}}},
      {"refined", {{"type", "boolean"}, {"description", "Whether nonmatches were removed and baseline advanced."}}}}},
      {"required", {"snapshot_id", "candidate_count", "matches", "truncated", "refined"}},
      {"additionalProperties", false}};
    return value;
  }
  const Json& annotations() const noexcept override { return tools::read_only_annotations(); }
  mcp::ToolResult invoke(const Json& arguments) const override {
    if (!arguments.is_object()) return std::unexpected(tools::invalid("Arguments must be an object"));
    mcp::ToolError error{};
    auto session = tools::require_session(arguments, processes_, error);
    if (!session) return std::unexpected(std::move(error));
    auto id = tools::unsigned_value(arguments, "snapshot_id");
    if (!id) return std::unexpected(std::move(id.error()));
    auto descriptor = snapshots_->descriptor(*id);
    if (!descriptor) return std::unexpected(tools::invalid(descriptor.error()));
    if (descriptor->session_id != session->id())
      return std::unexpected(tools::invalid("Snapshot belongs to a different process session"));
    const auto mode_name = arguments.value("comparison", std::string{});
    const auto mode = comparison(mode_name);
    if (!mode) return std::unexpected(tools::invalid("Unknown comparison"));
    const auto max_results = arguments.value("max_results", std::size_t{256});
    if (max_results == 0 || max_results > 4096)
      return std::unexpected(tools::invalid("max_results must be between 1 and 4096"));
    auto current = processes_->read(*session, descriptor->address, descriptor->length);
    if (!current) return std::unexpected(tools::process_error(current.error()));
    const bool refine = arguments.value("refine", true);
    auto compared = snapshots_->compare(*id, *current, *mode, max_results, refine);
    if (!compared) return std::unexpected(tools::invalid(compared.error()));
    Json matches = Json::array();
    for (const auto& match : compared->matches) {
      const auto before = std::span{match.before}.first(match.size);
      const auto after = std::span{match.after}.first(match.size);
      matches.push_back({{"address", tools::hex_u64(descriptor->address + match.offset)},
        {"offset", match.offset}, {"before_hex", tools::hex_bytes(before)},
        {"after_hex", tools::hex_bytes(after)}});
    }
    return Json{{"snapshot_id", *id}, {"candidate_count", compared->candidate_count},
      {"matches", std::move(matches)}, {"truncated", compared->truncated}, {"refined", refine}};
  }
 private:
  std::shared_ptr<process::ProcessManager> processes_;
  std::shared_ptr<memory::SnapshotStore> snapshots_;
};

class DeleteMemorySnapshotTool final : public mcp::Tool {
 public:
  explicit DeleteMemorySnapshotTool(std::shared_ptr<memory::SnapshotStore> snapshots)
      : snapshots_(std::move(snapshots)) {}
  std::string_view name() const noexcept override { return "delete_memory_snapshot"; }
  std::string_view description() const noexcept override {
    return "Delete a memory snapshot and immediately release its bounded server-side storage.";
  }
  const Json& input_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"snapshot_id", {{"type", "integer"}, {"minimum", 1},
        {"description", "Snapshot identifier returned by create_memory_snapshot."}}}}},
      {"required", {"snapshot_id"}}, {"additionalProperties", false}};
    return value;
  }
  const Json& output_schema() const noexcept override {
    static const Json value{{"type", "object"}, {"properties", {
      {"deleted", {{"type", "boolean"}, {"description", "True when a live snapshot was removed."}}}}},
      {"required", {"deleted"}}, {"additionalProperties", false}}; return value;
  }
  const Json& annotations() const noexcept override {
    static const Json value{{"readOnlyHint", false}, {"destructiveHint", false},
      {"idempotentHint", true}, {"openWorldHint", false}}; return value;
  }
  mcp::ToolResult invoke(const Json& arguments) const override {
    auto id = tools::unsigned_value(arguments, "snapshot_id");
    if (!id) return std::unexpected(std::move(id.error()));
    return Json{{"deleted", snapshots_->remove(*id)}};
  }
 private:
  std::shared_ptr<memory::SnapshotStore> snapshots_;
};

}  // namespace

void register_memory_snapshot_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<process::ProcessManager>& processes) {
  auto snapshots = std::make_shared<memory::SnapshotStore>();
  if (!registry.add(std::make_unique<CreateMemorySnapshotTool>(processes, snapshots)) ||
      !registry.add(std::make_unique<CompareMemorySnapshotTool>(processes, snapshots)) ||
      !registry.add(std::make_unique<DeleteMemorySnapshotTool>(snapshots)))
    std::terminate();
}

}  // namespace reverseplugin
