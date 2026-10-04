#include "reverseplugin/tools.hpp"

#include <charconv>
#include <format>
#include <limits>
#include <memory>
#include <string>
#include <unordered_set>

#include "reverseplugin/analysis/analysis_cache.hpp"
#include "reverseplugin/analysis/binary_store.hpp"
#include "reverseplugin/analysis/decompiler.hpp"
#include "tool_support.hpp"

namespace reverseplugin {
namespace {

using mcp::Json;

std::optional<std::uint64_t> parse_hex(std::string_view text) {
  if (text.starts_with("0x")) text.remove_prefix(2);
  std::uint64_t value = 0;
  const auto [end, error] = std::from_chars(
      text.data(), text.data() + text.size(), value, 16);
  if (error != std::errc{} || end != text.data() + text.size()) return std::nullopt;
  return value;
}

void apply_annotations(Json& result, const analysis::BinaryImage& image,
                       const analysis::AnalysisCache& cache,
                       std::uint32_t entry_rva) {
  result["function_name"] = std::format("function_{:x}", entry_rva);
  result["prototype"] = "";
  result["annotations"] = Json::array();
  const auto database = cache.load(image.info().fingerprint, "annotations_v1");
  if (!database) return;
  const auto entries = database->value("entries", Json::object());
  if (!entries.is_object()) return;

  const auto function = entries.find(std::to_string(entry_rva));
  if (function != entries.end() && function->is_object()) {
    if (function->contains("name") && (*function)["name"].is_string())
      result["function_name"] = (*function)["name"];
    if (function->contains("type") && (*function)["type"].is_string())
      result["prototype"] = (*function)["type"];
  }

  std::unordered_set<std::uint32_t> relevant{entry_rva};
  for (auto& block : result["blocks"]) {
    if (const auto rva = parse_hex(block.value("rva", ""));
        rva && *rva <= std::numeric_limits<std::uint32_t>::max())
      relevant.insert(static_cast<std::uint32_t>(*rva));
    for (auto& statement : block["statements"]) {
      if (const auto address = parse_hex(statement.value("address", ""));
          address && *address >= image.info().image_base &&
          *address - image.info().image_base <=
              std::numeric_limits<std::uint32_t>::max())
        relevant.insert(static_cast<std::uint32_t>(*address - image.info().image_base));
      if (!statement["target_rva"].is_string()) continue;
      const auto target = parse_hex(statement["target_rva"].get_ref<const std::string&>());
      if (!target || *target > std::numeric_limits<std::uint32_t>::max()) continue;
      relevant.insert(static_cast<std::uint32_t>(*target));
      const auto annotation = entries.find(std::to_string(*target));
      if (annotation != entries.end() && annotation->is_object() &&
          annotation->contains("name") && (*annotation)["name"].is_string())
        statement["target_name"] = (*annotation)["name"];
    }
  }
  for (const auto rva : relevant) {
    const auto annotation = entries.find(std::to_string(rva));
    if (annotation == entries.end() || !annotation->is_object()) continue;
    auto value = *annotation;
    value["rva"] = tools::hex_u64(rva);
    result["annotations"].push_back(std::move(value));
  }
}

Json edge_json(const analysis::ControlFlowEdge& edge) {
  return {{"from_rva", tools::hex_u64(edge.from_rva)},
          {"to_rva", tools::hex_u64(edge.to_rva)},
          {"type", edge.type}};
}

Json reference_json(const analysis::CodeReference& reference) {
  return {{"from_rva", tools::hex_u64(reference.from_rva)},
          {"to_rva", tools::hex_u64(reference.to_rva)},
          {"type", reference.type}};
}

Json decompilation_json(const analysis::BinaryImage& image,
                        const analysis::Decompilation& decompiled) {
  Json blocks = Json::array();
  for (const auto& block : decompiled.blocks) {
    Json statements = Json::array();
    for (const auto& value : block.statements) {
      Json ssa_uses = Json::array();
      for (const auto& use : value.ssa_uses)
        ssa_uses.push_back({{"storage", use.storage}, {"value", use.value},
                            {"role", use.role}, {"offset_bits", use.offset_bits},
                            {"size_bits", use.size_bits}});
      Json ssa_definitions = Json::array();
      for (const auto& definition : value.ssa_definitions)
        ssa_definitions.push_back(
            {{"storage", definition.storage}, {"value", definition.value},
             {"previous_value", definition.previous_value},
             {"write", definition.write}, {"role", definition.role},
             {"offset_bits", definition.offset_bits},
             {"size_bits", definition.size_bits}});
      Json memory_accesses = Json::array();
      for (const auto& memory : value.memory_accesses)
        memory_accesses.push_back(
            {{"action", memory.action}, {"address", memory.address},
             {"alias_set", memory.alias_set}, {"size_bits", memory.size_bits},
             {"ssa_input", memory.ssa_input.empty() ? Json(nullptr)
                                                      : Json(memory.ssa_input)},
             {"ssa_output", memory.ssa_output.empty() ? Json(nullptr)
                                                        : Json(memory.ssa_output)}});
      statements.push_back({{"address", tools::hex_u64(value.address)},
                            {"operation", value.operation},
                            {"text", value.text},
                            {"source", value.source},
                            {"target_rva", value.target_rva
                                               ? Json(tools::hex_u64(*value.target_rva))
                                               : Json(nullptr)},
                            {"target_name", value.target_name},
                            {"indirect", value.indirect},
                            {"definitions", value.definitions},
                            {"uses", value.uses},
                            {"ssa_definitions", std::move(ssa_definitions)},
                            {"ssa_uses", std::move(ssa_uses)},
                            {"memory_accesses", std::move(memory_accesses)},
                            {"confidence", value.confidence}});
    }
    Json phi_nodes = Json::array();
    for (const auto& phi : block.phi_nodes) {
      Json inputs = Json::array();
      for (const auto& input : phi.inputs)
        inputs.push_back(
            {{"predecessor_rva", input.function_entry
                                     ? Json(nullptr)
                                     : Json(tools::hex_u64(input.predecessor_rva))},
             {"value", input.value},
             {"function_entry", input.function_entry}});
      phi_nodes.push_back({{"storage", phi.storage}, {"output", phi.output},
                           {"inputs", std::move(inputs)}});
    }
    blocks.push_back({{"rva", tools::hex_u64(block.rva)},
                      {"address", tools::hex_u64(image.info().image_base + block.rva)},
                      {"phi_nodes", std::move(phi_nodes)},
                      {"statements", std::move(statements)}});
  }

  Json stack_variables = Json::array();
  for (const auto& variable : decompiled.stack_variables) {
    Json references = Json::array();
    for (const auto address : variable.references)
      references.push_back(tools::hex_u64(address));
    stack_variables.push_back({{"name", variable.name},
                               {"storage", variable.storage},
                               {"role", variable.role},
                               {"offset", variable.offset},
                               {"entry_sp_offset", variable.entry_sp_offset
                                                       ? Json(*variable.entry_sp_offset)
                                                       : Json(nullptr)},
                               {"size_bits", variable.size_bits},
                               {"confidence", variable.confidence},
                               {"references", std::move(references)}});
  }

  Json parameters = Json::array();
  for (const auto& parameter : decompiled.parameters) {
    Json evidence = Json::array();
    for (const auto address : parameter.evidence)
      evidence.push_back(tools::hex_u64(address));
    parameters.push_back({{"name", parameter.name},
                          {"storage", parameter.storage},
                          {"size_bits", parameter.size_bits},
                          {"evidence", std::move(evidence)}});
  }

  Json edges = Json::array();
  for (const auto& edge : decompiled.edges) edges.push_back(edge_json(edge));
  Json references = Json::array();
  for (const auto& reference : decompiled.references)
    references.push_back(reference_json(reference));

  Json control_regions = Json::array();
  for (const auto& region : decompiled.control_regions) {
    Json entries = Json::array();
    Json members = Json::array();
    Json exits = Json::array();
    for (const auto value : region.entries) entries.push_back(tools::hex_u64(value));
    for (const auto value : region.members) members.push_back(tools::hex_u64(value));
    for (const auto value : region.exits) exits.push_back(tools::hex_u64(value));
    control_regions.push_back(
        {{"kind", region.kind}, {"header_rva", tools::hex_u64(region.header_rva)},
         {"merge_rva", region.merge_rva == 0 ? Json(nullptr)
                                               : Json(tools::hex_u64(region.merge_rva))},
         {"entries", std::move(entries)}, {"members", std::move(members)},
         {"exits", std::move(exits)}, {"confidence", region.confidence}});
  }

  Json type_evidence = Json::array();
  for (const auto& evidence : decompiled.type_evidence) {
    Json addresses = Json::array();
    for (const auto address : evidence.evidence)
      addresses.push_back(tools::hex_u64(address));
    type_evidence.push_back(
        {{"storage", evidence.storage}, {"kind", evidence.kind},
         {"size_bits", evidence.size_bits}, {"signedness", evidence.signedness},
         {"confidence", evidence.confidence}, {"evidence", std::move(addresses)}});
  }

  Json field_evidence = Json::array();
  for (const auto& field : decompiled.field_evidence) {
    Json addresses = Json::array();
    for (const auto address : field.evidence)
      addresses.push_back(tools::hex_u64(address));
    field_evidence.push_back(
        {{"base_storage", field.base_storage},
         {"index_storage", field.index_storage}, {"offset", field.offset},
         {"scale", field.scale}, {"size_bits", field.size_bits},
         {"read", field.read}, {"written", field.written},
         {"kind", field.kind}, {"evidence", std::move(addresses)}});
  }

  return {{"entry_rva", tools::hex_u64(decompiled.entry_rva)},
          {"entry_address",
           tools::hex_u64(image.info().image_base + decompiled.entry_rva)},
          {"architecture", decompiled.architecture},
          {"function_name", std::format("function_{:x}", decompiled.entry_rva)},
          {"prototype", ""},
          {"calling_convention", decompiled.calling_convention},
          {"blocks", std::move(blocks)},
          {"edges", std::move(edges)},
          {"references", std::move(references)},
          {"parameters", std::move(parameters)},
          {"stack_variables", std::move(stack_variables)},
          {"control_regions", std::move(control_regions)},
          {"type_evidence", std::move(type_evidence)},
          {"field_evidence", std::move(field_evidence)},
          {"pseudocode", decompiled.pseudocode},
          {"warnings", decompiled.warnings},
          {"annotations", Json::array()},
          {"instruction_count", decompiled.instruction_count},
          {"lifted_instruction_count", decompiled.lifted_instruction_count},
          {"phi_count", decompiled.phi_count},
          {"ssa_converged", decompiled.ssa_converged},
          {"truncated", decompiled.truncated},
          {"cache_hit", false}};
}

class DecompileBinaryFunctionTool final : public mcp::Tool {
 public:
  DecompileBinaryFunctionTool(
      std::shared_ptr<analysis::BinaryStore> binaries,
      std::shared_ptr<analysis::AnalysisCache> cache,
      std::shared_ptr<disasm::Disassembler> disassembler)
      : binaries_(std::move(binaries)),
        cache_(std::move(cache)),
        disassembler_(std::move(disassembler)) {}

  std::string_view name() const noexcept override {
    return "decompile_binary_function";
  }

  std::string_view description() const noexcept override {
    return "Lift a bounded x86/x64 PE function into conservative C-like pseudocode and structured semantic IR. Returns canonical register slices, inter-block SSA definitions and uses, phi nodes, natural loops, conditional merge regions, type evidence, CFG edges, direct calls, ABI parameter candidates, stack variables, per-statement confidence, and explicit warnings for unmodeled semantics. Unsupported instructions remain visible as intrinsics instead of being guessed.";
  }

  const Json& input_schema() const noexcept override {
    static const Json value{
        {"type", "object"},
        {"properties",
         {{"binary_id",
           {{"type", "integer"},
            {"minimum", 1},
            {"description", "Identifier returned by open_binary."}}},
          {"address", tools::address_schema()},
          {"max_bytes",
           {{"type", "integer"},
            {"minimum", 1},
            {"maximum", 1048576},
            {"default", 65536},
            {"description", "Maximum instruction bytes lifted across the function CFG."}}},
          {"max_blocks",
           {{"type", "integer"},
            {"minimum", 1},
            {"maximum", 4096},
            {"default", 1024},
            {"description", "Maximum reachable basic blocks lifted."}}},
          {"use_cache",
           {{"type", "boolean"},
            {"default", true},
            {"description", "Reuse deterministic results keyed by binary fingerprint, function RVA, and analysis budgets."}}}}},
        {"required", {"binary_id", "address"}},
        {"additionalProperties", false}};
    return value;
  }

  const Json& output_schema() const noexcept override {
    static const Json value = [] {
      const Json ssa_use{
          {"type", "object"},
          {"properties",
           {{"storage", {{"type", "string"}, {"description", "Canonical register or memory alias set."}}},
            {"value", {{"type", "string"}, {"description", "SSA version consumed by this statement."}}},
            {"role", {{"type", "string"}, {"description", "Ordinary input, partial-write dependency, or ABI argument candidate."}}},
            {"offset_bits", {{"type", "integer"}}},
            {"size_bits", {{"type", "integer"}}}}},
          {"required", {"storage", "value", "role", "offset_bits", "size_bits"}},
          {"additionalProperties", false}};
      const Json ssa_definition{
          {"type", "object"},
          {"properties",
           {{"storage", {{"type", "string"}, {"description", "Canonical register or memory alias set."}}},
            {"value", {{"type", "string"}, {"description", "New SSA version."}}},
            {"previous_value", {{"type", "string"}, {"description", "Prior version required for a partial update; empty for complete writes."}}},
            {"write", {{"type", "string"}, {"description", "Full, partial, zero-extension, or call-clobber write semantics."}}},
            {"role", {{"type", "string"}}},
            {"offset_bits", {{"type", "integer"}}},
            {"size_bits", {{"type", "integer"}}}}},
          {"required", {"storage", "value", "previous_value", "write", "role",
                         "offset_bits", "size_bits"}},
          {"additionalProperties", false}};
      const Json memory_access{
          {"type", "object"},
          {"properties",
           {{"action", {{"type", "string"}, {"description", "Read, write, or read_write."}}},
            {"address", {{"type", "string"}, {"description", "Rendered effective-address expression."}}},
            {"alias_set", {{"type", "string"}, {"description", "Conservative memory-SSA identity; memory:unknown may alias any unresolved access."}}},
            {"size_bits", {{"type", "integer"}}},
            {"ssa_input", {{"type", "string"}, {"description", "Memory version read, or empty when no read occurs."}}},
            {"ssa_output", {{"type", "string"}, {"description", "Memory version written, or empty when no write occurs."}}}}},
          {"required", {"action", "address", "alias_set", "size_bits",
                         "ssa_input", "ssa_output"}},
          {"additionalProperties", false}};
      const Json phi_input{
          {"type", "object"},
          {"properties",
           {{"predecessor_rva", {{"type", {"string", "null"}}, {"description", "Incoming CFG predecessor, or null for the function-entry value."}}},
            {"value", {{"type", "string"}}},
            {"function_entry", {{"type", "boolean"}}}}},
          {"required", {"predecessor_rva", "value", "function_entry"}},
          {"additionalProperties", false}};
      const Json phi_node{
          {"type", "object"},
          {"properties",
           {{"storage", {{"type", "string"}, {"description", "Canonical register or memory alias set being merged."}}},
            {"output", {{"type", "string"}, {"description", "SSA version defined by the phi node."}}},
            {"inputs", {{"type", "array"}, {"items", phi_input}}}}},
          {"required", {"storage", "output", "inputs"}},
          {"additionalProperties", false}};
      const Json statement{
          {"type", "object"},
          {"properties",
           {{"address", {{"type", "string"}}},
            {"operation", {{"type", "string"}}},
            {"text", {{"type", "string"}}},
            {"source", {{"type", "string"}}},
            {"target_rva", {{"type", {"string", "null"}}}},
            {"target_name", {{"type", "string"}}},
            {"indirect", {{"type", "boolean"}}},
            {"definitions", {{"type", "array"}, {"items", {{"type", "string"}}}}},
            {"uses", {{"type", "array"}, {"items", {{"type", "string"}}}}},
            {"ssa_definitions", {{"type", "array"}, {"items", ssa_definition}}},
            {"ssa_uses", {{"type", "array"}, {"items", ssa_use}}},
            {"memory_accesses", {{"type", "array"}, {"items", memory_access}}},
            {"confidence",
             {{"type", "string"},
              {"enum", {"exact", "inferred", "partial", "unmodeled"}}}}}},
          {"required", {"address", "operation", "text", "source", "target_rva",
                         "target_name", "indirect", "definitions",
                         "uses", "ssa_definitions", "ssa_uses", "memory_accesses",
                         "confidence"}},
          {"additionalProperties", false}};
      const Json block{
          {"type", "object"},
          {"properties",
           {{"rva", {{"type", "string"}}},
            {"address", {{"type", "string"}}},
            {"phi_nodes", {{"type", "array"}, {"items", phi_node}}},
            {"statements", {{"type", "array"}, {"items", statement}}}}},
          {"required", {"rva", "address", "phi_nodes", "statements"}},
          {"additionalProperties", false}};
      const Json edge{
          {"type", "object"},
          {"properties",
           {{"from_rva", {{"type", "string"}}},
            {"to_rva", {{"type", "string"}}},
            {"type", {{"type", "string"}}}}},
          {"required", {"from_rva", "to_rva", "type"}},
          {"additionalProperties", false}};
      const Json parameter{
          {"type", "object"},
          {"properties",
           {{"name", {{"type", "string"}}},
            {"storage", {{"type", "string"}}},
            {"size_bits", {{"type", "integer"}}},
            {"evidence", {{"type", "array"}, {"items", {{"type", "string"}}}}}}},
          {"required", {"name", "storage", "size_bits", "evidence"}},
          {"additionalProperties", false}};
      const Json variable{
          {"type", "object"},
          {"properties",
           {{"name", {{"type", "string"}}},
            {"storage", {{"type", "string"}}},
            {"role", {{"type", "string"}}},
            {"offset", {{"type", "integer"}}},
            {"entry_sp_offset", {{"type", {"integer", "null"}}}},
            {"size_bits", {{"type", "integer"}}},
            {"confidence", {{"type", "string"}}},
            {"references", {{"type", "array"}, {"items", {{"type", "string"}}}}}}},
          {"required", {"name", "storage", "role", "offset", "entry_sp_offset",
                         "size_bits", "confidence", "references"}},
          {"additionalProperties", false}};
      const Json control_region{
          {"type", "object"},
          {"properties",
           {{"kind", {{"type", "string"}, {"enum", {"natural_loop", "conditional"}}}},
            {"header_rva", {{"type", "string"}}},
            {"merge_rva", {{"type", {"string", "null"}}}},
            {"entries", {{"type", "array"}, {"items", {{"type", "string"}}}}},
            {"members", {{"type", "array"}, {"items", {{"type", "string"}}}}},
            {"exits", {{"type", "array"}, {"items", {{"type", "string"}}}}},
            {"confidence", {{"type", "string"}}}}},
          {"required", {"kind", "header_rva", "merge_rva", "entries", "members",
                         "exits", "confidence"}},
          {"additionalProperties", false}};
      const Json type_evidence{
          {"type", "object"},
          {"properties",
           {{"storage", {{"type", "string"}, {"description", "Canonical register or stack location."}}},
            {"kind", {{"type", "string"}, {"description", "Pointer, boolean, integer, or stack-object hypothesis."}}},
            {"size_bits", {{"type", "integer"}}},
            {"signedness", {{"type", "string"}}},
            {"confidence", {{"type", "string"}}},
            {"evidence", {{"type", "array"}, {"items", {{"type", "string"}}}}}}},
          {"required", {"storage", "kind", "size_bits", "signedness", "confidence",
                         "evidence"}},
          {"additionalProperties", false}};
      const Json field_evidence{
          {"type", "object"},
          {"properties",
           {{"base_storage", {{"type", "string"}}},
            {"index_storage", {{"type", "string"}}},
            {"offset", {{"type", "integer"}}},
            {"scale", {{"type", "integer"}}},
            {"size_bits", {{"type", "integer"}}},
            {"read", {{"type", "boolean"}}},
            {"written", {{"type", "boolean"}}},
            {"kind", {{"type", "string"}, {"description", "Object-field or indexed-element access hypothesis."}}},
            {"evidence", {{"type", "array"}, {"items", {{"type", "string"}}}}}}},
          {"required", {"base_storage", "index_storage", "offset", "scale", "size_bits",
                         "read", "written", "kind", "evidence"}},
          {"additionalProperties", false}};
      const Json annotation{
          {"type", "object"},
          {"properties",
           {{"rva", {{"type", "string"}}}, {"name", {{"type", "string"}}},
            {"comment", {{"type", "string"}}}, {"type", {{"type", "string"}}}}},
          {"required", {"rva"}},
          {"additionalProperties", false}};
      return Json{
          {"type", "object"},
          {"properties",
           {{"entry_rva", {{"type", "string"}}},
            {"entry_address", {{"type", "string"}}},
            {"architecture", {{"type", "string"}}},
            {"function_name", {{"type", "string"}}},
            {"prototype", {{"type", "string"}}},
            {"calling_convention", {{"type", "string"}}},
            {"blocks", {{"type", "array"}, {"items", block}}},
            {"edges", {{"type", "array"}, {"items", edge}}},
            {"references", {{"type", "array"}, {"items", edge}}},
            {"parameters", {{"type", "array"}, {"items", parameter}}},
            {"stack_variables", {{"type", "array"}, {"items", variable}}},
            {"control_regions", {{"type", "array"}, {"items", control_region}}},
            {"type_evidence", {{"type", "array"}, {"items", type_evidence}}},
            {"field_evidence", {{"type", "array"}, {"items", field_evidence}}},
            {"pseudocode", {{"type", "array"}, {"items", {{"type", "string"}}}}},
            {"warnings", {{"type", "array"}, {"items", {{"type", "string"}}}}},
            {"annotations", {{"type", "array"}, {"items", annotation}}},
            {"instruction_count", {{"type", "integer"}}},
            {"lifted_instruction_count", {{"type", "integer"}}},
            {"phi_count", {{"type", "integer"}}},
            {"ssa_converged", {{"type", "boolean"}}},
            {"truncated", {{"type", "boolean"}}},
            {"cache_hit", {{"type", "boolean"}}}}},
          {"required", {"entry_rva", "entry_address", "architecture",
                         "function_name", "prototype",
                         "calling_convention", "blocks", "edges", "references",
                         "parameters", "stack_variables", "control_regions",
                         "type_evidence", "pseudocode", "warnings", "annotations",
                         "field_evidence",
                         "instruction_count", "lifted_instruction_count", "phi_count",
                         "ssa_converged", "truncated", "cache_hit"}},
          {"additionalProperties", false}};
    }();
    return value;
  }

  const Json& annotations() const noexcept override {
    return tools::read_only_annotations();
  }

  mcp::ToolResult invoke(const Json& arguments) const override {
    auto id = tools::unsigned_value(arguments, "binary_id");
    if (!id) return std::unexpected(std::move(id.error()));
    auto image = binaries_->image(*id);
    if (!image)
      return std::unexpected(tools::invalid(
          "Unknown or closed binary workspace", {{"binary_id", *id}}));
    auto address = tools::unsigned_value(arguments, "address");
    if (!address) return std::unexpected(std::move(address.error()));
    auto rva = image->normalize_address(*address);
    if (!rva) return std::unexpected(tools::invalid(rva.error()));

    const auto max_bytes = arguments.value("max_bytes", std::size_t{65536});
    const auto max_blocks = arguments.value("max_blocks", std::size_t{1024});
    const bool use_cache = arguments.value("use_cache", true);
    const auto key = std::string{"decompile_v2_"} + std::to_string(*rva) + "_" +
                     std::to_string(max_bytes) + "_" + std::to_string(max_blocks);
    Json json;
    if (use_cache) {
      if (auto cached = cache_->load(image->info().fingerprint, key)) {
        json = std::move(*cached);
        json["cache_hit"] = true;
      }
    }
    if (json.is_null()) {
      auto result = analysis::decompile_function(
          *image, *disassembler_, *rva, max_bytes, max_blocks);
      if (!result) return std::unexpected(tools::invalid(result.error()));
      json = decompilation_json(*image, *result);
      if (use_cache)
        static_cast<void>(cache_->store(image->info().fingerprint, key, json));
    }
    apply_annotations(json, *image, *cache_, *rva);
    return json;
  }

 private:
  std::shared_ptr<analysis::BinaryStore> binaries_;
  std::shared_ptr<analysis::AnalysisCache> cache_;
  std::shared_ptr<disasm::Disassembler> disassembler_;
};

}  // namespace

void register_binary_decompiler_tools(
    mcp::ToolRegistry& registry,
    const std::shared_ptr<analysis::BinaryStore>& binaries,
    const std::shared_ptr<analysis::AnalysisCache>& cache,
    const std::shared_ptr<disasm::Disassembler>& disassembler) {
  if (!registry.add(std::make_unique<DecompileBinaryFunctionTool>(
          binaries, cache, disassembler)))
    std::terminate();
}

}  // namespace reverseplugin
