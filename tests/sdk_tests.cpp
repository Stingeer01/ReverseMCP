#include <stdexcept>
#include <sstream>
#include <string>
#include <string_view>
#include <array>
#include <filesystem>
#include <ranges>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "reverseplugin/analysis/analysis_cache.hpp"
#include "reverseplugin/analysis/binary_image.hpp"
#include "reverseplugin/analysis/binary_store.hpp"
#include "reverseplugin/analysis/function_analyzer.hpp"
#include "reverseplugin/analysis/static_index.hpp"
#include "reverseplugin/mcp/server.hpp"
#include "reverseplugin/memory/pattern.hpp"
#include "reverseplugin/memory/snapshot_store.hpp"
#include "reverseplugin/tools.hpp"

namespace {

void expect(bool condition, std::string_view message) {
  if (!condition) {
    throw std::runtime_error(std::string{message});
  }
}

void registry_exposes_server_info() {
  reverseplugin::mcp::ToolRegistry registry;
  reverseplugin::register_builtin_tools(
      registry, std::make_shared<reverseplugin::process::ProcessManager>(),
      std::make_shared<reverseplugin::disasm::Disassembler>(),
      std::make_shared<reverseplugin::debug::DebugEngine>());
  const auto* tool = registry.find("get_server_info");
  expect(tool != nullptr, "get_server_info was not registered");
  const auto result = tool->invoke(nlohmann::json::object());
  expect(result.has_value(), "get_server_info failed");
  expect(result->at("language") == "C++23", "unexpected language metadata");
  expect(registry.find("write_memory") != nullptr, "write_memory was not registered");
  expect(registry.find("read_pointer_chain") != nullptr, "read_pointer_chain was not registered");
  expect(registry.find("scan_memory_pattern") != nullptr, "scan_memory_pattern was not registered");
  expect(registry.find("set_hardware_breakpoint") != nullptr, "hardware breakpoint tool was not registered");
  expect(registry.find("get_stack_trace") != nullptr, "stack trace tool was not registered");
  expect(registry.find("create_memory_snapshot") != nullptr, "snapshot creation tool was not registered");
  expect(registry.find("compare_memory_snapshot") != nullptr, "snapshot comparison tool was not registered");
  expect(registry.find("delete_memory_snapshot") != nullptr, "snapshot deletion tool was not registered");
  expect(registry.find("open_binary") != nullptr, "binary loader tool was not registered");
  expect(registry.find("get_binary_index") != nullptr, "binary index tool was not registered");
  expect(registry.find("analyze_binary_function") != nullptr, "function analysis tool was not registered");
  expect(registry.find("close_binary") != nullptr, "binary close tool was not registered");
  expect(registry.find("read_binary_bytes") != nullptr, "static byte reader was not registered");
  expect(registry.find("disassemble_binary") != nullptr, "static disassembler was not registered");
  expect(registry.find("scan_binary_pattern") != nullptr, "static pattern scanner was not registered");
  expect(registry.find("find_binary_strings") != nullptr, "string index tool was not registered");
  expect(registry.find("find_binary_xrefs") != nullptr, "xref tool was not registered");
  expect(registry.find("discover_binary_functions") != nullptr, "function discovery tool was not registered");
  expect(registry.find("set_binary_annotation") != nullptr, "annotation writer was not registered");
  expect(registry.find("get_binary_annotations") != nullptr, "annotation reader was not registered");
}

void server_handles_core_protocol() {
  std::istringstream input{
      R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}})"
      "\n"
      R"({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})"
      "\n"
      R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_server_info","arguments":{}}})"
      "\n"
      R"({"jsonrpc":2,"id":4,"method":"tools/list","params":{}})"
      "\n"};
  std::ostringstream output;
  reverseplugin::mcp::ToolRegistry registry;
  reverseplugin::register_builtin_tools(
      registry, std::make_shared<reverseplugin::process::ProcessManager>(),
      std::make_shared<reverseplugin::disasm::Disassembler>(),
      std::make_shared<reverseplugin::debug::DebugEngine>());
  {
    reverseplugin::mcp::Server server{std::move(registry), input, output, 1};
    expect(server.run() == 0, "server run failed");
  }

  std::istringstream responses{output.str()};
  std::string line;
  std::size_t count = 0;
  while (std::getline(responses, line)) {
    const auto response = nlohmann::json::parse(line);
    expect(response.at("jsonrpc") == "2.0", "invalid response envelope");
    ++count;
  }
  expect(count == 4, "unexpected response count");
}

void process_memory_round_trip() {
  std::array payload{std::byte{0x48}, std::byte{0x89},
                     std::byte{0xD8}, std::byte{0xC3}};
  reverseplugin::process::ProcessManager processes;
  auto session = processes.attach(GetCurrentProcessId());
  expect(session.has_value(), "could not attach to current process");
  const auto address = reinterpret_cast<std::uint64_t>(payload.data());
  auto bytes = processes.read(**session, address, payload.size());
  expect(bytes.has_value(), "could not read current process memory");
  expect(std::ranges::equal(*bytes, payload), "read memory did not match source bytes");
  constexpr std::array replacement{std::byte{0x90}, std::byte{0x90},
                                   std::byte{0x90}, std::byte{0xC3}};
  auto written = processes.write(**session, address, replacement);
  expect(written && *written == replacement.size(), "could not write current process memory");
  expect(std::ranges::equal(payload, replacement), "written bytes did not reach memory");
  expect(processes.detach((*session)->id()), "could not detach process session");
}

void pattern_parser_and_matcher_work() {
  auto pattern = reverseplugin::memory::Pattern::parse("48 8B ?? 89");
  expect(pattern.has_value(), "valid AOB pattern was rejected");
  constexpr std::array bytes{std::byte{0x90}, std::byte{0x48}, std::byte{0x8B},
                             std::byte{0x12}, std::byte{0x89}, std::byte{0x48},
                             std::byte{0x8B}, std::byte{0xFF}, std::byte{0x89}};
  const auto matches = pattern->find_all(bytes, 8);
  expect(matches == std::vector<std::size_t>({1, 5}), "AOB matches are incorrect");
  expect(!reverseplugin::memory::Pattern::parse("48 nope 89"), "invalid AOB was accepted");
}

void snapshot_store_refines_candidates() {
  std::array<std::uint32_t, 4> values{10, 20, 30, 40};
  const auto bytes = std::as_bytes(std::span{values});
  reverseplugin::memory::SnapshotStore snapshots;
  auto created = snapshots.create(
      7, 0x1000, std::vector<std::byte>{bytes.begin(), bytes.end()},
      reverseplugin::memory::ValueType::u32, sizeof(std::uint32_t));
  expect(created.has_value(), "could not create typed snapshot");

  values[1] = 21;
  values[2] = 29;
  auto changed = snapshots.compare(created->id, std::as_bytes(std::span{values}),
      reverseplugin::memory::Comparison::changed, 8, true);
  expect(changed && changed->candidate_count == 2,
         "changed comparison did not retain two candidates");
  expect(changed->matches[0].offset == 4 && changed->matches[1].offset == 8,
         "changed comparison returned wrong offsets");

  values[1] = 22;
  auto increased = snapshots.compare(created->id, std::as_bytes(std::span{values}),
      reverseplugin::memory::Comparison::increased, 8, true);
  expect(increased && increased->candidate_count == 1,
         "iterative snapshot refinement did not isolate the increasing value");
  expect(increased->matches[0].offset == 4,
         "iterative snapshot refinement retained the wrong value");
  expect(snapshots.remove(created->id), "could not delete typed snapshot");
}

void memory_tools_work_end_to_end() {
  constexpr std::size_t allocation_size = 2U * 1024 * 1024;
  auto* allocation = static_cast<std::byte*>(VirtualAlloc(
      nullptr, allocation_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  expect(allocation != nullptr, "VirtualAlloc failed");
  struct AllocationGuard final {
    void* value;
    ~AllocationGuard() { VirtualFree(value, 0, MEM_RELEASE); }
  } guard{allocation};
  std::ranges::fill(std::span{allocation, allocation_size}, std::byte{0});
  const auto signature_offset = 1024U * 1024 - 2;
  constexpr std::array signature{std::byte{0xDE}, std::byte{0xAD},
                                 std::byte{0xBE}, std::byte{0xEF}};
  std::ranges::copy(signature, allocation + signature_offset);

  auto processes = std::make_shared<reverseplugin::process::ProcessManager>();
  auto session = processes->attach(GetCurrentProcessId());
  expect(session.has_value(), "self attach for tool tests failed");
  reverseplugin::mcp::ToolRegistry registry;
  reverseplugin::register_builtin_tools(
      registry, processes, std::make_shared<reverseplugin::disasm::Disassembler>(),
      std::make_shared<reverseplugin::debug::DebugEngine>());
  const auto address = reinterpret_cast<std::uint64_t>(allocation);

  const auto scan = registry.find("scan_memory_pattern")->invoke({
      {"session_id", (*session)->id()}, {"start_address", address},
      {"size", allocation_size}, {"pattern", "DE AD ?? EF"}, {"max_results", 8}});
  expect(scan && scan->at("match_count") == 1, "scan_memory_pattern failed");
  expect(scan->at("matches").at(0) ==
             (std::string{"0x"} + [&] {
               std::ostringstream text; text << std::hex << address + signature_offset;
               return text.str();
             }()),
         "cross-chunk AOB address is incorrect");

  const auto write = registry.find("write_memory")->invoke({
      {"session_id", (*session)->id()}, {"address", address},
      {"hex", "11223344"}, {"verify", true}});
  expect(write && write->at("verified") == true, "write_memory failed");

  auto* typed_values = reinterpret_cast<std::uint32_t*>(allocation + 64);
  typed_values[0] = 10;
  typed_values[1] = 20;
  typed_values[2] = 30;
  typed_values[3] = 40;
  const auto snapshot = registry.find("create_memory_snapshot")->invoke({
      {"session_id", (*session)->id()},
      {"address", reinterpret_cast<std::uint64_t>(typed_values)},
      {"length", 4 * sizeof(std::uint32_t)}, {"value_type", "u32"}});
  expect(snapshot && snapshot->at("candidate_count") == 4,
         "create_memory_snapshot failed");
  typed_values[1] = 21;
  typed_values[2] = 29;
  const auto compared = registry.find("compare_memory_snapshot")->invoke({
      {"session_id", (*session)->id()},
      {"snapshot_id", snapshot->at("snapshot_id")},
      {"comparison", "changed"}, {"refine", true}, {"max_results", 8}});
  expect(compared && compared->at("candidate_count") == 2,
         "compare_memory_snapshot failed");
  const auto deleted = registry.find("delete_memory_snapshot")->invoke(
      {{"snapshot_id", snapshot->at("snapshot_id")}});
  expect(deleted && deleted->at("deleted") == true,
         "delete_memory_snapshot failed");

  std::uint64_t terminal = 0x12345678;
  std::uint64_t second = reinterpret_cast<std::uint64_t>(&terminal);
  std::uint64_t first = reinterpret_cast<std::uint64_t>(&second);
  const auto chain = registry.find("read_pointer_chain")->invoke({
      {"session_id", (*session)->id()},
      {"base_address", reinterpret_cast<std::uint64_t>(&first)},
      {"offsets", {0, 0}}, {"pointer_width", "64"}});
  expect(chain && chain->at("final_address") ==
              (std::string{"0x"} + [&] {
                std::ostringstream text; text << std::hex << reinterpret_cast<std::uint64_t>(&terminal);
                return text.str();
              }()),
         "read_pointer_chain failed");
}

void zydis_decodes_structured_instructions() {
  constexpr std::array bytes{std::byte{0x48}, std::byte{0x89},
                             std::byte{0xD8}, std::byte{0xC3}};
  reverseplugin::disasm::Disassembler disassembler;
  auto decoded = disassembler.decode(bytes, 0x140001000, 2,
                                     reverseplugin::disasm::Mode::x64,
                                     reverseplugin::disasm::Syntax::intel);
  expect(decoded.has_value(), "Zydis decode failed");
  expect(decoded->size() == 2, "unexpected instruction count");
  expect(decoded->at(0).mnemonic == "mov", "first instruction is not mov");
  expect(decoded->at(1).mnemonic == "ret", "second instruction is not ret");
  expect(!decoded->at(0).registers_read.empty(), "register reads were not collected");
  expect(!decoded->at(0).registers_written.empty(), "register writes were not collected");
}

std::filesystem::path current_executable() {
  std::array<wchar_t, 32768> path{};
  const auto length = GetModuleFileNameW(nullptr, path.data(),
                                         static_cast<DWORD>(path.size()));
  expect(length > 0 && length < path.size(), "could not resolve current executable");
  return std::filesystem::path{path.data(), path.data() + length};
}

void static_binary_analysis_works() {
  const auto path = current_executable();
  auto image = reverseplugin::analysis::BinaryImage::open(path);
  expect(image.has_value(), "could not parse current PE image");
  expect((*image)->info().format == "PE", "binary format was not identified");
  expect(!(*image)->sections().empty(), "PE sections were not indexed");
  expect((*image)->contains_rva((*image)->info().entry_rva),
         "PE entry point is outside the image");
  auto entry_bytes = (*image)->bytes_at((*image)->info().entry_rva, 32);
  expect(entry_bytes && !entry_bytes->empty(), "PE entry point has no file bytes");

  reverseplugin::disasm::Disassembler disassembler;
  auto function = reverseplugin::analysis::analyze_function(
      **image, disassembler, (*image)->info().entry_rva, 16384, 256);
  expect(function && !function->blocks.empty(), "entry-point CFG recovery failed");
  expect(function->instruction_count > 0, "entry-point analysis decoded no instructions");

  reverseplugin::analysis::BinaryStore binaries;
  auto first = binaries.open(path);
  auto second = binaries.open(path);
  expect(first && second && first->id == second->id && second->cache_hit,
         "unchanged binary was not reused from memory cache");
  expect(binaries.close(first->id), "binary workspace did not close");

  const auto cache_path = std::filesystem::temp_directory_path() /
                          ("reverseplugin-cache-test-" +
                           std::to_string(GetCurrentProcessId()));
  std::error_code ec;
  std::filesystem::remove_all(cache_path, ec);
  reverseplugin::analysis::AnalysisCache cache{cache_path};
  expect(cache.store("abcdef", "function_1", {{"value", 42}}),
         "persistent analysis cache write failed");
  expect(!cache.store("../escape", "function_1", {{"value", 42}}),
         "persistent analysis cache accepted an unsafe fingerprint");
  auto cached = cache.load("abcdef", "function_1");
  expect(cached && cached->at("value") == 42,
         "persistent analysis cache read failed");
  const auto bounded_strings = reverseplugin::analysis::scan_strings(
      **image, 3, 1000, 128);
  expect(bounded_strings.bytes_scanned <= 128 && bounded_strings.truncated,
         "string scan did not honor its byte budget");
  std::filesystem::remove_all(cache_path, ec);
}

void static_analysis_tools_work_end_to_end() {
  reverseplugin::mcp::ToolRegistry registry;
  reverseplugin::register_builtin_tools(
      registry, std::make_shared<reverseplugin::process::ProcessManager>(),
      std::make_shared<reverseplugin::disasm::Disassembler>(),
      std::make_shared<reverseplugin::debug::DebugEngine>());
  const auto path = current_executable().generic_string();
  auto opened = registry.find("open_binary")->invoke({{"path", path}});
  expect(opened.has_value(), "open_binary failed for current executable");
  const auto id = opened->at("binary_id");
  auto sections = registry.find("get_binary_index")->invoke(
      {{"binary_id", id}, {"kind", "sections"}, {"limit", 16}});
  expect(sections && sections->at("total").get<std::size_t>() > 0,
         "get_binary_index returned no sections");
  auto analysis = registry.find("analyze_binary_function")->invoke({
      {"binary_id", id}, {"address", opened->at("entry_rva")},
      {"max_bytes", 16384}, {"max_blocks", 256}, {"use_cache", true}});
  expect(analysis && analysis->at("instruction_count").get<std::size_t>() > 0,
         "analyze_binary_function decoded no instructions");
  auto cached_analysis = registry.find("analyze_binary_function")->invoke({
      {"binary_id", id}, {"address", opened->at("entry_rva")},
      {"max_bytes", 16384}, {"max_blocks", 256}, {"use_cache", true}});
  expect(cached_analysis && cached_analysis->at("cache_hit") == true,
         "function analysis was not reused from persistent cache");

  auto bytes = registry.find("read_binary_bytes")->invoke({
      {"binary_id", id}, {"address", opened->at("entry_rva")}, {"length", 16}});
  expect(bytes && bytes->at("length").get<std::size_t>() == 16,
         "read_binary_bytes failed");
  auto disassembled = registry.find("disassemble_binary")->invoke({
      {"binary_id", id}, {"address", opened->at("entry_rva")},
      {"max_bytes", 64}, {"max_instructions", 8}});
  expect(disassembled && disassembled->at("instruction_count").get<std::size_t>() > 0,
         "disassemble_binary failed");

  const auto entry_hex = bytes->at("hex").get<std::string>().substr(0, 8);
  std::string pattern;
  for (std::size_t i = 0; i < entry_hex.size(); i += 2) {
    if (!pattern.empty()) pattern.push_back(' ');
    pattern.append(entry_hex, i, 2);
  }
  auto pattern_matches = registry.find("scan_binary_pattern")->invoke({
      {"binary_id", id}, {"pattern", pattern}, {"executable_only", true},
      {"max_results", 16}});
  expect(pattern_matches && pattern_matches->at("match_count").get<std::size_t>() > 0,
         "scan_binary_pattern failed");

  auto strings = registry.find("find_binary_strings")->invoke({
      {"binary_id", id}, {"minimum_length", 4}, {"max_results", 1024},
      {"use_cache", false}});
  expect(strings && strings->at("string_count").get<std::size_t>() > 0,
         "find_binary_strings failed");
  auto xrefs = registry.find("find_binary_xrefs")->invoke({
      {"binary_id", id}, {"target", opened->at("entry_rva")},
      {"max_scan_bytes", 1048576}, {"max_results", 128}, {"use_cache", false}});
  expect(xrefs.has_value(), "find_binary_xrefs failed");
  auto functions = registry.find("discover_binary_functions")->invoke({
      {"binary_id", id}, {"max_functions", 512}, {"max_total_bytes", 2097152},
      {"use_cache", false}});
  expect(functions && functions->at("function_count").get<std::size_t>() > 0,
         "discover_binary_functions failed");

  auto annotation = registry.find("set_binary_annotation")->invoke({
      {"binary_id", id}, {"address", opened->at("entry_rva")},
      {"name", "test_entry"}, {"comment", "integration annotation"},
      {"type", "void entry()"}});
  expect(annotation && annotation->at("stored") == true,
         "set_binary_annotation failed");
  auto annotations = registry.find("get_binary_annotations")->invoke({
      {"binary_id", id}, {"limit", 32}});
  expect(annotations && annotations->at("total").get<std::size_t>() > 0,
         "get_binary_annotations failed");
  auto removed_annotation = registry.find("set_binary_annotation")->invoke({
      {"binary_id", id}, {"address", opened->at("entry_rva")}, {"remove", true}});
  expect(removed_annotation && removed_annotation->at("removed") == true,
         "binary annotation cleanup failed");
  auto closed = registry.find("close_binary")->invoke({{"binary_id", id}});
  expect(closed && closed->at("closed") == true, "close_binary failed");
}

}  // namespace

int main() {
  registry_exposes_server_info();
  server_handles_core_protocol();
  process_memory_round_trip();
  zydis_decodes_structured_instructions();
  static_binary_analysis_works();
  static_analysis_tools_work_end_to_end();
  pattern_parser_and_matcher_work();
  snapshot_store_refines_candidates();
  memory_tools_work_end_to_end();
}
#include <array>
#include <cstddef>
