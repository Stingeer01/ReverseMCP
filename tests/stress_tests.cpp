#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

#include "reverseplugin/disasm/disassembler.hpp"
#include "reverseplugin/analysis/binary_image.hpp"
#include "reverseplugin/analysis/binary_store.hpp"
#include "reverseplugin/analysis/decompiler.hpp"
#include "reverseplugin/analysis/static_index.hpp"
#include "reverseplugin/memory/pattern.hpp"
#include "reverseplugin/memory/snapshot_store.hpp"
#include "reverseplugin/mcp/server.hpp"
#include "reverseplugin/process/process_manager.hpp"
#include "reverseplugin/tools.hpp"

namespace {

using Clock = std::chrono::steady_clock;

void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

void pattern_throughput() {
  constexpr std::size_t bytes_per_pass = 128U * 1024 * 1024;
  constexpr std::size_t passes = 8;
  std::vector<std::byte> data(bytes_per_pass, std::byte{0x90});
  constexpr std::array signature{std::byte{0x48}, std::byte{0x8B}, std::byte{0x05},
                                 std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
                                 std::byte{0xDD}, std::byte{0x48}, std::byte{0x85}};
  for (std::size_t offset = 4093; offset + signature.size() < data.size(); offset += 8U * 1024 * 1024)
    std::ranges::copy(signature, data.begin() + static_cast<std::ptrdiff_t>(offset));
  auto pattern = reverseplugin::memory::Pattern::parse("48 8B 05 ?? ?? ?? ?? 48 85");
  require(pattern.has_value(), "pattern parse failed");
  std::size_t matches = 0;
  const auto started = Clock::now();
  for (std::size_t pass = 0; pass < passes; ++pass)
    matches += pattern->find_all(data, 1024).size();
  const auto seconds = std::chrono::duration<double>(Clock::now() - started).count();
  require(matches > 0, "stress pattern scan found no matches");
  const auto gib = static_cast<double>(bytes_per_pass * passes) / (1024.0 * 1024.0 * 1024.0);
  std::cout << "AOB: " << gib / seconds << " GiB/s across " << gib << " GiB\n";
}

void concurrent_memory_reads() {
  constexpr std::array payload{std::byte{0x10}, std::byte{0x20}, std::byte{0x30}, std::byte{0x40}};
  reverseplugin::process::ProcessManager manager;
  auto session = manager.attach(GetCurrentProcessId());
  require(session.has_value(), "self attach failed");
  constexpr std::size_t workers = 8;
  constexpr std::size_t reads_per_worker = 25000;
  std::atomic_size_t failures{0};
  const auto started = Clock::now();
  std::vector<std::jthread> threads;
  for (std::size_t worker = 0; worker < workers; ++worker) {
    threads.emplace_back([&] {
      for (std::size_t index = 0; index < reads_per_worker; ++index) {
        auto bytes = manager.read(**session,
          reinterpret_cast<std::uint64_t>(payload.data()), payload.size());
        if (!bytes || !std::ranges::equal(*bytes, payload)) ++failures;
      }
    });
  }
  threads.clear();
  const auto seconds = std::chrono::duration<double>(Clock::now() - started).count();
  require(failures.load() == 0, "concurrent memory reads failed");
  std::cout << "ReadProcessMemory: " << (workers * reads_per_worker) / seconds
            << " ops/s on " << workers << " threads\n";
}

void snapshot_comparison_throughput() {
  constexpr std::size_t bytes_per_pass = 64U * 1024 * 1024;
  constexpr std::size_t passes = 8;
  std::vector<std::byte> baseline(bytes_per_pass, std::byte{0});
  std::vector<std::byte> current(bytes_per_pass, std::byte{1});
  reverseplugin::memory::SnapshotStore snapshots;
  auto snapshot = snapshots.create(1, 0x10000000, std::move(baseline),
      reverseplugin::memory::ValueType::u32, sizeof(std::uint32_t));
  require(snapshot.has_value(), "snapshot creation failed");
  std::size_t candidates = 0;
  const auto started = Clock::now();
  for (std::size_t pass = 0; pass < passes; ++pass) {
    auto result = snapshots.compare(snapshot->id, current,
        reverseplugin::memory::Comparison::changed, 1, false);
    require(result.has_value(), "snapshot comparison failed");
    candidates += result->candidate_count;
  }
  const auto seconds = std::chrono::duration<double>(Clock::now() - started).count();
  const auto gib = static_cast<double>(bytes_per_pass * passes) /
                   (1024.0 * 1024.0 * 1024.0);
  require(candidates == (bytes_per_pass / sizeof(std::uint32_t)) * passes,
          "snapshot comparison lost candidates");
  std::cout << "Typed snapshots: " << gib / seconds << " GiB/s across "
            << gib << " GiB\n";
}

void concurrent_disassembly() {
  constexpr std::array code{std::byte{0x48}, std::byte{0x8B}, std::byte{0xC1},
                            std::byte{0x48}, std::byte{0x83}, std::byte{0xC0},
                            std::byte{0x01}, std::byte{0xC3}};
  reverseplugin::disasm::Disassembler disassembler;
  constexpr std::size_t workers = 8;
  constexpr std::size_t iterations = 50000;
  std::atomic_size_t failures{0};
  const auto started = Clock::now();
  std::vector<std::jthread> threads;
  for (std::size_t worker = 0; worker < workers; ++worker) {
    threads.emplace_back([&] {
      for (std::size_t index = 0; index < iterations; ++index) {
        auto decoded = disassembler.decode(code, 0x140001000, 3,
          reverseplugin::disasm::Mode::x64, reverseplugin::disasm::Syntax::intel);
        if (!decoded || decoded->size() != 3) ++failures;
      }
    });
  }
  threads.clear();
  const auto seconds = std::chrono::duration<double>(Clock::now() - started).count();
  require(failures.load() == 0, "concurrent disassembly failed");
  std::cout << "Zydis: " << (workers * iterations * 3) / seconds
            << " instructions/s on " << workers << " threads\n";
}

void mcp_request_flood() {
  constexpr std::size_t request_count = 20000;
  std::ostringstream requests;
  for (std::size_t id = 1; id <= request_count; ++id)
    requests << "{\"jsonrpc\":\"2.0\",\"id\":" << id
             << ",\"method\":\"tools/call\",\"params\":{\"name\":\"get_server_info\",\"arguments\":{}}}\n";
  std::istringstream input{requests.str()};
  std::ostringstream output;
  reverseplugin::mcp::ToolRegistry registry;
  reverseplugin::register_builtin_tools(
      registry, std::make_shared<reverseplugin::process::ProcessManager>(),
      std::make_shared<reverseplugin::disasm::Disassembler>(),
      std::make_shared<reverseplugin::debug::DebugEngine>());
  const auto started = Clock::now();
  {
    reverseplugin::mcp::Server server{std::move(registry), input, output, 8};
    require(server.run() == 0, "MCP request flood failed");
  }
  const auto seconds = std::chrono::duration<double>(Clock::now() - started).count();
  const auto responses = static_cast<std::size_t>(
      std::ranges::count(output.str(), '\n'));
  require(responses == request_count, "MCP request flood lost responses");
  std::cout << "MCP: " << request_count / seconds << " requests/s on 8 workers\n";
}

void static_analysis_load() {
  std::array<wchar_t, 32768> path{};
  const auto length = GetModuleFileNameW(nullptr, path.data(),
                                         static_cast<DWORD>(path.size()));
  require(length > 0 && length < path.size(), "static load path resolution failed");
  const auto started = Clock::now();
  auto image = reverseplugin::analysis::BinaryImage::open(
      std::filesystem::path{path.data(), path.data() + length});
  require(image.has_value(), "static load PE parse failed");
  reverseplugin::disasm::Disassembler disassembler;
  auto functions = reverseplugin::analysis::discover_functions(
      **image, disassembler, 10000, 64U * 1024U * 1024U);
  require(functions && !functions->functions.empty(), "static load function discovery failed");
  auto strings = reverseplugin::analysis::scan_strings(
      **image, 4, 100000, 64U * 1024U * 1024U);
  require(!strings.strings.empty(), "static load string index failed");
  auto xrefs = reverseplugin::analysis::find_references(
      **image, disassembler, (*image)->info().entry_rva,
      64U * 1024U * 1024U, 65536);
  require(xrefs.has_value(), "static load xref scan failed");
  constexpr std::size_t decompiler_workers = 8;
  constexpr std::size_t decompilations_per_worker = 32;
  std::atomic_size_t decompiler_failures{0};
  std::vector<std::jthread> decompiler_threads;
  const auto decompiler_started = Clock::now();
  for (std::size_t worker = 0; worker < decompiler_workers; ++worker) {
    decompiler_threads.emplace_back([&] {
      for (std::size_t iteration = 0; iteration < decompilations_per_worker;
           ++iteration) {
        auto result = reverseplugin::analysis::decompile_function(
            **image, disassembler, (*image)->info().entry_rva, 16384, 256);
        if (!result || result->blocks.empty() || result->pseudocode.empty())
          ++decompiler_failures;
      }
    });
  }
  decompiler_threads.clear();
  require(decompiler_failures.load() == 0,
          "concurrent decompilation failed");
  const auto decompiler_seconds =
      std::chrono::duration<double>(Clock::now() - decompiler_started).count();
  std::cout << "Decompiler: "
            << (decompiler_workers * decompilations_per_worker) /
                   decompiler_seconds
            << " functions/s on " << decompiler_workers << " threads\n";
  reverseplugin::analysis::BinaryStore store;
  auto opened = store.open((*image)->info().path);
  require(opened.has_value(), "static cache initial open failed");
  std::atomic_size_t cache_failures{0};
  std::vector<std::jthread> cache_workers;
  for (std::size_t worker = 0; worker < 8; ++worker) {
    cache_workers.emplace_back([&] {
      for (std::size_t iteration = 0; iteration < 1000; ++iteration) {
        auto reused = store.open((*image)->info().path);
        if (!reused || reused->id != opened->id || !reused->cache_hit) ++cache_failures;
      }
    });
  }
  cache_workers.clear();
  require(cache_failures.load() == 0, "concurrent binary cache reuse failed");
  const auto seconds = std::chrono::duration<double>(Clock::now() - started).count();
  std::cout << "Static PE: " << functions->functions.size() << " functions, "
            << strings.strings.size() << " strings, " << functions->decoded_bytes
            << " decoded bytes in " << seconds << " s\n";
}

}  // namespace

int main() {
  pattern_throughput();
  snapshot_comparison_throughput();
  concurrent_memory_reads();
  concurrent_disassembly();
  static_analysis_load();
  mcp_request_flood();
}
