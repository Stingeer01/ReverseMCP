#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "reverseplugin/engine/artifact_inspector.hpp"
#include "reverseplugin/engine/workspace.hpp"

namespace {

void expect(bool condition, std::string_view message) {
  if (!condition) throw std::runtime_error(std::string{message});
}

void write_file(const std::filesystem::path& path,
                std::span<const std::byte> bytes = {}) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  expect(output.good(), "could not create engine fixture");
  if (!bytes.empty())
    expect(output.write(reinterpret_cast<const char*>(bytes.data()),
                        static_cast<std::streamsize>(bytes.size())).good(),
           "could not write engine fixture");
}

template <typename T>
void write_at(std::vector<std::byte>& bytes, std::size_t offset, T value) {
  expect(offset + sizeof(T) <= bytes.size(), "fixture write exceeds buffer");
  std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

void detects_unity_il2cpp(const std::filesystem::path& root) {
  const auto game = root / "unity";
  write_file(game / "UnityPlayer.dll");
  write_file(game / "GameAssembly.dll");
  write_file(game / "Game_Data/il2cpp_data/Metadata/global-metadata.dat");
  reverseplugin::engine::WorkspaceStore store;
  auto workspace = store.open(game, {});
  expect(workspace.has_value(), "could not scan Unity fixture");
  expect((*workspace)->engine == reverseplugin::engine::Kind::unity,
         "Unity fixture was not detected");
  expect((*workspace)->confidence == "high", "Unity confidence is too low");
  expect((*workspace)->scripting_backend == "il2cpp",
         "Unity scripting backend is incorrect");
  expect((*workspace)->artifacts.size() == 3, "Unity artifacts are incomplete");
}

void detects_source2(const std::filesystem::path& root) {
  const auto game = root / "source2";
  write_file(game / "game/csgo/gameinfo.gi");
  write_file(game / "game/bin/win64/engine2.dll");
  write_file(game / "game/bin/win64/schemasystem.dll");
  reverseplugin::engine::WorkspaceStore store;
  auto workspace = store.open(game, {});
  expect(workspace.has_value(), "could not scan Source 2 fixture");
  expect((*workspace)->engine == reverseplugin::engine::Kind::source2,
         "Source 2 fixture was not detected");
  expect((*workspace)->confidence == "high", "Source 2 confidence is too low");
}

void inspects_godot_pck(const std::filesystem::path& root) {
  const auto game = root / "godot";
  std::vector<std::byte> header(32);
  write_at(header, 0, std::uint32_t{0x43504447U});
  write_at(header, 4, std::uint32_t{3});
  write_at(header, 8, std::uint32_t{4});
  write_at(header, 12, std::uint32_t{5});
  write_at(header, 16, std::uint32_t{1});
  write_at(header, 20, std::uint32_t{0});
  write_file(game / "project.godot");
  write_file(game / "game.pck", header);
  std::vector<std::byte> embedded(64, std::byte{0});
  embedded[0] = std::byte{'M'};
  embedded[1] = std::byte{'Z'};
  embedded.insert(embedded.end(), header.begin(), header.end());
  const auto footer = embedded.size();
  embedded.resize(footer + 12);
  write_at(embedded, footer, std::uint64_t{header.size()});
  write_at(embedded, footer + 8, std::uint32_t{0x43504447U});
  write_file(game / "embedded.exe", embedded);
  reverseplugin::engine::WorkspaceStore store;
  auto workspace = store.open(game, {});
  expect(workspace.has_value(), "could not scan Godot fixture");
  expect((*workspace)->engine == reverseplugin::engine::Kind::godot,
         "Godot fixture was not detected");
  const auto artifact = std::ranges::find_if((*workspace)->artifacts,
      [](const reverseplugin::engine::Artifact& value) {
        return value.format == "godot_pck";
      });
  expect(artifact != (*workspace)->artifacts.end(), "Godot PCK was not indexed");
  auto inspected = reverseplugin::engine::inspect_artifact(**workspace, *artifact);
  expect(inspected.has_value(), "Godot PCK inspection failed");
  expect(inspected->at("signature") == "godot_pck", "Godot PCK magic was not recognized");
  expect(inspected->at("details").at("engine_version") == "4.5.1",
         "Godot engine version is incorrect");
  const auto executable = std::ranges::find_if((*workspace)->artifacts,
      [](const reverseplugin::engine::Artifact& value) {
        return value.relative_path.filename() == "embedded.exe";
      });
  expect(executable != (*workspace)->artifacts.end(), "embedded Godot executable was not indexed");
  auto embedded_result = reverseplugin::engine::inspect_artifact(**workspace, *executable);
  expect(embedded_result && embedded_result->at("signature") == "godot_pck" &&
             embedded_result->at("details").at("embedded") == true,
         "embedded Godot PCK was not recognized");
}

}  // namespace

int main() {
  const auto root = std::filesystem::temp_directory_path() /
                    ("reverseplugin-engine-tests-" +
                     std::to_string(GetCurrentProcessId()));
  struct Cleanup final {
    std::filesystem::path path;
    ~Cleanup() {
      std::error_code ec;
      std::filesystem::remove_all(path, ec);
    }
  } cleanup{root};
  std::filesystem::create_directories(root);
  detects_unity_il2cpp(root);
  detects_source2(root);
  inspects_godot_pck(root);
}
