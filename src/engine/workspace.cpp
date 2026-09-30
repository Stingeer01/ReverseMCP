#include "reverseplugin/engine/workspace.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <fstream>
#include <mutex>
#include <system_error>
#include <unordered_set>

namespace reverseplugin::engine {
namespace {

constexpr std::size_t engine_count = 7;
constexpr std::uint32_t godot_pck_magic = 0x43504447U;

std::string lower_ascii(std::string_view value) {
  std::string result{value};
  std::ranges::transform(result, result.begin(), [](unsigned char character) {
    return static_cast<char>(std::tolower(character));
  });
  return result;
}

std::string path_utf8(const std::filesystem::path& path) {
  const auto value = path.generic_u8string();
  return {reinterpret_cast<const char*>(value.data()), value.size()};
}

std::size_t slot(Kind kind) noexcept {
  return static_cast<std::size_t>(kind) - 1;
}

struct Signals final {
  std::array<std::uint32_t, engine_count> scores{};
  std::unordered_set<std::string> seen;
  std::vector<std::string> evidence;
  bool unity_il2cpp{};
  bool unity_mono{};

  void add(Kind kind, std::uint32_t weight, std::string_view signal,
           std::string_view path) {
    std::string key{name(kind)};
    key += ':';
    key += signal;
    if (!seen.emplace(std::move(key)).second) return;
    scores[slot(kind)] += weight;
    evidence.emplace_back(std::string{name(kind)} + ": " + std::string{signal} +
                          " [" + std::string{path} + ']');
  }
};

std::optional<std::pair<ArtifactKind, std::string>> classify(
    std::string_view path, std::string_view filename, std::string_view extension) {
  if (extension == ".exe" || extension == ".sys")
    return {{ArtifactKind::native_module, "pe"}};
  if (extension == ".dll") {
    if (path.starts_with("managed/") ||
        path.find("/managed/") != std::string_view::npos)
      return {{ArtifactKind::managed_assembly, "dotnet_assembly"}};
    return {{ArtifactKind::native_module, "pe_or_managed"}};
  }
  if (extension == ".pdb" || extension == ".dbg")
    return {{ArtifactKind::symbol, "debug_symbols"}};
  if (extension == ".pak") return {{ArtifactKind::container, "pak"}};
  if (extension == ".utoc") return {{ArtifactKind::container, "unreal_iostore_toc"}};
  if (extension == ".ucas") return {{ArtifactKind::container, "unreal_iostore_data"}};
  if (extension == ".vpk") return {{ArtifactKind::container, "valve_vpk"}};
  if (extension == ".pck") return {{ArtifactKind::container, "godot_pck"}};
  if (extension == ".bundle") return {{ArtifactKind::container, "unity_bundle"}};
  if (extension == ".uasset" || extension == ".uexp" || extension == ".ubulk")
    return {{ArtifactKind::asset, "unreal_cooked_asset"}};
  if (extension == ".assets" || extension == ".resource" || extension == ".res")
    return {{ArtifactKind::asset, "engine_asset"}};
  if (extension.ends_with("_c") || extension == ".vtex" || extension == ".vmdl")
    return {{ArtifactKind::asset, "source2_resource"}};
  if (extension == ".gd" || extension == ".gdc" || extension == ".gdextension")
    return {{ArtifactKind::script, "godot_script"}};
  if (extension == ".lua" || extension == ".luac" || extension == ".js" ||
      extension == ".jsc")
    return {{ArtifactKind::script, "script"}};
  if (extension == ".ushaderbytecode" || extension == ".spv" ||
      extension == ".vcs" || extension == ".vcs2")
    return {{ArtifactKind::shader, "shader"}};
  if (filename == "global-metadata.dat")
    return {{ArtifactKind::metadata, "il2cpp_metadata"}};
  if (filename == "assetregistry.bin" || filename == "globalgamemanagers")
    return {{ArtifactKind::metadata, "engine_metadata"}};
  if (filename == "project.godot" || filename == "gameinfo.txt" ||
      filename == "gameinfo.gi" || filename == "system.cfg" ||
      extension == ".uproject" || extension == ".cryproject" ||
      extension == ".ini")
    return {{ArtifactKind::configuration, "engine_configuration"}};
  return std::nullopt;
}

void detect(Signals& signals, std::string_view path, std::string_view filename,
            std::string_view extension) {
  if (filename == "unityplayer.dll") signals.add(Kind::unity, 5, "UnityPlayer.dll", path);
  if (filename == "gameassembly.dll") {
    signals.add(Kind::unity, 6, "GameAssembly.dll", path);
    signals.unity_il2cpp = true;
  }
  if (filename == "global-metadata.dat") {
    signals.add(Kind::unity, 6, "global-metadata.dat", path);
    signals.unity_il2cpp = true;
  }
  if (path.find("/monobleedingedge/") != std::string_view::npos ||
      path.find("/managed/") != std::string_view::npos) {
    signals.add(Kind::unity, 4, "Mono managed runtime", path);
    signals.unity_mono = true;
  }

  if (extension == ".uproject") signals.add(Kind::unreal, 7, ".uproject manifest", path);
  if (filename.ends_with("-win64-shipping.exe"))
    signals.add(Kind::unreal, 6, "Win64 shipping executable", path);
  if (path.find("/engine/binaries/") != std::string_view::npos)
    signals.add(Kind::unreal, 6, "Engine/Binaries layout", path);
  if (path.find("/content/paks/") != std::string_view::npos && extension == ".pak")
    signals.add(Kind::unreal, 5, "Content/Paks layout", path);
  if (extension == ".utoc" || extension == ".ucas")
    signals.add(Kind::unreal, 5, "IoStore container", path);
  if (filename == "assetregistry.bin")
    signals.add(Kind::unreal, 4, "AssetRegistry.bin", path);
  if (extension == ".uasset") signals.add(Kind::unreal, 3, "cooked uasset", path);

  if (filename == "project.godot") signals.add(Kind::godot, 8, "project.godot", path);
  if (extension == ".pck") signals.add(Kind::godot, 5, "PCK container", path);
  if (extension == ".gd" || extension == ".gdc")
    signals.add(Kind::godot, 3, "GDScript", path);

  if (filename == "gameinfo.txt") signals.add(Kind::source, 7, "gameinfo.txt", path);
  if (filename == "engine.dll") signals.add(Kind::source, 6, "engine.dll", path);
  if (filename == "vphysics.dll") signals.add(Kind::source, 3, "vphysics.dll", path);
  if (filename == "gameinfo.gi") signals.add(Kind::source2, 8, "gameinfo.gi", path);
  if (filename == "engine2.dll") signals.add(Kind::source2, 7, "engine2.dll", path);
  if (filename == "schemasystem.dll")
    signals.add(Kind::source2, 7, "schemasystem.dll", path);
  if (extension.ends_with("_c")) signals.add(Kind::source2, 3, "compiled resource", path);
  if (extension == ".vpk") {
    signals.add(Kind::source, 2, "VPK container", path);
    signals.add(Kind::source2, 2, "VPK container", path);
  }

  if (filename == "crysystem.dll") signals.add(Kind::cryengine, 8, "CrySystem.dll", path);
  if (filename == "cryrenderd3d11.dll")
    signals.add(Kind::cryengine, 6, "CryRenderD3D11.dll", path);
  if (extension == ".cryproject")
    signals.add(Kind::cryengine, 7, ".cryproject manifest", path);
  if (filename == "system.cfg") signals.add(Kind::cryengine, 3, "system.cfg", path);

  if (filename == "cocos2d.dll" || filename == "libcocos2d.dll")
    signals.add(Kind::cocos2d_x, 8, "cocos2d native library", path);
  if (path.find("/cocos2d/") != std::string_view::npos)
    signals.add(Kind::cocos2d_x, 5, "cocos2d directory", path);
}

bool has_embedded_godot_pck(const std::filesystem::path& path,
                            std::uint64_t file_size) {
  if (file_size < 12) return false;
  std::ifstream input(path, std::ios::binary);
  if (!input) return false;
  std::array<std::byte, 12> trailer{};
  input.seekg(static_cast<std::streamoff>(file_size - trailer.size()), std::ios::beg);
  if (!input.read(reinterpret_cast<char*>(trailer.data()), trailer.size())) return false;
  std::uint64_t embedded_size = 0;
  std::uint32_t trailer_magic = 0;
  std::memcpy(&embedded_size, trailer.data(), sizeof(embedded_size));
  std::memcpy(&trailer_magic, trailer.data() + sizeof(embedded_size),
              sizeof(trailer_magic));
  if (trailer_magic != godot_pck_magic || embedded_size > file_size - 12)
    return false;
  const auto offset = file_size - embedded_size - 12;
  std::uint32_t header_magic = 0;
  input.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  return input.read(reinterpret_cast<char*>(&header_magic), sizeof(header_magic)) &&
         header_magic == godot_pck_magic;
}

void finish_profile(Workspace& workspace, const Signals& signals) {
  for (std::size_t i = 0; i < signals.scores.size(); ++i) {
    if (signals.scores[i] != 0)
      workspace.candidates.push_back(
          {static_cast<Kind>(i + 1), signals.scores[i]});
  }
  std::ranges::sort(workspace.candidates, [](const Candidate& left,
                                             const Candidate& right) {
    if (left.score != right.score) return left.score > right.score;
    return name(left.kind) < name(right.kind);
  });
  workspace.evidence = signals.evidence;
  if (workspace.candidates.empty()) {
    workspace.engine = Kind::unknown;
    workspace.confidence = "none";
    return;
  }
  const auto first = workspace.candidates.front();
  const auto second = workspace.candidates.size() > 1 ? workspace.candidates[1].score : 0;
  if (first.score == second) {
    workspace.engine = Kind::unknown;
    workspace.confidence = "ambiguous";
    return;
  }
  workspace.engine = first.kind;
  const auto lead = first.score - second;
  workspace.confidence = first.score >= 10 && lead >= 3 ? "high" :
                         first.score >= 6 ? "medium" : "low";
  if (workspace.engine == Kind::unity) {
    if (signals.unity_il2cpp) workspace.scripting_backend = "il2cpp";
    else if (signals.unity_mono) workspace.scripting_backend = "mono";
    else workspace.scripting_backend = "unknown";
  }
}

}  // namespace

std::expected<std::shared_ptr<const Workspace>, std::string> WorkspaceStore::open(
    const std::filesystem::path& root, const OpenOptions& options) {
  if (options.max_depth > 32 || options.max_files == 0 ||
      options.max_files > 1'000'000 || options.max_artifacts == 0 ||
      options.max_artifacts > 250'000)
    return std::unexpected("Engine workspace scan limits are invalid");
  std::error_code ec;
  auto canonical = std::filesystem::weakly_canonical(root, ec);
  if (ec || !std::filesystem::is_directory(canonical, ec))
    return std::unexpected("Engine root is not a readable directory");

  Workspace result{.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                   .root = std::move(canonical)};
  Signals signals;
  const auto directory_options = std::filesystem::directory_options::skip_permission_denied;
  std::filesystem::recursive_directory_iterator iterator(result.root, directory_options, ec);
  const std::filesystem::recursive_directory_iterator end;
  for (; !ec && iterator != end; iterator.increment(ec)) {
    if (iterator.depth() >= static_cast<int>(options.max_depth) &&
        iterator->is_directory(ec)) {
      iterator.disable_recursion_pending();
      ec.clear();
      continue;
    }
    const auto status = iterator->symlink_status(ec);
    if (ec) {
      ec.clear();
      continue;
    }
    if (!std::filesystem::is_regular_file(status)) continue;
    if (result.scanned_files == options.max_files) {
      result.scan_truncated = true;
      break;
    }
    ++result.scanned_files;

    const auto relative = iterator->path().lexically_relative(result.root);
    const auto relative_text = lower_ascii(path_utf8(relative));
    const auto filename = lower_ascii(path_utf8(relative.filename()));
    const auto extension = lower_ascii(path_utf8(relative.extension()));
    detect(signals, relative_text, filename, extension);
    const auto classification = classify(relative_text, filename, extension);
    if (!classification) continue;
    if (result.artifacts.size() >= options.max_artifacts) {
      result.scan_truncated = true;
      continue;
    }
    const auto size = iterator->file_size(ec);
    if (ec) {
      ec.clear();
      continue;
    }
    if (extension == ".exe" && has_embedded_godot_pck(iterator->path(), size))
      signals.add(Kind::godot, 8, "embedded PCK", relative_text);
    result.artifact_bytes += size;
    result.artifacts.push_back({.id = result.artifacts.size() + 1,
                                .relative_path = relative,
                                .size = size,
                                .kind = classification->first,
                                .format = std::move(classification->second)});
  }
  if (ec) return std::unexpected("Could not complete the engine directory scan");
  finish_profile(result, signals);

  auto workspace = std::make_shared<const Workspace>(std::move(result));
  std::unique_lock lock(mutex_);
  entries_.emplace(workspace->id, workspace);
  return workspace;
}

std::shared_ptr<const Workspace> WorkspaceStore::workspace(std::uint64_t id) const {
  std::shared_lock lock(mutex_);
  const auto found = entries_.find(id);
  return found == entries_.end() ? nullptr : found->second;
}

bool WorkspaceStore::close(std::uint64_t id) {
  std::unique_lock lock(mutex_);
  return entries_.erase(id) != 0;
}

std::string_view name(Kind kind) noexcept {
  switch (kind) {
    case Kind::unity: return "unity";
    case Kind::unreal: return "unreal_engine";
    case Kind::godot: return "godot";
    case Kind::source: return "source";
    case Kind::source2: return "source_2";
    case Kind::cryengine: return "cryengine";
    case Kind::cocos2d_x: return "cocos2d_x";
    case Kind::unknown: return "unknown";
  }
  return "unknown";
}

std::string_view name(ArtifactKind kind) noexcept {
  switch (kind) {
    case ArtifactKind::native_module: return "native_module";
    case ArtifactKind::managed_assembly: return "managed_assembly";
    case ArtifactKind::container: return "container";
    case ArtifactKind::asset: return "asset";
    case ArtifactKind::configuration: return "configuration";
    case ArtifactKind::metadata: return "metadata";
    case ArtifactKind::symbol: return "symbol";
    case ArtifactKind::script: return "script";
    case ArtifactKind::shader: return "shader";
  }
  return "unknown";
}

}  // namespace reverseplugin::engine
