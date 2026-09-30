#pragma once

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace reverseplugin::engine {

enum class Kind : std::uint8_t {
  unknown,
  unity,
  unreal,
  godot,
  source,
  source2,
  cryengine,
  cocos2d_x,
};

enum class ArtifactKind : std::uint8_t {
  native_module,
  managed_assembly,
  container,
  asset,
  configuration,
  metadata,
  symbol,
  script,
  shader,
};

struct Artifact final {
  std::uint64_t id{};
  std::filesystem::path relative_path;
  std::uint64_t size{};
  ArtifactKind kind{};
  std::string format;
};

struct Candidate final {
  Kind kind{};
  std::uint32_t score{};
};

struct Workspace final {
  std::uint64_t id{};
  std::filesystem::path root;
  Kind engine{};
  std::string confidence;
  std::string scripting_backend;
  std::uint64_t scanned_files{};
  std::uint64_t artifact_bytes{};
  bool scan_truncated{};
  std::vector<std::string> evidence;
  std::vector<Candidate> candidates;
  std::vector<Artifact> artifacts;
};

struct OpenOptions final {
  std::uint32_t max_depth{8};
  std::uint64_t max_files{250'000};
  std::uint64_t max_artifacts{100'000};
};

class WorkspaceStore final {
 public:
  [[nodiscard]] std::expected<std::shared_ptr<const Workspace>, std::string> open(
      const std::filesystem::path& root, const OpenOptions& options);
  [[nodiscard]] std::shared_ptr<const Workspace> workspace(std::uint64_t id) const;
  [[nodiscard]] bool close(std::uint64_t id);

 private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::uint64_t, std::shared_ptr<const Workspace>> entries_;
  std::atomic_uint64_t next_id_{1};
};

[[nodiscard]] std::string_view name(Kind kind) noexcept;
[[nodiscard]] std::string_view name(ArtifactKind kind) noexcept;

}  // namespace reverseplugin::engine
