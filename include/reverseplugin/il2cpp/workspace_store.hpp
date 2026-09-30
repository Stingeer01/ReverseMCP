#pragma once

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include "reverseplugin/il2cpp/game_assembly.hpp"
#include "reverseplugin/il2cpp/metadata.hpp"

namespace reverseplugin::il2cpp {

struct Workspace final {
  std::uint64_t id{};
  std::shared_ptr<const Metadata> metadata;
  std::shared_ptr<const GameAssemblyInfo> game_assembly;
};

struct OpenedWorkspace final {
  std::shared_ptr<const Workspace> workspace;
  bool cache_hit{};
};

class WorkspaceStore final {
 public:
  [[nodiscard]] std::expected<OpenedWorkspace, std::string> open(
      const std::filesystem::path& metadata_path,
      const std::filesystem::path& game_assembly_path = {});
  [[nodiscard]] std::shared_ptr<const Workspace> workspace(std::uint64_t id) const;
  [[nodiscard]] bool close(std::uint64_t id);

 private:
  struct Entry final {
    std::shared_ptr<const Workspace> workspace;
    std::string key;
  };

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::uint64_t, Entry> entries_;
  std::unordered_map<std::string, std::uint64_t> by_key_;
  std::atomic_uint64_t next_id_{1};
};

}  // namespace reverseplugin::il2cpp
