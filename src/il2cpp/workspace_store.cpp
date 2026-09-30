#include "reverseplugin/il2cpp/workspace_store.hpp"

#include <mutex>
#include <system_error>

namespace reverseplugin::il2cpp {
namespace {

std::expected<std::filesystem::path, std::string> canonical_file(
    const std::filesystem::path& path) {
  std::error_code ec;
  auto canonical = std::filesystem::weakly_canonical(path, ec);
  if (ec || !std::filesystem::is_regular_file(canonical, ec))
    return std::unexpected("Path is not a regular file");
  return canonical;
}

std::expected<std::string, std::string> cache_key(
    const std::filesystem::path& path) {
  auto canonical = canonical_file(path);
  if (!canonical) return std::unexpected(std::move(canonical.error()));
  std::error_code ec;
  const auto size = std::filesystem::file_size(*canonical, ec);
  if (ec) return std::unexpected("Could not inspect file size");
  const auto modified = std::filesystem::last_write_time(*canonical, ec);
  if (ec) return std::unexpected("Could not inspect file timestamp");
  const auto utf8 = canonical->generic_u8string();
  std::string result{reinterpret_cast<const char*>(utf8.data()), utf8.size()};
  result += '|' + std::to_string(size) + '|' +
            std::to_string(modified.time_since_epoch().count());
  return result;
}

}  // namespace

std::expected<OpenedWorkspace, std::string> WorkspaceStore::open(
    const std::filesystem::path& metadata_path,
    const std::filesystem::path& game_assembly_path) {
  auto metadata_key = cache_key(metadata_path);
  if (!metadata_key) return std::unexpected(std::move(metadata_key.error()));
  std::string key = std::move(*metadata_key);
  if (!game_assembly_path.empty()) {
    auto assembly_key = cache_key(game_assembly_path);
    if (!assembly_key) return std::unexpected(std::move(assembly_key.error()));
    key += "||" + *assembly_key;
  }
  {
    std::shared_lock lock(mutex_);
    const auto found = by_key_.find(key);
    if (found != by_key_.end()) {
      const auto entry = entries_.find(found->second);
      if (entry != entries_.end())
        return OpenedWorkspace{.workspace = entry->second.workspace,
                               .cache_hit = true};
    }
  }

  auto metadata = Metadata::open(metadata_path);
  if (!metadata) return std::unexpected(std::move(metadata.error()));
  std::shared_ptr<const GameAssemblyInfo> assembly;
  if (!game_assembly_path.empty()) {
    auto inspected = open_game_assembly(game_assembly_path,
                                        (*metadata)->info().image_count);
    if (!inspected) return std::unexpected(std::move(inspected.error()));
    assembly = std::make_shared<const GameAssemblyInfo>(std::move(*inspected));
  }

  std::unique_lock lock(mutex_);
  const auto existing = by_key_.find(key);
  if (existing != by_key_.end()) {
    const auto entry = entries_.find(existing->second);
    if (entry != entries_.end())
      return OpenedWorkspace{.workspace = entry->second.workspace,
                             .cache_hit = true};
  }
  const auto id = next_id_.fetch_add(1, std::memory_order_relaxed);
  auto workspace = std::make_shared<const Workspace>(Workspace{
      .id = id, .metadata = std::move(*metadata), .game_assembly = std::move(assembly)});
  entries_.emplace(id, Entry{.workspace = workspace, .key = key});
  by_key_.emplace(std::move(key), id);
  return OpenedWorkspace{.workspace = std::move(workspace), .cache_hit = false};
}

std::shared_ptr<const Workspace> WorkspaceStore::workspace(std::uint64_t id) const {
  std::shared_lock lock(mutex_);
  const auto found = entries_.find(id);
  return found == entries_.end() ? nullptr : found->second.workspace;
}

bool WorkspaceStore::close(std::uint64_t id) {
  std::unique_lock lock(mutex_);
  const auto found = entries_.find(id);
  if (found == entries_.end()) return false;
  by_key_.erase(found->second.key);
  entries_.erase(found);
  return true;
}

}  // namespace reverseplugin::il2cpp
