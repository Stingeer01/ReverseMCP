#include "reverseplugin/analysis/binary_store.hpp"

#include <filesystem>
#include <mutex>
#include <system_error>

namespace reverseplugin::analysis {

std::expected<OpenedBinary, std::string> BinaryStore::open(
    const std::filesystem::path& path) {
  std::error_code ec;
  const auto canonical = std::filesystem::weakly_canonical(path, ec);
  if (ec) return std::unexpected("Could not canonicalize binary path");
  const auto size = std::filesystem::file_size(canonical, ec);
  if (ec) return std::unexpected("Could not inspect binary size");
  const auto modified = std::filesystem::last_write_time(canonical, ec);
  if (ec) return std::unexpected("Could not inspect binary timestamp");
  const auto utf8_path = canonical.generic_u8string();
  auto key = std::string{reinterpret_cast<const char*>(utf8_path.data()),
                         utf8_path.size()};
  key.push_back('|');
  key += std::to_string(size);
  key.push_back('|');
  key += std::to_string(modified.time_since_epoch().count());
  {
    std::shared_lock lock(mutex_);
    if (const auto found = by_key_.find(key); found != by_key_.end()) {
      if (const auto entry = entries_.find(found->second); entry != entries_.end())
        return OpenedBinary{.id = found->second, .image = entry->second.image,
                            .cache_hit = true};
    }
  }

  auto parsed = BinaryImage::open(canonical);
  if (!parsed) return std::unexpected(std::move(parsed.error()));
  std::unique_lock lock(mutex_);
  if (const auto found = by_key_.find(key); found != by_key_.end()) {
    if (const auto entry = entries_.find(found->second); entry != entries_.end())
      return OpenedBinary{.id = found->second, .image = entry->second.image,
                          .cache_hit = true};
  }
  const auto id = next_id_.fetch_add(1, std::memory_order_relaxed);
  auto image = std::shared_ptr<const BinaryImage>{std::move(*parsed)};
  entries_.emplace(id, Entry{.image = image, .key = key});
  by_key_.emplace(key, id);
  return OpenedBinary{.id = id, .image = std::move(image), .cache_hit = false};
}

std::shared_ptr<const BinaryImage> BinaryStore::image(std::uint64_t id) const {
  std::shared_lock lock(mutex_);
  const auto found = entries_.find(id);
  return found == entries_.end() ? nullptr : found->second.image;
}

bool BinaryStore::close(std::uint64_t id) {
  std::unique_lock lock(mutex_);
  const auto found = entries_.find(id);
  if (found == entries_.end()) return false;
  by_key_.erase(found->second.key);
  entries_.erase(found);
  return true;
}

}  // namespace reverseplugin::analysis
