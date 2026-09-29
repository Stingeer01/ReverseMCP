#pragma once

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include "reverseplugin/analysis/binary_image.hpp"

namespace reverseplugin::analysis {

struct OpenedBinary final {
  std::uint64_t id;
  std::shared_ptr<const BinaryImage> image;
  bool cache_hit;
};

class BinaryStore final {
 public:
  [[nodiscard]] std::expected<OpenedBinary, std::string> open(
      const std::filesystem::path& path);
  [[nodiscard]] std::shared_ptr<const BinaryImage> image(std::uint64_t id) const;
  [[nodiscard]] bool close(std::uint64_t id);

 private:
  struct Entry final {
    std::shared_ptr<const BinaryImage> image;
    std::string key;
  };

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::uint64_t, Entry> entries_;
  std::unordered_map<std::string, std::uint64_t> by_key_;
  std::atomic_uint64_t next_id_{1};
};

}  // namespace reverseplugin::analysis
