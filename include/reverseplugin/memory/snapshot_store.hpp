#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace reverseplugin::memory {

enum class ValueType { u8, u16, u32, u64, i8, i16, i32, i64, f32, f64 };
enum class Comparison { changed, unchanged, increased, decreased };

struct SnapshotDescriptor final {
  std::uint64_t id;
  std::uint64_t session_id;
  std::uint64_t address;
  std::size_t length;
  ValueType type;
  std::size_t step;
  std::size_t candidates;
};

struct SnapshotMatch final {
  std::size_t offset;
  std::array<std::byte, 8> before{};
  std::array<std::byte, 8> after{};
  std::uint8_t size;
};

struct SnapshotComparison final {
  std::vector<SnapshotMatch> matches;
  std::size_t candidate_count;
  bool truncated;
};

class SnapshotStore final {
 public:
  [[nodiscard]] std::expected<SnapshotDescriptor, std::string> create(
      std::uint64_t session_id, std::uint64_t address,
      std::vector<std::byte> bytes, ValueType type, std::size_t step);
  [[nodiscard]] std::expected<SnapshotDescriptor, std::string> descriptor(
      std::uint64_t id) const;
  [[nodiscard]] std::expected<SnapshotComparison, std::string> compare(
      std::uint64_t id, std::span<const std::byte> current,
      Comparison comparison, std::size_t max_results, bool refine);
  [[nodiscard]] bool remove(std::uint64_t id);

 private:
  struct Snapshot final {
    SnapshotDescriptor descriptor;
    std::vector<std::byte> baseline;
    std::vector<std::uint64_t> active;
  };

  static constexpr std::size_t max_snapshot_bytes = 64U * 1024U * 1024U;
  static constexpr std::size_t max_total_bytes = 256U * 1024U * 1024U;
  static constexpr std::size_t max_snapshots = 32;

  mutable std::mutex mutex_;
  std::unordered_map<std::uint64_t, Snapshot> snapshots_;
  std::size_t total_bytes_{};
  std::atomic_uint64_t next_id_{1};
};

[[nodiscard]] std::size_t width(ValueType type) noexcept;
[[nodiscard]] std::string_view to_string(ValueType type) noexcept;

}  // namespace reverseplugin::memory
