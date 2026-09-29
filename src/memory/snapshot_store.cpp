#include "reverseplugin/memory/snapshot_store.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstring>
#include <limits>
#include <ranges>
#include <type_traits>

namespace reverseplugin::memory {
namespace {

template <typename T>
bool compare_value(std::span<const std::byte> before,
                   std::span<const std::byte> after,
                   Comparison comparison) noexcept {
  T lhs{};
  T rhs{};
  std::memcpy(&lhs, before.data(), sizeof(T));
  std::memcpy(&rhs, after.data(), sizeof(T));
  if constexpr (std::is_floating_point_v<T>) {
    if (std::isnan(lhs) || std::isnan(rhs))
      return comparison == Comparison::changed &&
             std::bit_cast<std::array<std::byte, sizeof(T)>>(lhs) !=
                 std::bit_cast<std::array<std::byte, sizeof(T)>>(rhs);
  }
  switch (comparison) {
    case Comparison::changed: return lhs != rhs;
    case Comparison::unchanged: return lhs == rhs;
    case Comparison::increased: return rhs > lhs;
    case Comparison::decreased: return rhs < lhs;
  }
  return false;
}

bool matches(ValueType type, std::span<const std::byte> before,
             std::span<const std::byte> after,
             Comparison comparison) noexcept {
  switch (type) {
    case ValueType::u8: return compare_value<std::uint8_t>(before, after, comparison);
    case ValueType::u16: return compare_value<std::uint16_t>(before, after, comparison);
    case ValueType::u32: return compare_value<std::uint32_t>(before, after, comparison);
    case ValueType::u64: return compare_value<std::uint64_t>(before, after, comparison);
    case ValueType::i8: return compare_value<std::int8_t>(before, after, comparison);
    case ValueType::i16: return compare_value<std::int16_t>(before, after, comparison);
    case ValueType::i32: return compare_value<std::int32_t>(before, after, comparison);
    case ValueType::i64: return compare_value<std::int64_t>(before, after, comparison);
    case ValueType::f32: return compare_value<float>(before, after, comparison);
    case ValueType::f64: return compare_value<double>(before, after, comparison);
  }
  return false;
}

bool bit(const std::vector<std::uint64_t>& values, std::size_t index) noexcept {
  return (values[index / 64] & (std::uint64_t{1} << (index % 64))) != 0;
}

void clear_bit(std::vector<std::uint64_t>& values, std::size_t index) noexcept {
  values[index / 64] &= ~(std::uint64_t{1} << (index % 64));
}

}  // namespace

std::size_t width(ValueType type) noexcept {
  switch (type) {
    case ValueType::u8:
    case ValueType::i8: return 1;
    case ValueType::u16:
    case ValueType::i16: return 2;
    case ValueType::u32:
    case ValueType::i32:
    case ValueType::f32: return 4;
    case ValueType::u64:
    case ValueType::i64:
    case ValueType::f64: return 8;
  }
  return 0;
}

std::string_view to_string(ValueType type) noexcept {
  switch (type) {
    case ValueType::u8: return "u8";
    case ValueType::u16: return "u16";
    case ValueType::u32: return "u32";
    case ValueType::u64: return "u64";
    case ValueType::i8: return "i8";
    case ValueType::i16: return "i16";
    case ValueType::i32: return "i32";
    case ValueType::i64: return "i64";
    case ValueType::f32: return "f32";
    case ValueType::f64: return "f64";
  }
  return "unknown";
}

std::expected<SnapshotDescriptor, std::string> SnapshotStore::create(
    std::uint64_t session_id, std::uint64_t address,
    std::vector<std::byte> bytes, ValueType type, std::size_t step) {
  const auto value_width = width(type);
  if (bytes.size() < value_width)
    return std::unexpected("Snapshot range is smaller than the selected value type");
  if (bytes.size() > max_snapshot_bytes)
    return std::unexpected("Snapshot exceeds the 64 MiB per-snapshot limit");
  if (step == 0 || step > value_width)
    return std::unexpected("Snapshot step must be between 1 and the value width");
  const auto candidates = 1 + (bytes.size() - value_width) / step;
  std::lock_guard lock(mutex_);
  if (snapshots_.size() >= max_snapshots)
    return std::unexpected("Snapshot count limit reached");
  if (bytes.size() > max_total_bytes - total_bytes_)
    return std::unexpected("Snapshot memory budget of 256 MiB would be exceeded");
  const auto id = next_id_.fetch_add(1, std::memory_order_relaxed);
  SnapshotDescriptor descriptor{.id = id, .session_id = session_id,
    .address = address, .length = bytes.size(), .type = type,
    .step = step, .candidates = candidates};
  std::vector<std::uint64_t> active((candidates + 63) / 64,
                                    (std::numeric_limits<std::uint64_t>::max)());
  snapshots_.emplace(id, Snapshot{.descriptor = descriptor,
                                  .baseline = std::move(bytes),
                                  .active = std::move(active)});
  total_bytes_ += descriptor.length;
  return descriptor;
}

std::expected<SnapshotDescriptor, std::string> SnapshotStore::descriptor(
    std::uint64_t id) const {
  std::lock_guard lock(mutex_);
  const auto found = snapshots_.find(id);
  if (found == snapshots_.end()) return std::unexpected("Unknown memory snapshot");
  return found->second.descriptor;
}

std::expected<SnapshotComparison, std::string> SnapshotStore::compare(
    std::uint64_t id, std::span<const std::byte> current,
    Comparison comparison, std::size_t max_results, bool refine) {
  std::lock_guard lock(mutex_);
  const auto found = snapshots_.find(id);
  if (found == snapshots_.end()) return std::unexpected("Unknown memory snapshot");
  auto& snapshot = found->second;
  if (current.size() != snapshot.baseline.size())
    return std::unexpected("Current memory range does not match snapshot length");
  SnapshotComparison result;
  result.matches.reserve((std::min)(max_results, std::size_t{256}));
  const auto value_width = width(snapshot.descriptor.type);
  std::size_t survivors = 0;
  const auto total_candidates =
      1 + (snapshot.baseline.size() - value_width) / snapshot.descriptor.step;
  for (std::size_t index = 0; index < total_candidates; ++index) {
    if (!bit(snapshot.active, index)) continue;
    const auto offset = index * snapshot.descriptor.step;
    const auto before = std::span{snapshot.baseline}.subspan(offset, value_width);
    const auto after = current.subspan(offset, value_width);
    if (!matches(snapshot.descriptor.type, before, after, comparison)) {
      if (refine) clear_bit(snapshot.active, index);
      continue;
    }
    ++survivors;
    if (result.matches.size() < max_results) {
      SnapshotMatch match{.offset = offset,
                          .size = static_cast<std::uint8_t>(value_width)};
      std::ranges::copy(before, match.before.begin());
      std::ranges::copy(after, match.after.begin());
      result.matches.push_back(match);
    }
  }
  if (refine) {
    snapshot.baseline.assign(current.begin(), current.end());
    snapshot.descriptor.candidates = survivors;
  }
  result.candidate_count = survivors;
  result.truncated = survivors > result.matches.size();
  return result;
}

bool SnapshotStore::remove(std::uint64_t id) {
  std::lock_guard lock(mutex_);
  const auto found = snapshots_.find(id);
  if (found == snapshots_.end()) return false;
  total_bytes_ -= found->second.baseline.size();
  snapshots_.erase(found);
  return true;
}

}  // namespace reverseplugin::memory
