#include "reverseplugin/memory/pattern.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <utility>

namespace reverseplugin::memory {

Pattern::Pattern(std::vector<std::uint8_t> bytes,
                 std::vector<std::uint8_t> fixed,
                 std::size_t anchor) noexcept
    : bytes_(std::move(bytes)), fixed_(std::move(fixed)), anchor_(anchor) {}

std::expected<Pattern, std::string> Pattern::parse(std::string_view text) {
  std::vector<std::uint8_t> bytes;
  std::vector<std::uint8_t> fixed;
  std::size_t anchor = std::numeric_limits<std::size_t>::max();
  std::size_t position = 0;
  while (position < text.size()) {
    while (position < text.size() && text[position] == ' ') ++position;
    if (position == text.size()) break;
    const auto end = text.find(' ', position);
    const auto token = text.substr(position, end == std::string_view::npos
                                                 ? text.size() - position
                                                 : end - position);
    if (token == "?" || token == "??") {
      bytes.push_back(0);
      fixed.push_back(0);
    } else {
      if (token.size() != 2)
        return std::unexpected("Each AOB token must be two hexadecimal digits or ??");
      unsigned value = 0;
      const auto [last, error] = std::from_chars(
          token.data(), token.data() + token.size(), value, 16);
      if (error != std::errc{} || last != token.data() + token.size() || value > 0xFFU)
        return std::unexpected("AOB pattern contains an invalid hexadecimal token");
      bytes.push_back(static_cast<std::uint8_t>(value));
      fixed.push_back(1);
      anchor = bytes.size() - 1;
    }
    position = end == std::string_view::npos ? text.size() : end + 1;
  }
  if (bytes.empty()) return std::unexpected("AOB pattern must not be empty");
  if (bytes.size() > 4096) return std::unexpected("AOB pattern exceeds 4096 bytes");
  if (anchor == std::numeric_limits<std::size_t>::max()) anchor = 0;
  return Pattern{std::move(bytes), std::move(fixed), anchor};
}

bool Pattern::matches(std::span<const std::byte> bytes) const noexcept {
  if (bytes.size() < bytes_.size()) return false;
  for (std::size_t i = 0; i < bytes_.size(); ++i) {
    if (fixed_[i] != 0 && std::to_integer<std::uint8_t>(bytes[i]) != bytes_[i])
      return false;
  }
  return true;
}

std::vector<std::size_t> Pattern::find_all(std::span<const std::byte> bytes,
                                           std::size_t max_results) const {
  std::vector<std::size_t> result;
  if (max_results == 0 || bytes.size() < bytes_.size()) return result;
  result.reserve((std::min)(max_results, std::size_t{64}));
  const auto last = bytes.size() - bytes_.size();
  for (std::size_t offset = 0; offset <= last; ++offset) {
    if (fixed_[anchor_] != 0 &&
        std::to_integer<std::uint8_t>(bytes[offset + anchor_]) != bytes_[anchor_])
      continue;
    if (matches(bytes.subspan(offset, bytes_.size()))) {
      result.push_back(offset);
      if (result.size() == max_results) break;
    }
  }
  return result;
}

}  // namespace reverseplugin::memory
