#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace reverseplugin::memory {

class Pattern final {
 public:
  [[nodiscard]] static std::expected<Pattern, std::string> parse(
      std::string_view text);

  [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }
  [[nodiscard]] bool matches(std::span<const std::byte> bytes) const noexcept;
  [[nodiscard]] std::vector<std::size_t> find_all(
      std::span<const std::byte> bytes, std::size_t max_results) const;

 private:
  Pattern(std::vector<std::uint8_t> bytes, std::vector<std::uint8_t> fixed,
          std::size_t anchor) noexcept;

  std::vector<std::uint8_t> bytes_;
  std::vector<std::uint8_t> fixed_;
  std::size_t anchor_{};
};

}  // namespace reverseplugin::memory
