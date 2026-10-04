#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace reverseplugin::analysis {

enum class RegisterWrite { full, zero_extend, partial, opaque };

struct RegisterSlice final {
  std::string canonical;
  std::uint16_t canonical_bits{};
  std::uint16_t offset_bits{};
  std::uint16_t size_bits{};
  RegisterWrite write{RegisterWrite::opaque};
};

[[nodiscard]] std::optional<RegisterSlice> resolve_register(
    std::string_view name, bool x64);
[[nodiscard]] std::string_view name(RegisterWrite write) noexcept;

}  // namespace reverseplugin::analysis
