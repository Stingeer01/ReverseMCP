#include "reverseplugin/analysis/register_model.hpp"

#include <array>
#include <charconv>
#include <tuple>

namespace reverseplugin::analysis {
namespace {

struct GprFamily final {
  std::string_view qword;
  std::string_view dword;
  std::string_view word;
  std::string_view low;
  std::string_view high;
};

constexpr std::array gprs{
    GprFamily{"rax", "eax", "ax", "al", "ah"},
    GprFamily{"rbx", "ebx", "bx", "bl", "bh"},
    GprFamily{"rcx", "ecx", "cx", "cl", "ch"},
    GprFamily{"rdx", "edx", "dx", "dl", "dh"},
    GprFamily{"rsi", "esi", "si", "sil", ""},
    GprFamily{"rdi", "edi", "di", "dil", ""},
    GprFamily{"rbp", "ebp", "bp", "bpl", ""},
    GprFamily{"rsp", "esp", "sp", "spl", ""},
};

std::optional<RegisterSlice> legacy_gpr(std::string_view value, bool x64) {
  for (const auto& family : gprs) {
    const auto canonical = x64 ? family.qword : family.dword;
    const auto canonical_bits = static_cast<std::uint16_t>(x64 ? 64 : 32);
    if (value == family.qword && x64)
      return RegisterSlice{std::string{canonical}, canonical_bits, 0, 64,
                           RegisterWrite::full};
    if (value == family.dword)
      return RegisterSlice{std::string{canonical}, canonical_bits, 0, 32,
                           x64 ? RegisterWrite::zero_extend
                               : RegisterWrite::full};
    if (value == family.word)
      return RegisterSlice{std::string{canonical}, canonical_bits, 0, 16,
                           RegisterWrite::partial};
    if (value == family.low)
      return RegisterSlice{std::string{canonical}, canonical_bits, 0, 8,
                           RegisterWrite::partial};
    if (!family.high.empty() && value == family.high)
      return RegisterSlice{std::string{canonical}, canonical_bits, 8, 8,
                           RegisterWrite::partial};
  }
  return std::nullopt;
}

std::optional<unsigned> numbered_register(std::string_view value,
                                          std::string_view prefix,
                                          std::string_view suffix = {}) {
  if (!value.starts_with(prefix) || !value.ends_with(suffix)) return std::nullopt;
  const auto digits = value.substr(prefix.size(), value.size() - prefix.size() -
                                                      suffix.size());
  unsigned index = 0;
  const auto [end, error] = std::from_chars(digits.data(), digits.data() + digits.size(), index);
  if (error != std::errc{} || end != digits.data() + digits.size()) return std::nullopt;
  return index;
}

std::optional<RegisterSlice> extended_gpr(std::string_view value, bool x64) {
  if (!x64 || value.size() < 2 || value.front() != 'r') return std::nullopt;
  constexpr std::array suffixes{
      std::tuple<std::string_view, std::uint16_t, RegisterWrite>{
          "", std::uint16_t{64}, RegisterWrite::full},
      std::tuple<std::string_view, std::uint16_t, RegisterWrite>{
          "d", std::uint16_t{32}, RegisterWrite::zero_extend},
      std::tuple<std::string_view, std::uint16_t, RegisterWrite>{
          "w", std::uint16_t{16}, RegisterWrite::partial},
      std::tuple<std::string_view, std::uint16_t, RegisterWrite>{
          "b", std::uint16_t{8}, RegisterWrite::partial}};
  for (const auto [suffix, bits, write] : suffixes) {
    auto index = numbered_register(value, "r", suffix);
    if (!index || *index < 8 || *index > 15) continue;
    return RegisterSlice{"r" + std::to_string(*index), 64, 0, bits, write};
  }
  return std::nullopt;
}

std::optional<RegisterSlice> vector_register(std::string_view value) {
  constexpr std::array prefixes{
      std::pair<std::string_view, std::uint16_t>{"xmm", std::uint16_t{128}},
      std::pair<std::string_view, std::uint16_t>{"ymm", std::uint16_t{256}},
      std::pair<std::string_view, std::uint16_t>{"zmm", std::uint16_t{512}}};
  for (const auto [prefix, bits] : prefixes) {
    auto index = numbered_register(value, prefix);
    if (!index || *index > 31) continue;
    return RegisterSlice{"zmm" + std::to_string(*index), 512, 0, bits,
                         bits == 512 ? RegisterWrite::full
                                     : RegisterWrite::partial};
  }
  return std::nullopt;
}

}  // namespace

std::optional<RegisterSlice> resolve_register(std::string_view value, bool x64) {
  if (auto result = legacy_gpr(value, x64)) return result;
  if (auto result = extended_gpr(value, x64)) return result;
  if (auto result = vector_register(value)) return result;

  if (value == "rip" && x64)
    return RegisterSlice{"rip", 64, 0, 64, RegisterWrite::full};
  if (value == "eip")
    return RegisterSlice{x64 ? "rip" : "eip", static_cast<std::uint16_t>(x64 ? 64 : 32),
                         0, 32, x64 ? RegisterWrite::zero_extend
                                    : RegisterWrite::full};
  if (value == "rflags" && x64)
    return RegisterSlice{"rflags", 64, 0, 64, RegisterWrite::full};
  if (value == "eflags")
    return RegisterSlice{x64 ? "rflags" : "eflags",
                         static_cast<std::uint16_t>(x64 ? 64 : 32), 0, 32,
                         x64 ? RegisterWrite::partial : RegisterWrite::full};
  if (value == "flags")
    return RegisterSlice{x64 ? "rflags" : "eflags",
                         static_cast<std::uint16_t>(x64 ? 64 : 32), 0, 16,
                         RegisterWrite::partial};

  if (value.size() >= 2 && value.front() == 'k') {
    auto index = numbered_register(value, "k");
    if (index && *index <= 7)
      return RegisterSlice{std::string{value}, 64, 0, 64, RegisterWrite::full};
  }
  return std::nullopt;
}

std::string_view name(RegisterWrite write) noexcept {
  switch (write) {
    case RegisterWrite::full: return "full";
    case RegisterWrite::zero_extend: return "zero_extend";
    case RegisterWrite::partial: return "partial";
    case RegisterWrite::opaque: return "opaque";
  }
  return "opaque";
}

}  // namespace reverseplugin::analysis
