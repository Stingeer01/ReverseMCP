#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace reverseplugin::il2cpp {

struct GameAssemblyInfo final {
  std::filesystem::path path;
  std::string fingerprint;
  std::string architecture;
  std::uint64_t file_size{};
  std::uint64_t image_base{};
  std::uint32_t image_size{};
  std::uint32_t code_registration_rva{};
  std::unordered_map<std::string, std::vector<std::uint32_t>> method_rvas;

  [[nodiscard]] std::optional<std::uint32_t> method_rva(
      std::string_view image_name, std::uint32_t token) const;
};

[[nodiscard]] std::expected<GameAssemblyInfo, std::string> open_game_assembly(
    const std::filesystem::path& path, std::uint32_t expected_image_count);

}  // namespace reverseplugin::il2cpp

