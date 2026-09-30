#include "reverseplugin/engine/artifact_inspector.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <optional>
#include <span>
#include <sstream>
#include <system_error>
#include <vector>

namespace reverseplugin::engine {
namespace {

constexpr std::uint32_t godot_pck_magic = 0x43504447U;
constexpr std::uint32_t valve_vpk_magic = 0x55aa1234U;
constexpr std::size_t sample_size = 64;

template <typename T>
std::optional<T> read(std::span<const std::byte> bytes, std::size_t offset) noexcept {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return std::nullopt;
  T value{};
  std::memcpy(&value, bytes.data() + offset, sizeof(T));
  return value;
}

std::string hex_bytes(std::span<const std::byte> bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result(bytes.size() * 2, '0');
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    const auto value = std::to_integer<unsigned char>(bytes[i]);
    result[i * 2] = digits[value >> 4U];
    result[i * 2 + 1] = digits[value & 0x0fU];
  }
  return result;
}

std::string hex_u64(std::uint64_t value) {
  std::ostringstream stream;
  stream << "0x" << std::hex << value;
  return stream.str();
}

std::string path_utf8(const std::filesystem::path& path) {
  const auto value = path.generic_u8string();
  return {reinterpret_cast<const char*>(value.data()), value.size()};
}

bool within(const std::filesystem::path& root,
            const std::filesystem::path& path) noexcept {
  const auto relative = path.lexically_relative(root);
  if (relative.empty()) return false;
  const auto first = relative.begin();
  return first != relative.end() && *first != "..";
}

std::expected<std::vector<std::byte>, std::string> read_range(
    std::ifstream& input, std::uint64_t offset, std::size_t size) {
  std::vector<std::byte> result(size);
  input.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  if (!input || !input.read(reinterpret_cast<char*>(result.data()),
                            static_cast<std::streamsize>(result.size())))
    return std::unexpected("Could not read the engine artifact sample");
  return result;
}

std::optional<std::uint64_t> godot_pck_offset(
    std::span<const std::byte> head, std::span<const std::byte> tail,
    std::uint64_t file_size) noexcept {
  if (read<std::uint32_t>(head, 0) == godot_pck_magic) return 0;
  if (file_size < 12 || tail.size() < 12 ||
      read<std::uint32_t>(tail, tail.size() - 4) != godot_pck_magic)
    return std::nullopt;
  const auto embedded_size = read<std::uint64_t>(tail, tail.size() - 12);
  if (!embedded_size || *embedded_size > file_size - 12) return std::nullopt;
  return file_size - *embedded_size - 12;
}

}  // namespace

std::expected<nlohmann::json, std::string> inspect_artifact(
    const Workspace& workspace, const Artifact& artifact) {
  std::error_code ec;
  const auto path = std::filesystem::weakly_canonical(
      workspace.root / artifact.relative_path, ec);
  if (ec || !within(workspace.root, path) ||
      !std::filesystem::is_regular_file(path, ec))
    return std::unexpected("Engine artifact is no longer a regular file inside the workspace");
  const auto file_size = std::filesystem::file_size(path, ec);
  if (ec || file_size != artifact.size)
    return std::unexpected("Engine artifact changed after the workspace scan");
  std::ifstream input(path, std::ios::binary);
  if (!input) return std::unexpected("Could not open the engine artifact");
  const auto head_size = static_cast<std::size_t>((std::min<std::uint64_t>)(file_size,
                                                                           sample_size));
  auto head = read_range(input, 0, head_size);
  if (!head) return std::unexpected(std::move(head.error()));
  const auto tail_size = head_size;
  auto tail = read_range(input, file_size - tail_size, tail_size);
  if (!tail) return std::unexpected(std::move(tail.error()));

  nlohmann::json result{{"artifact_id", artifact.id},
                        {"path", path_utf8(artifact.relative_path)},
                        {"kind", name(artifact.kind)},
                        {"format", artifact.format},
                        {"size", artifact.size},
                        {"header_hex", hex_bytes(*head)},
                        {"trailer_hex", hex_bytes(*tail)},
                        {"signature", nullptr},
                        {"details", nlohmann::json::object()}};
  const auto first = read<std::uint32_t>(*head, 0);
  if (head->size() >= 2 && (*head)[0] == std::byte{'M'} &&
      (*head)[1] == std::byte{'Z'}) {
    result["signature"] = "pe";
  } else if (first == valve_vpk_magic) {
    result["signature"] = "valve_vpk";
    const auto version = read<std::uint32_t>(*head, 4);
    const auto tree_size = read<std::uint32_t>(*head, 8);
    result["details"] = {{"version", version ? nlohmann::json(*version) : nullptr},
                         {"directory_tree_size",
                          tree_size ? nlohmann::json(*tree_size) : nullptr}};
  }

  const auto pck_offset = godot_pck_offset(*head, *tail, file_size);
  if (pck_offset) {
    auto header = read_range(input, *pck_offset, 32);
    if (!header) return std::unexpected(std::move(header.error()));
    if (read<std::uint32_t>(*header, 0) == godot_pck_magic) {
      result["signature"] = "godot_pck";
      const auto version = read<std::uint32_t>(*header, 4);
      const auto major = read<std::uint32_t>(*header, 8);
      const auto minor = read<std::uint32_t>(*header, 12);
      const auto patch = read<std::uint32_t>(*header, 16);
      const auto flags = read<std::uint32_t>(*header, 20);
      result["details"] = {{"embedded", *pck_offset != 0},
                           {"offset", hex_u64(*pck_offset)},
                           {"pack_version", version ? nlohmann::json(*version) : nullptr},
                           {"engine_version", major && minor && patch
                               ? nlohmann::json(std::to_string(*major) + '.' +
                                                std::to_string(*minor) + '.' +
                                                std::to_string(*patch))
                               : nlohmann::json(nullptr)},
                           {"flags", flags ? nlohmann::json(hex_u64(*flags)) : nullptr}};
    }
  }
  if (result["signature"].is_null()) {
    if (artifact.format == "unreal_iostore_toc")
      result["signature"] = "unreal_iostore_toc_by_extension";
    else if (artifact.format == "unreal_iostore_data")
      result["signature"] = "unreal_iostore_data_by_extension";
    else if (artifact.format == "pak")
      result["signature"] = "engine_pak_by_extension";
  }
  return result;
}

}  // namespace reverseplugin::engine
