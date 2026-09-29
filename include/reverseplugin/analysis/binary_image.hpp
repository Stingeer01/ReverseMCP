#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace reverseplugin::analysis {

struct Section final {
  std::string name;
  std::uint32_t rva;
  std::uint32_t virtual_size;
  std::uint32_t raw_offset;
  std::uint32_t raw_size;
  bool readable;
  bool writable;
  bool executable;
};

struct Import final {
  std::string module;
  std::string name;
  std::uint16_t ordinal;
  std::uint32_t iat_rva;
  bool by_ordinal;
};

struct Export final {
  std::string name;
  std::uint32_t ordinal;
  std::uint32_t rva;
  std::string forwarder;
};

struct BinaryInfo final {
  std::filesystem::path path;
  std::string fingerprint;
  std::string format;
  std::string architecture;
  std::uint64_t image_base;
  std::uint32_t entry_rva;
  std::uint32_t image_size;
  std::uint64_t file_size;
};

class BinaryImage final {
 public:
  [[nodiscard]] static std::expected<std::shared_ptr<BinaryImage>, std::string>
      open(const std::filesystem::path& path);

  [[nodiscard]] const BinaryInfo& info() const noexcept { return info_; }
  [[nodiscard]] const std::vector<Section>& sections() const noexcept { return sections_; }
  [[nodiscard]] const std::vector<Import>& imports() const noexcept { return imports_; }
  [[nodiscard]] const std::vector<Export>& exports() const noexcept { return exports_; }
  [[nodiscard]] std::expected<std::span<const std::byte>, std::string> bytes_at(
      std::uint32_t rva, std::size_t maximum) const;
  [[nodiscard]] bool contains_rva(std::uint64_t rva) const noexcept;
  [[nodiscard]] bool executable_rva(std::uint64_t rva) const noexcept;
  [[nodiscard]] const Section* section_at(std::uint64_t rva) const noexcept;
  [[nodiscard]] std::expected<std::uint32_t, std::string> normalize_address(
      std::uint64_t address) const;

 private:
  BinaryInfo info_;
  std::vector<std::byte> bytes_;
  std::vector<Section> sections_;
  std::vector<Import> imports_;
  std::vector<Export> exports_;
};

}  // namespace reverseplugin::analysis
