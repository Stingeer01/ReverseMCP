#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace reverseplugin::il2cpp {

struct Section final {
  std::uint32_t offset{};
  std::uint32_t size{};
  std::uint32_t count{};
};

struct ImageDefinition final {
  std::uint32_t name_index{};
  std::int32_t assembly_index{};
  std::int32_t type_start{};
  std::uint32_t type_count{};
  std::uint32_t token{};
};

struct TypeDefinition final {
  std::uint32_t name_index{};
  std::uint32_t namespace_index{};
  std::int32_t field_start{};
  std::int32_t method_start{};
  std::uint16_t method_count{};
  std::uint16_t field_count{};
  std::uint32_t flags{};
  std::uint32_t bitfield{};
  std::uint32_t token{};
};

struct MethodDefinition final {
  std::uint32_t name_index{};
  std::int32_t declaring_type{};
  std::int32_t return_type{};
  std::int32_t parameter_start{};
  std::uint32_t token{};
  std::uint16_t flags{};
  std::uint16_t slot{};
  std::uint16_t parameter_count{};
};

struct FieldDefinition final {
  std::uint32_t name_index{};
  std::int32_t type_index{};
  std::uint32_t token{};
};

struct ParameterDefinition final {
  std::uint32_t name_index{};
  std::uint32_t token{};
  std::int32_t type_index{};
};

struct MetadataInfo final {
  std::filesystem::path path;
  std::string fingerprint;
  std::uint32_t version{};
  std::uint64_t file_size{};
  std::uint32_t image_count{};
  std::uint32_t type_count{};
  std::uint32_t method_count{};
  std::uint32_t field_count{};
  std::uint32_t parameter_count{};
};

class Metadata final {
 public:
  [[nodiscard]] static std::expected<std::shared_ptr<Metadata>, std::string> open(
      const std::filesystem::path& path);

  [[nodiscard]] const MetadataInfo& info() const noexcept { return info_; }
  [[nodiscard]] std::expected<std::string_view, std::string> string_at(
      std::uint32_t index) const;
  [[nodiscard]] std::expected<ImageDefinition, std::string> image(
      std::size_t index) const;
  [[nodiscard]] std::expected<TypeDefinition, std::string> type(
      std::size_t index) const;
  [[nodiscard]] std::expected<MethodDefinition, std::string> method(
      std::size_t index) const;
  [[nodiscard]] std::expected<FieldDefinition, std::string> field(
      std::size_t index) const;
  [[nodiscard]] std::expected<ParameterDefinition, std::string> parameter(
      std::size_t index) const;

 private:
  MetadataInfo info_;
  std::vector<std::byte> bytes_;
  std::vector<Section> sections_;
  std::uint8_t type_definition_index_size_{4};
  std::uint8_t type_index_size_{4};
  std::uint8_t generic_container_index_size_{4};
  std::uint8_t parameter_index_size_{4};
  std::uint32_t image_record_size_{};
  std::uint32_t type_record_size_{};
  std::uint32_t method_record_size_{};
};

}  // namespace reverseplugin::il2cpp

