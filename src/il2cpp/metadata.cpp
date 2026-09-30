#include "reverseplugin/il2cpp/metadata.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <system_error>

namespace reverseplugin::il2cpp {
namespace {

constexpr std::uint32_t metadata_magic = 0xfab11bafU;
constexpr std::size_t section_count = 31;
constexpr std::size_t header_size = 8 + section_count * 12;
constexpr std::uint64_t max_metadata_size = 512ULL * 1024 * 1024;

enum SectionIndex : std::size_t {
  strings = 2,
  methods = 5,
  parameters = 10,
  fields = 11,
  generic_containers = 14,
  interface_offsets = 18,
  type_definitions = 19,
  images = 20,
};

template <typename T>
std::expected<T, std::string> read_value(std::span<const std::byte> bytes,
                                         std::size_t offset) {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - offset)
    return std::unexpected("IL2CPP metadata record is truncated");
  T value{};
  std::memcpy(&value, bytes.data() + offset, sizeof(T));
  return value;
}

std::uint8_t index_size(std::uint32_t count) noexcept {
  if (count < std::numeric_limits<std::uint8_t>::max()) return 1;
  if (count < std::numeric_limits<std::uint16_t>::max()) return 2;
  return 4;
}

std::expected<std::int32_t, std::string> read_index(
    std::span<const std::byte> bytes, std::size_t& offset, std::uint8_t width) {
  if (width == 1) {
    auto value = read_value<std::uint8_t>(bytes, offset);
    offset += 1;
    if (!value) return std::unexpected(std::move(value.error()));
    return *value == std::numeric_limits<std::uint8_t>::max() ? -1 : *value;
  }
  if (width == 2) {
    auto value = read_value<std::uint16_t>(bytes, offset);
    offset += 2;
    if (!value) return std::unexpected(std::move(value.error()));
    return *value == std::numeric_limits<std::uint16_t>::max() ? -1 : *value;
  }
  if (width == 4) {
    auto value = read_value<std::int32_t>(bytes, offset);
    offset += 4;
    return value;
  }
  return std::unexpected("Unsupported IL2CPP metadata index width");
}

std::expected<std::string, std::string> fingerprint(
    std::span<const std::byte> bytes) {
  struct Algorithm final {
    BCRYPT_ALG_HANDLE handle{};
    ~Algorithm() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
  } algorithm;
  if (BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_SHA256_ALGORITHM,
                                  nullptr, 0) < 0)
    return std::unexpected("Could not initialize SHA-256 provider");
  DWORD object_size = 0;
  DWORD copied = 0;
  if (BCryptGetProperty(algorithm.handle, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
                        &copied, 0) < 0)
    return std::unexpected("Could not query SHA-256 object size");
  std::vector<UCHAR> object(object_size);
  struct Hash final {
    BCRYPT_HASH_HANDLE handle{};
    ~Hash() { if (handle) BCryptDestroyHash(handle); }
  } hash;
  if (BCryptCreateHash(algorithm.handle, &hash.handle, object.data(), object_size,
                       nullptr, 0, 0) < 0 ||
      BCryptHashData(hash.handle,
                     reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
                     static_cast<ULONG>(bytes.size()), 0) < 0)
    return std::unexpected("Could not hash IL2CPP metadata");
  std::array<UCHAR, 32> digest{};
  if (BCryptFinishHash(hash.handle, digest.data(),
                       static_cast<ULONG>(digest.size()), 0) < 0)
    return std::unexpected("Could not finalize IL2CPP metadata fingerprint");
  constexpr std::string_view digits = "0123456789abcdef";
  std::string result(digest.size() * 2, '0');
  for (std::size_t i = 0; i < digest.size(); ++i) {
    result[i * 2] = digits[digest[i] >> 4U];
    result[i * 2 + 1] = digits[digest[i] & 0x0fU];
  }
  return result;
}

bool valid_range(std::int32_t start, std::uint32_t count,
                 std::uint32_t total) noexcept {
  if (count == 0) return start == -1 || start >= 0;
  if (start < 0) return false;
  return static_cast<std::uint64_t>(start) + count <= total;
}

}  // namespace

std::expected<std::shared_ptr<Metadata>, std::string> Metadata::open(
    const std::filesystem::path& path) {
  std::error_code ec;
  const auto canonical = std::filesystem::weakly_canonical(path, ec);
  if (ec || !std::filesystem::is_regular_file(canonical, ec))
    return std::unexpected("IL2CPP metadata path is not a regular file");
  const auto file_size = std::filesystem::file_size(canonical, ec);
  if (ec || file_size < header_size || file_size > max_metadata_size)
    return std::unexpected("IL2CPP metadata size is invalid or exceeds 512 MiB");

  auto metadata = std::shared_ptr<Metadata>{new Metadata};
  metadata->bytes_.resize(static_cast<std::size_t>(file_size));
  std::ifstream input(canonical, std::ios::binary);
  if (!input || !input.read(reinterpret_cast<char*>(metadata->bytes_.data()),
                            static_cast<std::streamsize>(metadata->bytes_.size())))
    return std::unexpected("Could not read the complete IL2CPP metadata file");

  const auto bytes = std::span<const std::byte>{metadata->bytes_};
  const auto magic = read_value<std::uint32_t>(bytes, 0);
  const auto version = read_value<std::uint32_t>(bytes, 4);
  if (!magic || !version || *magic != metadata_magic)
    return std::unexpected("File does not contain an IL2CPP metadata header");
  if (*version < 38 || *version > 39)
    return std::unexpected("Unsupported IL2CPP metadata version; this build supports compact versions 38 and 39");

  metadata->sections_.reserve(section_count);
  for (std::size_t i = 0; i < section_count; ++i) {
    const auto base = 8 + i * 12;
    const auto offset = read_value<std::int32_t>(bytes, base);
    const auto size = read_value<std::int32_t>(bytes, base + 4);
    const auto count = read_value<std::int32_t>(bytes, base + 8);
    if (!offset || !size || !count || *offset < 0 || *size < 0 || *count < 0)
      return std::unexpected("IL2CPP metadata contains a negative section value");
    if (static_cast<std::uint64_t>(*offset) + static_cast<std::uint64_t>(*size) > file_size)
      return std::unexpected("IL2CPP metadata section exceeds the file boundary");
    metadata->sections_.push_back({static_cast<std::uint32_t>(*offset),
                                   static_cast<std::uint32_t>(*size),
                                   static_cast<std::uint32_t>(*count)});
  }

  const auto& type_section = metadata->sections_[type_definitions];
  const auto& method_section = metadata->sections_[methods];
  const auto& field_section = metadata->sections_[fields];
  const auto& parameter_section = metadata->sections_[parameters];
  const auto& image_section = metadata->sections_[images];
  metadata->type_definition_index_size_ = index_size(type_section.count);
  metadata->generic_container_index_size_ =
      index_size(metadata->sections_[generic_containers].count);
  metadata->parameter_index_size_ = *version >= 39 ? index_size(parameter_section.count) : 4;
  const auto& interface_section = metadata->sections_[interface_offsets];
  const auto interface_record_size = interface_section.count == 0
      ? 8U : interface_section.size / interface_section.count;
  metadata->type_index_size_ = interface_record_size == 5 ? 1 :
                               interface_record_size == 6 ? 2 : 4;

  metadata->image_record_size_ = 32 + 2 * metadata->type_definition_index_size_;
  metadata->type_record_size_ = 68 + 3 * metadata->type_index_size_ +
                                metadata->generic_container_index_size_;
  metadata->method_record_size_ = 20 + metadata->type_definition_index_size_ +
                                  metadata->type_index_size_ +
                                  metadata->parameter_index_size_ +
                                  metadata->generic_container_index_size_;

  const auto exact_size = [](const Section& section, std::uint32_t record_size) {
    return section.count == 0 ||
           static_cast<std::uint64_t>(section.count) * record_size == section.size;
  };
  if (!exact_size(image_section, metadata->image_record_size_) ||
      !exact_size(type_section, metadata->type_record_size_) ||
      !exact_size(method_section, metadata->method_record_size_) ||
      !exact_size(field_section, 4 + metadata->type_index_size_ + 4) ||
      !exact_size(parameter_section, 8 + metadata->type_index_size_))
    return std::unexpected("IL2CPP metadata record sizes do not match the compact v38/v39 layout");

  metadata->info_ = {.path = canonical,
                     .version = *version,
                     .file_size = file_size,
                     .image_count = image_section.count,
                     .type_count = type_section.count,
                     .method_count = method_section.count,
                     .field_count = field_section.count,
                     .parameter_count = parameter_section.count};
  auto hash = fingerprint(bytes);
  if (!hash) return std::unexpected(std::move(hash.error()));
  metadata->info_.fingerprint = std::move(*hash);

  for (std::size_t i = 0; i < image_section.count; ++i) {
    auto value = metadata->image(i);
    if (!value || !valid_range(value->type_start, value->type_count, type_section.count))
      return std::unexpected("IL2CPP image contains an invalid type range");
  }
  for (std::size_t i = 0; i < type_section.count; ++i) {
    auto value = metadata->type(i);
    if (!value || !valid_range(value->method_start, value->method_count, method_section.count) ||
        !valid_range(value->field_start, value->field_count, field_section.count))
      return std::unexpected("IL2CPP type contains an invalid member range");
  }
  return metadata;
}

std::expected<std::string_view, std::string> Metadata::string_at(
    std::uint32_t index) const {
  const auto& section = sections_[strings];
  if (index >= section.size) return std::unexpected("IL2CPP string index is out of range");
  const auto begin = static_cast<std::size_t>(section.offset) + index;
  const auto end_offset = static_cast<std::size_t>(section.offset) + section.size;
  const auto limit = (std::min)(end_offset, begin + 4096);
  const auto* first = reinterpret_cast<const char*>(bytes_.data() + begin);
  const auto* last = reinterpret_cast<const char*>(bytes_.data() + limit);
  const auto* terminator = std::find(first, last, '\0');
  if (terminator == last) return std::unexpected("IL2CPP metadata string is not terminated within 4096 bytes");
  return std::string_view{first, static_cast<std::size_t>(terminator - first)};
}

std::expected<ImageDefinition, std::string> Metadata::image(std::size_t index) const {
  const auto& section = sections_[images];
  if (index >= section.count) return std::unexpected("IL2CPP image index is out of range");
  std::size_t cursor = section.offset + index * image_record_size_;
  ImageDefinition result{};
  auto name = read_value<std::uint32_t>(bytes_, cursor); cursor += 4;
  auto assembly = read_value<std::int32_t>(bytes_, cursor); cursor += 4;
  auto type_start = read_index(bytes_, cursor, type_definition_index_size_);
  auto type_count = read_value<std::uint32_t>(bytes_, cursor); cursor += 4;
  auto exported_start = read_index(bytes_, cursor, type_definition_index_size_);
  auto exported_count = read_value<std::uint32_t>(bytes_, cursor); cursor += 4;
  auto entry = read_value<std::int32_t>(bytes_, cursor); cursor += 4;
  auto token = read_value<std::uint32_t>(bytes_, cursor);
  if (!name || !assembly || !type_start || !type_count || !exported_start ||
      !exported_count || !entry || !token)
    return std::unexpected("IL2CPP image definition is truncated");
  result.name_index = *name;
  result.assembly_index = *assembly;
  result.type_start = *type_start;
  result.type_count = *type_count;
  result.token = *token;
  return result;
}

std::expected<TypeDefinition, std::string> Metadata::type(std::size_t index) const {
  const auto& section = sections_[type_definitions];
  if (index >= section.count) return std::unexpected("IL2CPP type index is out of range");
  std::size_t cursor = section.offset + index * type_record_size_;
  TypeDefinition result{};
  auto name = read_value<std::uint32_t>(bytes_, cursor); cursor += 4;
  auto namespc = read_value<std::uint32_t>(bytes_, cursor); cursor += 4;
  for (int i = 0; i < 3; ++i) {
    auto ignored = read_index(bytes_, cursor, type_index_size_);
    if (!ignored) return std::unexpected(std::move(ignored.error()));
  }
  auto generic = read_index(bytes_, cursor, generic_container_index_size_);
  auto flags = read_value<std::uint32_t>(bytes_, cursor); cursor += 4;
  auto field_start = read_value<std::int32_t>(bytes_, cursor); cursor += 4;
  auto method_start = read_value<std::int32_t>(bytes_, cursor); cursor += 4;
  cursor += 6 * 4;
  auto method_count = read_value<std::uint16_t>(bytes_, cursor); cursor += 2;
  cursor += 2;
  auto field_count = read_value<std::uint16_t>(bytes_, cursor); cursor += 2;
  cursor += 5 * 2;
  auto bitfield = read_value<std::uint32_t>(bytes_, cursor); cursor += 4;
  auto token = read_value<std::uint32_t>(bytes_, cursor);
  if (!name || !namespc || !generic || !flags || !field_start || !method_start ||
      !method_count || !field_count || !bitfield || !token)
    return std::unexpected("IL2CPP type definition is truncated");
  result = {.name_index = *name, .namespace_index = *namespc,
            .field_start = *field_start, .method_start = *method_start,
            .method_count = *method_count, .field_count = *field_count,
            .flags = *flags, .bitfield = *bitfield, .token = *token};
  return result;
}

std::expected<MethodDefinition, std::string> Metadata::method(std::size_t index) const {
  const auto& section = sections_[methods];
  if (index >= section.count) return std::unexpected("IL2CPP method index is out of range");
  std::size_t cursor = section.offset + index * method_record_size_;
  MethodDefinition result{};
  auto name = read_value<std::uint32_t>(bytes_, cursor); cursor += 4;
  auto declaring = read_index(bytes_, cursor, type_definition_index_size_);
  auto return_type = read_index(bytes_, cursor, type_index_size_);
  cursor += 4;
  auto parameter_start = read_index(bytes_, cursor, parameter_index_size_);
  auto generic = read_index(bytes_, cursor, generic_container_index_size_);
  auto token = read_value<std::uint32_t>(bytes_, cursor); cursor += 4;
  auto flags = read_value<std::uint16_t>(bytes_, cursor); cursor += 2;
  cursor += 2;
  auto slot = read_value<std::uint16_t>(bytes_, cursor); cursor += 2;
  auto parameter_count = read_value<std::uint16_t>(bytes_, cursor);
  if (!name || !declaring || !return_type || !parameter_start || !generic ||
      !token || !flags || !slot || !parameter_count)
    return std::unexpected("IL2CPP method definition is truncated");
  result = {.name_index = *name, .declaring_type = *declaring,
            .return_type = *return_type, .parameter_start = *parameter_start,
            .token = *token, .flags = *flags, .slot = *slot,
            .parameter_count = *parameter_count};
  if (!valid_range(result.parameter_start, result.parameter_count,
                   info_.parameter_count))
    return std::unexpected("IL2CPP method contains an invalid parameter range");
  return result;
}

std::expected<FieldDefinition, std::string> Metadata::field(std::size_t index) const {
  const auto& section = sections_[fields];
  if (index >= section.count) return std::unexpected("IL2CPP field index is out of range");
  std::size_t cursor = section.offset + index * (4 + type_index_size_ + 4);
  auto name = read_value<std::uint32_t>(bytes_, cursor); cursor += 4;
  auto type_index = read_index(bytes_, cursor, type_index_size_);
  auto token = read_value<std::uint32_t>(bytes_, cursor);
  if (!name || !type_index || !token) return std::unexpected("IL2CPP field definition is truncated");
  return FieldDefinition{.name_index = *name, .type_index = *type_index,
                         .token = *token};
}

std::expected<ParameterDefinition, std::string> Metadata::parameter(
    std::size_t index) const {
  const auto& section = sections_[parameters];
  if (index >= section.count) return std::unexpected("IL2CPP parameter index is out of range");
  std::size_t cursor = section.offset + index * (8 + type_index_size_);
  auto name = read_value<std::uint32_t>(bytes_, cursor); cursor += 4;
  auto token = read_value<std::uint32_t>(bytes_, cursor); cursor += 4;
  auto type_index = read_index(bytes_, cursor, type_index_size_);
  if (!name || !token || !type_index)
    return std::unexpected("IL2CPP parameter definition is truncated");
  return ParameterDefinition{.name_index = *name, .token = *token,
                             .type_index = *type_index};
}

}  // namespace reverseplugin::il2cpp
