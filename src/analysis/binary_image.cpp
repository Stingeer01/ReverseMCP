#include "reverseplugin/analysis/binary_image.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
#include <system_error>

namespace reverseplugin::analysis {
namespace {

template <typename T>
std::optional<T> read_object(std::span<const std::byte> bytes, std::size_t offset) {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return std::nullopt;
  T value{};
  std::memcpy(&value, bytes.data() + offset, sizeof(T));
  return value;
}

std::optional<std::size_t> raw_offset(std::uint32_t rva,
                                      std::span<const Section> sections,
                                      std::size_t file_size) {
  for (const auto& section : sections) {
    const auto extent = (std::max)(section.virtual_size, section.raw_size);
    if (rva < section.rva || static_cast<std::uint64_t>(rva) >=
                                   static_cast<std::uint64_t>(section.rva) + extent)
      continue;
    const auto delta = static_cast<std::uint64_t>(rva) - section.rva;
    if (delta >= section.raw_size) return std::nullopt;
    const auto offset = static_cast<std::uint64_t>(section.raw_offset) + delta;
    if (offset >= file_size) return std::nullopt;
    return static_cast<std::size_t>(offset);
  }
  if (rva < file_size) return static_cast<std::size_t>(rva);
  return std::nullopt;
}

std::optional<std::string> read_string(std::span<const std::byte> bytes,
                                       std::size_t offset) {
  if (offset >= bytes.size()) return std::nullopt;
  const auto remaining = bytes.subspan(offset);
  const auto limit = (std::min)(remaining.size(), std::size_t{4096});
  const auto* chars = reinterpret_cast<const char*>(remaining.data());
  const auto end = std::find(chars, chars + limit, '\0');
  if (end == chars + limit) return std::nullopt;
  return std::string(chars, end);
}

std::expected<std::string, std::string> fingerprint(std::span<const std::byte> bytes) {
  struct Algorithm final {
    BCRYPT_ALG_HANDLE value{};
    ~Algorithm() { if (value) BCryptCloseAlgorithmProvider(value, 0); }
  } algorithm;
  if (BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_SHA256_ALGORITHM,
                                  nullptr, 0) < 0)
    return std::unexpected("Could not initialize SHA-256 provider");
  DWORD object_size = 0;
  DWORD copied = 0;
  if (BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
                        &copied, 0) < 0)
    return std::unexpected("Could not query SHA-256 object size");
  std::vector<UCHAR> object(object_size);
  struct Hash final {
    BCRYPT_HASH_HANDLE value{};
    ~Hash() { if (value) BCryptDestroyHash(value); }
  } hash;
  if (BCryptCreateHash(algorithm.value, &hash.value, object.data(), object_size,
                       nullptr, 0, 0) < 0 ||
      BCryptHashData(hash.value,
                     reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
                     static_cast<ULONG>(bytes.size()), 0) < 0)
    return std::unexpected("Could not hash binary contents");
  std::array<UCHAR, 32> digest{};
  if (BCryptFinishHash(hash.value, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
    return std::unexpected("Could not finalize binary fingerprint");
  constexpr std::string_view digits = "0123456789abcdef";
  std::string text(digest.size() * 2, '0');
  for (std::size_t i = 0; i < digest.size(); ++i) {
    text[i * 2] = digits[digest[i] >> 4U];
    text[i * 2 + 1] = digits[digest[i] & 0x0fU];
  }
  return text;
}

}  // namespace

std::expected<std::shared_ptr<BinaryImage>, std::string> BinaryImage::open(
    const std::filesystem::path& path) {
  std::error_code ec;
  const auto canonical = std::filesystem::weakly_canonical(path, ec);
  if (ec || !std::filesystem::is_regular_file(canonical, ec))
    return std::unexpected("Binary path is not a regular file");
  const auto file_size = std::filesystem::file_size(canonical, ec);
  constexpr std::uint64_t max_file_size = 2ULL * 1024 * 1024 * 1024;
  if (ec || file_size < sizeof(IMAGE_DOS_HEADER) || file_size > max_file_size)
    return std::unexpected("Binary size is invalid or exceeds the 2 GiB PE parser limit");

  std::ifstream stream(canonical, std::ios::binary);
  if (!stream) return std::unexpected("Could not open binary for reading");
  auto image = std::shared_ptr<BinaryImage>{new BinaryImage};
  image->bytes_.resize(static_cast<std::size_t>(file_size));
  if (!stream.read(reinterpret_cast<char*>(image->bytes_.data()),
                   static_cast<std::streamsize>(image->bytes_.size())))
    return std::unexpected("Could not read the complete binary");
  const auto bytes = std::span<const std::byte>{image->bytes_};
  const auto dos = read_object<IMAGE_DOS_HEADER>(bytes, 0);
  if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
    return std::unexpected("File is not a valid PE image");
  const auto nt_offset = static_cast<std::size_t>(dos->e_lfanew);
  const auto signature = read_object<DWORD>(bytes, nt_offset);
  const auto file_header = read_object<IMAGE_FILE_HEADER>(bytes, nt_offset + sizeof(DWORD));
  if (!signature || *signature != IMAGE_NT_SIGNATURE || !file_header)
    return std::unexpected("PE signature or COFF header is truncated");
  const auto optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
  const auto magic = read_object<WORD>(bytes, optional_offset);
  if (!magic) return std::unexpected("PE optional header is truncated");

  IMAGE_DATA_DIRECTORY import_directory{};
  IMAGE_DATA_DIRECTORY export_directory{};
  std::uint32_t section_alignment = 0;
  if (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    const auto optional = read_object<IMAGE_OPTIONAL_HEADER64>(bytes, optional_offset);
    if (!optional) return std::unexpected("PE32+ optional header is truncated");
    image->info_.architecture = "x86_64";
    image->info_.image_base = optional->ImageBase;
    image->info_.entry_rva = optional->AddressOfEntryPoint;
    image->info_.image_size = optional->SizeOfImage;
    section_alignment = optional->SectionAlignment;
    if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
      import_directory = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
      export_directory = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  } else if (*magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    const auto optional = read_object<IMAGE_OPTIONAL_HEADER32>(bytes, optional_offset);
    if (!optional) return std::unexpected("PE32 optional header is truncated");
    image->info_.architecture = "x86";
    image->info_.image_base = optional->ImageBase;
    image->info_.entry_rva = optional->AddressOfEntryPoint;
    image->info_.image_size = optional->SizeOfImage;
    section_alignment = optional->SectionAlignment;
    if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
      import_directory = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
      export_directory = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  } else {
    return std::unexpected("Unsupported PE optional-header format");
  }
  if (section_alignment == 0) return std::unexpected("PE section alignment is zero");

  const auto section_offset = optional_offset + file_header->SizeOfOptionalHeader;
  if (file_header->NumberOfSections > 96)
    return std::unexpected("PE section count exceeds the defensive limit");
  image->sections_.reserve(file_header->NumberOfSections);
  for (std::size_t i = 0; i < file_header->NumberOfSections; ++i) {
    const auto header = read_object<IMAGE_SECTION_HEADER>(
        bytes, section_offset + i * sizeof(IMAGE_SECTION_HEADER));
    if (!header) return std::unexpected("PE section table is truncated");
    const auto name_size = std::find(header->Name, header->Name + IMAGE_SIZEOF_SHORT_NAME, 0) -
                           header->Name;
    image->sections_.push_back(Section{
        .name = std::string(reinterpret_cast<const char*>(header->Name), name_size),
        .rva = header->VirtualAddress,
        .virtual_size = header->Misc.VirtualSize,
        .raw_offset = header->PointerToRawData,
        .raw_size = header->SizeOfRawData,
        .readable = (header->Characteristics & IMAGE_SCN_MEM_READ) != 0,
        .writable = (header->Characteristics & IMAGE_SCN_MEM_WRITE) != 0,
        .executable = (header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0});
  }

  const auto string_at_rva = [&](std::uint32_t rva) -> std::optional<std::string> {
    const auto offset = raw_offset(rva, image->sections_, bytes.size());
    return offset ? read_string(bytes, *offset) : std::nullopt;
  };
  if (import_directory.VirtualAddress != 0) {
    const auto descriptor_offset = raw_offset(import_directory.VirtualAddress,
                                              image->sections_, bytes.size());
    if (descriptor_offset) {
      for (std::size_t i = 0; i < 65536; ++i) {
        const auto descriptor = read_object<IMAGE_IMPORT_DESCRIPTOR>(
            bytes, *descriptor_offset + i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (!descriptor || (descriptor->Name == 0 && descriptor->FirstThunk == 0)) break;
        const auto module = string_at_rva(descriptor->Name);
        if (!module) continue;
        const auto thunk_rva = descriptor->OriginalFirstThunk != 0
                                   ? descriptor->OriginalFirstThunk
                                   : descriptor->FirstThunk;
        const auto thunk_offset = raw_offset(thunk_rva, image->sections_, bytes.size());
        if (!thunk_offset) continue;
        const bool is_64 = image->info_.architecture == "x86_64";
        const auto width = is_64 ? sizeof(std::uint64_t) : sizeof(std::uint32_t);
        for (std::size_t index = 0; index < 1'000'000; ++index) {
          std::uint64_t thunk = 0;
          if (is_64) {
            const auto value = read_object<std::uint64_t>(bytes, *thunk_offset + index * width);
            if (!value) break;
            thunk = *value;
          } else {
            const auto value = read_object<std::uint32_t>(bytes, *thunk_offset + index * width);
            if (!value) break;
            thunk = *value;
          }
          if (thunk == 0) break;
          const auto ordinal_mask = is_64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
          Import imported{.module = *module,
                          .ordinal = static_cast<std::uint16_t>(thunk & 0xffffU),
                          .iat_rva = descriptor->FirstThunk +
                                     static_cast<std::uint32_t>(index * width),
                          .by_ordinal = (thunk & ordinal_mask) != 0};
          if (!imported.by_ordinal) {
            const auto name = string_at_rva(static_cast<std::uint32_t>(thunk) + 2);
            if (name) imported.name = *name;
          }
          image->imports_.push_back(std::move(imported));
        }
      }
    }
  }

  if (export_directory.VirtualAddress != 0) {
    const auto directory_offset = raw_offset(export_directory.VirtualAddress,
                                             image->sections_, bytes.size());
    const auto directory = directory_offset
                               ? read_object<IMAGE_EXPORT_DIRECTORY>(bytes, *directory_offset)
                               : std::nullopt;
    if (directory && directory->NumberOfFunctions <= 1'000'000 &&
        directory->NumberOfNames <= 1'000'000) {
      const auto functions = raw_offset(directory->AddressOfFunctions, image->sections_, bytes.size());
      const auto names = raw_offset(directory->AddressOfNames, image->sections_, bytes.size());
      const auto ordinals = raw_offset(directory->AddressOfNameOrdinals, image->sections_, bytes.size());
      if (functions) {
        std::vector<std::string> export_names(directory->NumberOfFunctions);
        if (names && ordinals) {
          for (std::size_t i = 0; i < directory->NumberOfNames; ++i) {
            const auto name_rva = read_object<std::uint32_t>(bytes, *names + i * 4);
            const auto ordinal = read_object<std::uint16_t>(bytes, *ordinals + i * 2);
            if (!name_rva || !ordinal || *ordinal >= export_names.size()) continue;
            if (auto name = string_at_rva(*name_rva)) export_names[*ordinal] = std::move(*name);
          }
        }
        for (std::size_t i = 0; i < directory->NumberOfFunctions; ++i) {
          const auto rva = read_object<std::uint32_t>(bytes, *functions + i * 4);
          if (!rva || *rva == 0) continue;
          Export exported{.name = std::move(export_names[i]),
                          .ordinal = static_cast<std::uint32_t>(directory->Base + i),
                          .rva = *rva};
          const auto directory_end = static_cast<std::uint64_t>(export_directory.VirtualAddress) +
                                     export_directory.Size;
          if (*rva >= export_directory.VirtualAddress && *rva < directory_end) {
            if (auto target = string_at_rva(*rva)) exported.forwarder = std::move(*target);
          }
          image->exports_.push_back(std::move(exported));
        }
      }
    }
  }

  image->info_.path = canonical;
  auto content_fingerprint = fingerprint(bytes);
  if (!content_fingerprint) return std::unexpected(std::move(content_fingerprint.error()));
  image->info_.fingerprint = std::move(*content_fingerprint);
  image->info_.format = "PE";
  image->info_.file_size = file_size;
  return image;
}

std::expected<std::span<const std::byte>, std::string> BinaryImage::bytes_at(
    std::uint32_t rva, std::size_t maximum) const {
  const auto offset = raw_offset(rva, sections_, bytes_.size());
  if (!offset) return std::unexpected("RVA is not backed by file bytes");
  std::size_t available = bytes_.size() - *offset;
  for (const auto& section : sections_) {
    if (rva >= section.rva &&
        static_cast<std::uint64_t>(rva) < static_cast<std::uint64_t>(section.rva) + section.raw_size) {
      available = static_cast<std::size_t>(section.raw_size - (rva - section.rva));
      break;
    }
  }
  return std::span<const std::byte>{bytes_}.subspan(*offset, (std::min)(maximum, available));
}

bool BinaryImage::contains_rva(std::uint64_t rva) const noexcept {
  return rva < info_.image_size;
}

const Section* BinaryImage::section_at(std::uint64_t rva) const noexcept {
  for (const auto& section : sections_) {
    const auto extent = (std::max)(section.virtual_size, section.raw_size);
    if (rva >= section.rva && rva < static_cast<std::uint64_t>(section.rva) + extent)
      return &section;
  }
  return nullptr;
}

bool BinaryImage::executable_rva(std::uint64_t rva) const noexcept {
  const auto* section = section_at(rva);
  return section != nullptr && section->executable;
}

std::expected<std::uint32_t, std::string> BinaryImage::normalize_address(
    std::uint64_t address) const {
  std::uint64_t rva = address;
  if (address >= info_.image_base) rva = address - info_.image_base;
  if (!contains_rva(rva) || rva > (std::numeric_limits<std::uint32_t>::max)())
    return std::unexpected("Address is outside the image");
  return static_cast<std::uint32_t>(rva);
}

}  // namespace reverseplugin::analysis
