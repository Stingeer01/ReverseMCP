#include "reverseplugin/il2cpp/game_assembly.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <limits>
#include <span>
#include <system_error>
#include <utility>

namespace reverseplugin::il2cpp {
namespace {

constexpr std::uint64_t max_game_assembly_size = 2ULL * 1024 * 1024 * 1024;
constexpr std::size_t code_registration_module_count_index = 15;
constexpr std::size_t code_registration_modules_index = 16;

struct MappedFile final {
  HANDLE file{INVALID_HANDLE_VALUE};
  HANDLE mapping{};
  const std::byte* view{};
  std::size_t size{};

  MappedFile() = default;
  MappedFile(const MappedFile&) = delete;
  MappedFile& operator=(const MappedFile&) = delete;
  MappedFile(MappedFile&& other) noexcept
      : file(std::exchange(other.file, INVALID_HANDLE_VALUE)),
        mapping(std::exchange(other.mapping, nullptr)),
        view(std::exchange(other.view, nullptr)), size(std::exchange(other.size, 0)) {}
  MappedFile& operator=(MappedFile&&) = delete;
  ~MappedFile() {
    if (view) UnmapViewOfFile(view);
    if (mapping) CloseHandle(mapping);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  }

  [[nodiscard]] std::span<const std::byte> bytes() const noexcept {
    return {view, size};
  }
};

struct Section final {
  std::uint32_t virtual_address{};
  std::uint32_t virtual_size{};
  std::uint32_t raw_offset{};
  std::uint32_t raw_size{};
  std::uint32_t characteristics{};
};

struct PeImage final {
  std::uint64_t image_base{};
  std::uint32_t image_size{};
  std::string architecture;
  std::vector<Section> sections;
};

template <typename T>
std::optional<T> read(std::span<const std::byte> bytes, std::size_t offset) noexcept {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return std::nullopt;
  T value{};
  std::memcpy(&value, bytes.data() + offset, sizeof(T));
  return value;
}

std::expected<std::filesystem::path, std::string> canonical_file(
    const std::filesystem::path& path) {
  std::error_code ec;
  auto canonical = std::filesystem::weakly_canonical(path, ec);
  if (ec || !std::filesystem::is_regular_file(canonical, ec))
    return std::unexpected("GameAssembly path is not a regular file");
  return canonical;
}

std::expected<MappedFile, std::string> map_file(const std::filesystem::path& path) {
  MappedFile result;
  result.file = CreateFileW(path.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (result.file == INVALID_HANDLE_VALUE)
    return std::unexpected("Could not open GameAssembly.dll");
  LARGE_INTEGER file_size{};
  if (!GetFileSizeEx(result.file, &file_size) || file_size.QuadPart <= 0 ||
      static_cast<std::uint64_t>(file_size.QuadPart) > max_game_assembly_size)
    return std::unexpected("GameAssembly size is invalid or exceeds 2 GiB");
  result.size = static_cast<std::size_t>(file_size.QuadPart);
  result.mapping = CreateFileMappingW(result.file, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (!result.mapping) return std::unexpected("Could not map GameAssembly.dll");
  result.view = static_cast<const std::byte*>(
      MapViewOfFile(result.mapping, FILE_MAP_READ, 0, 0, 0));
  if (!result.view) return std::unexpected("Could not create a GameAssembly view");
  return result;
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
    return std::unexpected("Could not hash GameAssembly.dll");
  std::array<UCHAR, 32> digest{};
  if (BCryptFinishHash(hash.handle, digest.data(),
                       static_cast<ULONG>(digest.size()), 0) < 0)
    return std::unexpected("Could not finalize GameAssembly fingerprint");
  constexpr std::string_view digits = "0123456789abcdef";
  std::string result(digest.size() * 2, '0');
  for (std::size_t i = 0; i < digest.size(); ++i) {
    result[i * 2] = digits[digest[i] >> 4U];
    result[i * 2 + 1] = digits[digest[i] & 0x0fU];
  }
  return result;
}

std::expected<PeImage, std::string> parse_pe(std::span<const std::byte> bytes) {
  const auto dos = read<IMAGE_DOS_HEADER>(bytes, 0);
  if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
    return std::unexpected("GameAssembly.dll has an invalid DOS header");
  const auto nt_offset = static_cast<std::size_t>(dos->e_lfanew);
  const auto signature = read<DWORD>(bytes, nt_offset);
  const auto file_header = read<IMAGE_FILE_HEADER>(bytes, nt_offset + sizeof(DWORD));
  if (!signature || *signature != IMAGE_NT_SIGNATURE || !file_header)
    return std::unexpected("GameAssembly.dll has an invalid PE header");
  if (file_header->Machine != IMAGE_FILE_MACHINE_AMD64)
    return std::unexpected("Static IL2CPP registration mapping currently requires x86-64");
  const auto optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
  const auto optional = read<IMAGE_OPTIONAL_HEADER64>(bytes, optional_offset);
  if (!optional || optional->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    return std::unexpected("GameAssembly.dll has an invalid PE32+ optional header");
  const auto section_offset = optional_offset + file_header->SizeOfOptionalHeader;
  if (file_header->NumberOfSections == 0 || file_header->NumberOfSections > 128)
    return std::unexpected("GameAssembly.dll has an invalid section count");

  PeImage image{.image_base = optional->ImageBase,
                .image_size = optional->SizeOfImage,
                .architecture = "x86_64"};
  image.sections.reserve(file_header->NumberOfSections);
  for (std::size_t i = 0; i < file_header->NumberOfSections; ++i) {
    const auto header = read<IMAGE_SECTION_HEADER>(
        bytes, section_offset + i * sizeof(IMAGE_SECTION_HEADER));
    if (!header) return std::unexpected("GameAssembly.dll section table is truncated");
    const auto raw_end = static_cast<std::uint64_t>(header->PointerToRawData) +
                         header->SizeOfRawData;
    if (raw_end > bytes.size())
      return std::unexpected("GameAssembly.dll section exceeds the file bounds");
    image.sections.push_back({.virtual_address = header->VirtualAddress,
                              .virtual_size = header->Misc.VirtualSize,
                              .raw_offset = header->PointerToRawData,
                              .raw_size = header->SizeOfRawData,
                              .characteristics = header->Characteristics});
  }
  return image;
}

std::optional<std::size_t> va_to_offset(const PeImage& image,
                                        std::uint64_t va) noexcept {
  if (va < image.image_base) return std::nullopt;
  const auto rva = va - image.image_base;
  for (const auto& section : image.sections) {
    if (rva < section.virtual_address) continue;
    const auto delta = rva - section.virtual_address;
    if (delta < section.raw_size)
      return static_cast<std::size_t>(section.raw_offset + delta);
  }
  return std::nullopt;
}

std::optional<std::uint64_t> offset_to_va(const PeImage& image,
                                          std::size_t offset) noexcept {
  for (const auto& section : image.sections) {
    if (offset < section.raw_offset) continue;
    const auto delta = offset - section.raw_offset;
    if (delta < section.raw_size)
      return image.image_base + section.virtual_address + delta;
  }
  return std::nullopt;
}

bool data_section(const Section& section) noexcept {
  return section.raw_size != 0 &&
         (section.characteristics & IMAGE_SCN_MEM_READ) != 0 &&
         (section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0;
}

bool executable_va(const PeImage& image, std::uint64_t va) noexcept {
  if (va < image.image_base) return false;
  const auto rva = va - image.image_base;
  for (const auto& section : image.sections) {
    const auto extent = (std::max)(section.virtual_size, section.raw_size);
    if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
        rva >= section.virtual_address && rva - section.virtual_address < extent)
      return true;
  }
  return false;
}

bool readable_data_va(const PeImage& image, std::uint64_t va) noexcept {
  if (va < image.image_base) return false;
  const auto rva = va - image.image_base;
  for (const auto& section : image.sections) {
    const auto extent = (std::max)(section.virtual_size, section.raw_size);
    if (data_section(section) && rva >= section.virtual_address &&
        rva - section.virtual_address < extent)
      return true;
  }
  return false;
}

std::optional<std::uint64_t> find_string_va(std::span<const std::byte> bytes,
                                            const PeImage& image,
                                            std::string_view needle) {
  const auto* first = reinterpret_cast<const char*>(bytes.data());
  for (const auto& section : image.sections) {
    if (!data_section(section)) continue;
    const auto begin = first + section.raw_offset;
    const auto end = begin + section.raw_size;
    const auto found = std::search(begin, end, needle.begin(), needle.end());
    if (found != end)
      return offset_to_va(image, static_cast<std::size_t>(found - first));
  }
  return std::nullopt;
}

std::vector<std::uint64_t> find_pointer_references(
    std::span<const std::byte> bytes, const PeImage& image, std::uint64_t target) {
  std::vector<std::uint64_t> references;
  for (const auto& section : image.sections) {
    if (!data_section(section)) continue;
    const auto end = static_cast<std::size_t>(section.raw_offset) + section.raw_size;
    for (std::size_t offset = section.raw_offset; offset + sizeof(std::uint64_t) <= end;
         offset += alignof(std::uint64_t)) {
      const auto value = read<std::uint64_t>(bytes, offset);
      if (value && *value == target) {
        if (auto va = offset_to_va(image, offset)) references.push_back(*va);
      }
    }
  }
  return references;
}

std::optional<std::uint64_t> find_code_registration(
    std::span<const std::byte> bytes, const PeImage& image,
    std::uint32_t image_count) {
  constexpr std::string_view core_library{"mscorlib.dll\0", 13};
  const auto string_va = find_string_va(bytes, image, core_library);
  if (!string_va) return std::nullopt;
  const auto first_references = find_pointer_references(bytes, image, *string_va);
  for (const auto first : first_references) {
    const auto second_references = find_pointer_references(bytes, image, first);
    for (const auto second : second_references) {
      for (const auto& section : image.sections) {
        if (!data_section(section)) continue;
        const auto end = static_cast<std::size_t>(section.raw_offset) + section.raw_size;
        for (std::size_t offset = section.raw_offset + sizeof(std::uint64_t);
             offset + sizeof(std::uint64_t) <= end; offset += alignof(std::uint64_t)) {
          const auto value = read<std::uint64_t>(bytes, offset);
          if (!value || *value > second) continue;
          const auto delta = second - *value;
          if (delta >= static_cast<std::uint64_t>(image_count) * sizeof(std::uint64_t) ||
              delta % sizeof(std::uint64_t) != 0)
            continue;
          const auto count = read<std::uint64_t>(bytes, offset - sizeof(std::uint64_t));
          const auto reference_va = offset_to_va(image, offset);
          if (!count || *count != image_count || !reference_va ||
              *reference_va < code_registration_modules_index * sizeof(std::uint64_t))
            continue;
          const auto candidate = *reference_va -
                                 code_registration_modules_index * sizeof(std::uint64_t);
          const auto candidate_offset = va_to_offset(image, candidate);
          if (!candidate_offset) continue;
          const auto module_count = read<std::uint64_t>(
              bytes, *candidate_offset +
                         code_registration_module_count_index * sizeof(std::uint64_t));
          const auto modules = read<std::uint64_t>(
              bytes, *candidate_offset +
                         code_registration_modules_index * sizeof(std::uint64_t));
          if (module_count && modules && *module_count == image_count &&
              va_to_offset(image, *modules))
            return candidate;
        }
      }
    }
  }
  return std::nullopt;
}

std::optional<std::string> read_c_string(std::span<const std::byte> bytes,
                                         const PeImage& image, std::uint64_t va) {
  const auto offset = va_to_offset(image, va);
  if (!offset) return std::nullopt;
  constexpr std::size_t max_length = 512;
  const auto available = (std::min)(max_length, bytes.size() - *offset);
  const auto* begin = reinterpret_cast<const char*>(bytes.data() + *offset);
  const auto* end = begin + available;
  const auto* terminator = std::find(begin, end, '\0');
  if (terminator == end || terminator == begin) return std::nullopt;
  return std::string{begin, terminator};
}

std::string normalized_name(std::string_view name) {
  std::string result{name};
  std::ranges::transform(result, result.begin(), [](unsigned char value) {
    return static_cast<char>(std::tolower(value));
  });
  return result;
}

std::expected<std::unordered_map<std::string, std::vector<std::uint32_t>>, std::string>
read_modules(std::span<const std::byte> bytes, const PeImage& image,
             std::uint64_t code_registration, std::uint32_t expected_count) {
  const auto registration_offset = va_to_offset(image, code_registration);
  if (!registration_offset)
    return std::unexpected("IL2CPP code registration is outside the image");
  const auto count = read<std::uint64_t>(
      bytes, *registration_offset +
                 code_registration_module_count_index * sizeof(std::uint64_t));
  const auto modules_va = read<std::uint64_t>(
      bytes, *registration_offset +
                 code_registration_modules_index * sizeof(std::uint64_t));
  if (!count || !modules_va || *count != expected_count)
    return std::unexpected("IL2CPP code registration image count does not match metadata");
  const auto modules_offset = va_to_offset(image, *modules_va);
  if (!modules_offset)
    return std::unexpected("IL2CPP code-generation module table is outside the image");

  std::unordered_map<std::string, std::vector<std::uint32_t>> result;
  result.reserve(expected_count);
  for (std::size_t index = 0; index < expected_count; ++index) {
    const auto module_va = read<std::uint64_t>(
        bytes, *modules_offset + index * sizeof(std::uint64_t));
    if (!module_va) return std::unexpected("IL2CPP module table is truncated");
    const auto module_offset = va_to_offset(image, *module_va);
    if (!module_offset)
      return std::unexpected("IL2CPP code-generation module is outside the image");
    const auto name_va = read<std::uint64_t>(bytes, *module_offset);
    const auto method_count = read<std::uint32_t>(bytes, *module_offset + 8);
    const auto methods_va = read<std::uint64_t>(bytes, *module_offset + 16);
    if (!name_va || !method_count || !methods_va)
      return std::unexpected("IL2CPP code-generation module header is invalid");
    auto name = read_c_string(bytes, image, *name_va);
    if (!name) return std::unexpected("IL2CPP code-generation module name is invalid");
    const auto normalized = normalized_name(*name);
    if (result.contains(normalized))
      return std::unexpected("IL2CPP code-generation module names are not unique");

    std::vector<std::uint32_t> method_rvas;
    method_rvas.reserve(static_cast<std::size_t>(*method_count));
    if (*method_count != 0) {
      const auto methods_offset = va_to_offset(image, *methods_va);
      if (!methods_offset && readable_data_va(image, *methods_va)) {
        // Unity can place tiny tables in the zero-filled tail of .data and
        // initialize them at runtime. Their tokens are valid but no static RVA exists.
        method_rvas.resize(*method_count, 0);
      } else if (!methods_offset ||
                 *method_count >
                     (bytes.size() - *methods_offset) / sizeof(std::uint64_t)) {
        return std::unexpected("IL2CPP method pointer table for " + *name +
                               " is outside the image");
      } else {
        for (std::size_t method = 0; method < *method_count; ++method) {
          const auto pointer = read<std::uint64_t>(
              bytes, *methods_offset + method * sizeof(std::uint64_t));
          if (!pointer)
            return std::unexpected("IL2CPP method pointer table is truncated");
          if (*pointer == 0) {
            method_rvas.push_back(0);
            continue;
          }
          if (!executable_va(image, *pointer) || *pointer < image.image_base ||
              *pointer - image.image_base > std::numeric_limits<std::uint32_t>::max())
            return std::unexpected("IL2CPP method pointer is outside executable sections");
          method_rvas.push_back(static_cast<std::uint32_t>(*pointer - image.image_base));
        }
      }
    }
    result.emplace(normalized, std::move(method_rvas));
  }
  return result;
}

}  // namespace

std::optional<std::uint32_t> GameAssemblyInfo::method_rva(
    std::string_view image_name, std::uint32_t token) const {
  const auto rid = token & 0x00ffffffU;
  if (rid == 0) return std::nullopt;
  const auto found = method_rvas.find(normalized_name(image_name));
  if (found == method_rvas.end() || rid > found->second.size()) return std::nullopt;
  const auto rva = found->second[rid - 1];
  return rva == 0 ? std::nullopt : std::optional<std::uint32_t>{rva};
}

std::expected<GameAssemblyInfo, std::string> open_game_assembly(
    const std::filesystem::path& path, std::uint32_t expected_image_count) {
  if (expected_image_count == 0)
    return std::unexpected("IL2CPP metadata does not contain any images");
  auto canonical = canonical_file(path);
  if (!canonical) return std::unexpected(std::move(canonical.error()));
  auto mapped = map_file(*canonical);
  if (!mapped) return std::unexpected(std::move(mapped.error()));
  auto pe = parse_pe(mapped->bytes());
  if (!pe) return std::unexpected(std::move(pe.error()));
  const auto registration = find_code_registration(mapped->bytes(), *pe,
                                                    expected_image_count);
  if (!registration)
    return std::unexpected("Could not locate the IL2CPP code registration table");
  auto modules = read_modules(mapped->bytes(), *pe, *registration,
                              expected_image_count);
  if (!modules) return std::unexpected(std::move(modules.error()));
  auto hash = fingerprint(mapped->bytes());
  if (!hash) return std::unexpected(std::move(hash.error()));
  return GameAssemblyInfo{
      .path = std::move(*canonical),
      .fingerprint = std::move(*hash),
      .architecture = std::move(pe->architecture),
      .file_size = mapped->size,
      .image_base = pe->image_base,
      .image_size = pe->image_size,
      .code_registration_rva = static_cast<std::uint32_t>(*registration - pe->image_base),
      .method_rvas = std::move(*modules)};
}

}  // namespace reverseplugin::il2cpp
