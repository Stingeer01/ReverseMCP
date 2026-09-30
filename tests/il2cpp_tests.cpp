#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <Windows.h>

#include "reverseplugin/il2cpp/metadata.hpp"
#include "reverseplugin/il2cpp/game_assembly.hpp"

namespace {

void expect(bool condition, std::string_view message) {
  if (!condition) throw std::runtime_error(std::string{message});
}

template <typename T>
void append(std::vector<std::byte>& bytes, T value) {
  const auto offset = bytes.size();
  bytes.resize(offset + sizeof(T));
  std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

template <typename T>
void write_at(std::vector<std::byte>& bytes, std::size_t offset, T value) {
  expect(offset + sizeof(T) <= bytes.size(), "fixture write exceeds buffer");
  std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

std::vector<std::byte> make_v39_fixture() {
  constexpr std::size_t section_count = 31;
  constexpr std::size_t header_size = 8 + section_count * 12;
  std::vector<std::byte> file(header_size);
  write_at(file, 0, std::uint32_t{0xfab11baf});
  write_at(file, 4, std::uint32_t{39});

  const auto add_section = [&](std::size_t index, const std::vector<std::byte>& data,
                               std::uint32_t count) {
    const auto offset = static_cast<std::uint32_t>(file.size());
    write_at(file, 8 + index * 12, static_cast<std::int32_t>(offset));
    write_at(file, 12 + index * 12, static_cast<std::int32_t>(data.size()));
    write_at(file, 16 + index * 12, static_cast<std::int32_t>(count));
    file.insert(file.end(), data.begin(), data.end());
  };

  const std::string strings{"\0Assembly-CSharp.dll\0Test.Namespace\0Player\0health\0Tick\0delta\0", 61};
  const auto name_index = [&](std::string_view value) {
    const auto found = strings.find(value);
    expect(found != std::string::npos, "fixture string was not found");
    return static_cast<std::uint32_t>(found);
  };
  std::vector<std::byte> string_bytes(strings.size());
  std::memcpy(string_bytes.data(), strings.data(), strings.size());

  std::vector<std::byte> method;
  append(method, name_index("Tick"));
  append(method, std::uint8_t{0});
  append(method, std::int32_t{1});
  append(method, std::int32_t{0x08000000});
  append(method, std::uint8_t{0});
  append(method, std::uint8_t{0xff});
  append(method, std::uint32_t{0x06000001});
  append(method, std::uint16_t{6});
  append(method, std::uint16_t{0});
  append(method, std::uint16_t{0xffff});
  append(method, std::uint16_t{1});

  std::vector<std::byte> parameter;
  append(parameter, name_index("delta"));
  append(parameter, std::uint32_t{0x08000001});
  append(parameter, std::int32_t{1});

  std::vector<std::byte> field;
  append(field, name_index("health"));
  append(field, std::int32_t{1});
  append(field, std::uint32_t{0x04000001});

  std::vector<std::byte> type;
  append(type, name_index("Player"));
  append(type, name_index("Test.Namespace"));
  append(type, std::int32_t{-1});
  append(type, std::int32_t{-1});
  append(type, std::int32_t{-1});
  append(type, std::uint8_t{0xff});
  append(type, std::uint32_t{1});
  append(type, std::int32_t{0});
  append(type, std::int32_t{0});
  for (int i = 0; i < 6; ++i) append(type, std::int32_t{-1});
  append(type, std::uint16_t{1});
  append(type, std::uint16_t{0});
  append(type, std::uint16_t{1});
  for (int i = 0; i < 5; ++i) append(type, std::uint16_t{0});
  append(type, std::uint32_t{0});
  append(type, std::uint32_t{0x02000001});

  std::vector<std::byte> image;
  append(image, name_index("Assembly-CSharp.dll"));
  append(image, std::int32_t{0});
  append(image, std::uint8_t{0});
  append(image, std::uint32_t{1});
  append(image, std::uint8_t{0xff});
  append(image, std::uint32_t{0});
  append(image, std::int32_t{-1});
  append(image, std::uint32_t{1});
  append(image, std::int32_t{-1});
  append(image, std::uint32_t{0});

  const std::array<std::vector<std::byte>, section_count> sections = [&] {
    std::array<std::vector<std::byte>, section_count> result{};
    result[2] = string_bytes;
    result[5] = method;
    result[10] = parameter;
    result[11] = field;
    result[19] = type;
    result[20] = image;
    return result;
  }();
  for (std::size_t i = 0; i < sections.size(); ++i) {
    std::uint32_t count = 0;
    if (i == 2) count = 6;
    if (i == 5 || i == 10 || i == 11 || i == 19 || i == 20) count = 1;
    add_section(i, sections[i], count);
  }
  return file;
}

void compact_metadata_v39_round_trip() {
  const auto path = std::filesystem::temp_directory_path() /
                    ("reverseplugin-il2cpp-" + std::to_string(GetCurrentProcessId()) + ".dat");
  struct Cleanup final {
    std::filesystem::path path;
    ~Cleanup() { std::error_code ec; std::filesystem::remove(path, ec); }
  } cleanup{path};
  const auto fixture = make_v39_fixture();
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  expect(output.write(reinterpret_cast<const char*>(fixture.data()),
                      static_cast<std::streamsize>(fixture.size())).good(),
         "could not write IL2CPP fixture");
  output.close();

  auto metadata = reverseplugin::il2cpp::Metadata::open(path);
  expect(metadata.has_value(), "could not parse compact IL2CPP v39 fixture");
  expect((*metadata)->info().version == 39, "metadata version is incorrect");
  expect((*metadata)->info().image_count == 1, "image count is incorrect");
  expect((*metadata)->info().type_count == 1, "type count is incorrect");
  expect((*metadata)->info().method_count == 1, "method count is incorrect");

  auto image = (*metadata)->image(0);
  auto type = (*metadata)->type(0);
  auto method = (*metadata)->method(0);
  auto field = (*metadata)->field(0);
  auto parameter = (*metadata)->parameter(0);
  expect(image && type && method && field && parameter, "fixture records did not parse");
  expect((*metadata)->string_at(image->name_index) == "Assembly-CSharp.dll",
         "image name is incorrect");
  expect((*metadata)->string_at(type->name_index) == "Player", "type name is incorrect");
  expect((*metadata)->string_at(method->name_index) == "Tick", "method name is incorrect");
  expect((*metadata)->string_at(field->name_index) == "health", "field name is incorrect");
  expect((*metadata)->string_at(parameter->name_index) == "delta",
         "parameter name is incorrect");
  expect(type->method_count == 1 && type->field_count == 1,
         "type member counts are incorrect");
  expect(method->parameter_count == 1 && method->parameter_start == 0,
         "method parameter range is incorrect");
}

void method_token_mapping() {
  reverseplugin::il2cpp::GameAssemblyInfo assembly;
  assembly.method_rvas.emplace("assembly-csharp.dll",
                               std::vector<std::uint32_t>{0x1234U, 0U, 0x5678U});
  expect(assembly.method_rva("Assembly-CSharp.dll", 0x06000001U) == 0x1234U,
         "method token did not resolve case-insensitively");
  expect(!assembly.method_rva("Assembly-CSharp.dll", 0x06000002U),
         "null method pointer should remain unresolved");
  expect(assembly.method_rva("assembly-csharp.dll", 0x06000003U) == 0x5678U,
         "method RID did not resolve");
  expect(!assembly.method_rva("missing.dll", 0x06000001U),
         "unknown module should remain unresolved");
}

}  // namespace

int main() {
  compact_metadata_v39_round_trip();
  method_token_mapping();
}
