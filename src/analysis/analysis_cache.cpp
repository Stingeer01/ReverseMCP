#include "reverseplugin/analysis/analysis_cache.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <array>
#include <fstream>
#include <system_error>

namespace reverseplugin::analysis {
namespace {

std::filesystem::path default_root() {
  std::array<wchar_t, 32768> local{};
  const auto length = GetEnvironmentVariableW(
      L"LOCALAPPDATA", local.data(), static_cast<DWORD>(local.size()));
  if (length > 0 && length < local.size())
    return std::filesystem::path{local.data()} / "ReversePlugin" / "analysis-cache-v1";
  std::error_code ec;
  auto temporary = std::filesystem::temp_directory_path(ec);
  return (ec ? std::filesystem::path{"."} : temporary) /
         "ReversePlugin" / "analysis-cache-v1";
}

bool safe_component(std::string_view value) {
  if (value.empty() || value.size() > 128) return false;
  for (const auto character : value) {
    if ((character < 'a' || character > 'z') &&
        (character < 'A' || character > 'Z') &&
        (character < '0' || character > '9') &&
        character != '-' && character != '_')
      return false;
  }
  return true;
}

}  // namespace

AnalysisCache::AnalysisCache() : root_(default_root()) {}
AnalysisCache::AnalysisCache(std::filesystem::path root) : root_(std::move(root)) {}

std::filesystem::path AnalysisCache::path_for(
    std::string_view fingerprint, std::string_view key) const {
  if (!safe_component(fingerprint) || !safe_component(key)) return {};
  return root_ / std::string{fingerprint} / (std::string{key} + ".json");
}

std::optional<nlohmann::json> AnalysisCache::load(
    std::string_view fingerprint, std::string_view key) const {
  const auto path = path_for(fingerprint, key);
  if (path.empty()) return std::nullopt;
  std::lock_guard lock(mutex_);
  std::ifstream input(path, std::ios::binary);
  if (!input) return std::nullopt;
  auto value = nlohmann::json::parse(input, nullptr, false);
  if (value.is_discarded() || !value.is_object()) return std::nullopt;
  return value;
}

bool AnalysisCache::store(std::string_view fingerprint, std::string_view key,
                          const nlohmann::json& value) const {
  const auto path = path_for(fingerprint, key);
  if (path.empty()) return false;
  std::lock_guard lock(mutex_);
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) return false;
  auto temporary = path;
  temporary += L"." + std::to_wstring(GetCurrentProcessId()) + L".tmp";
  {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output || !(output << value.dump())) return false;
  }
  if (MoveFileExW(temporary.c_str(), path.c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0)
    return true;
  std::filesystem::remove(temporary, ec);
  return false;
}

}  // namespace reverseplugin::analysis
