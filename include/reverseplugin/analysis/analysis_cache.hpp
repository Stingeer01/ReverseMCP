#pragma once

#include <filesystem>
#include <mutex>
#include <optional>
#include <string_view>

#include <nlohmann/json.hpp>

namespace reverseplugin::analysis {

class AnalysisCache final {
 public:
  AnalysisCache();
  explicit AnalysisCache(std::filesystem::path root);

  [[nodiscard]] std::optional<nlohmann::json> load(
      std::string_view fingerprint, std::string_view key) const;
  [[nodiscard]] bool store(std::string_view fingerprint, std::string_view key,
                           const nlohmann::json& value) const;

 private:
  [[nodiscard]] std::filesystem::path path_for(
      std::string_view fingerprint, std::string_view key) const;

  std::filesystem::path root_;
  mutable std::mutex mutex_;
};

}  // namespace reverseplugin::analysis
