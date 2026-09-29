#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <shared_mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace reverseplugin::process {

struct Error final {
  std::uint32_t native_code;
  std::string message;
};

template <typename T>
using Result = std::expected<T, Error>;

enum class Architecture { x86, x64, arm64, unknown };

struct ProcessInfo final {
  std::uint32_t pid;
  std::uint32_t parent_pid;
  std::uint32_t thread_count;
  std::string name;
};

struct ModuleInfo final {
  std::string name;
  std::string path;
  std::uint64_t base;
  std::uint64_t size;
};

struct MemoryRegion final {
  std::uint64_t base;
  std::uint64_t size;
  std::uint32_t state;
  std::uint32_t protection;
  std::uint32_t type;
  bool readable;
  bool writable;
  bool executable;
};

class UniqueHandle final {
 public:
  explicit UniqueHandle(HANDLE handle = nullptr) noexcept : handle_(handle) {}
  ~UniqueHandle();

  UniqueHandle(UniqueHandle&& other) noexcept;
  UniqueHandle& operator=(UniqueHandle&& other) noexcept;
  UniqueHandle(const UniqueHandle&) = delete;
  UniqueHandle& operator=(const UniqueHandle&) = delete;

  [[nodiscard]] HANDLE get() const noexcept { return handle_; }
  [[nodiscard]] explicit operator bool() const noexcept;

 private:
  HANDLE handle_;
};

class ProcessSession final {
 public:
  ProcessSession(std::uint64_t id, std::uint32_t pid, UniqueHandle handle,
                 Architecture architecture, std::string image_path);

  [[nodiscard]] std::uint64_t id() const noexcept { return id_; }
  [[nodiscard]] std::uint32_t pid() const noexcept { return pid_; }
  [[nodiscard]] HANDLE handle() const noexcept { return handle_.get(); }
  [[nodiscard]] Architecture architecture() const noexcept { return architecture_; }
  [[nodiscard]] const std::string& image_path() const noexcept { return image_path_; }

 private:
  std::uint64_t id_;
  std::uint32_t pid_;
  UniqueHandle handle_;
  Architecture architecture_;
  std::string image_path_;
};

class ProcessManager final {
 public:
  [[nodiscard]] Result<std::vector<ProcessInfo>> list_processes() const;
  [[nodiscard]] Result<std::shared_ptr<const ProcessSession>> attach(std::uint32_t pid);
  [[nodiscard]] bool detach(std::uint64_t session_id);
  [[nodiscard]] std::shared_ptr<const ProcessSession> session(std::uint64_t session_id) const;
  [[nodiscard]] Result<std::vector<ModuleInfo>> list_modules(
      const ProcessSession& session) const;
  [[nodiscard]] Result<std::vector<MemoryRegion>> query_regions(
      const ProcessSession& session, std::uint64_t start,
      std::size_t max_regions) const;
  [[nodiscard]] Result<std::vector<std::byte>> read(
      const ProcessSession& session, std::uint64_t address,
      std::size_t size) const;
  [[nodiscard]] Result<std::size_t> write(
      const ProcessSession& session, std::uint64_t address,
      std::span<const std::byte> bytes) const;

 private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::uint64_t, std::shared_ptr<const ProcessSession>> sessions_;
  std::atomic_uint64_t next_session_{1};
};

[[nodiscard]] std::string_view to_string(Architecture architecture) noexcept;

}  // namespace reverseplugin::process
