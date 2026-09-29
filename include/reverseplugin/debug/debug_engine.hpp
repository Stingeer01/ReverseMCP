#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <expected>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "reverseplugin/process/process_manager.hpp"

namespace reverseplugin::debug {

using Error = process::Error;

template <typename T>
using Result = std::expected<T, Error>;

struct Event final {
  std::uint64_t sequence;
  std::string type;
  std::uint32_t process_id;
  std::uint32_t thread_id;
  std::uint32_t exception_code;
  std::uint64_t address;
  bool first_chance;
  std::optional<std::uint64_t> breakpoint_id;
};

struct Breakpoint final {
  std::uint64_t id;
  std::uint64_t address;
  std::byte original_byte;
  bool enabled;
};

struct RegisterContext final {
  std::string architecture;
  std::unordered_map<std::string, std::uint64_t> registers;
};

struct ThreadInfo final {
  std::uint32_t id;
  std::int32_t base_priority;
};

struct StackFrame final {
  std::uint64_t address;
  std::uint64_t stack_pointer;
  std::uint64_t frame_pointer;
  std::uint64_t module_base;
  std::string module;
  std::string symbol;
  std::uint64_t displacement;
};

enum class HardwareBreakpointAccess { execute, write, read_write };

struct HardwareBreakpoint final {
  std::uint64_t id;
  std::uint32_t thread_id;
  std::uint8_t slot;
  std::uint64_t address;
  HardwareBreakpointAccess access;
  std::uint8_t size;
};

class DebugSession final : public std::enable_shared_from_this<DebugSession> {
 public:
  static Result<std::shared_ptr<DebugSession>> attach(std::uint64_t id,
                                                       std::uint32_t pid);
  ~DebugSession();

  DebugSession(const DebugSession&) = delete;
  DebugSession& operator=(const DebugSession&) = delete;

  [[nodiscard]] std::uint64_t id() const noexcept { return id_; }
  [[nodiscard]] std::uint32_t pid() const noexcept { return pid_; }
  [[nodiscard]] Result<Breakpoint> add_breakpoint(std::uint64_t address);
  [[nodiscard]] Result<bool> remove_breakpoint(std::uint64_t breakpoint_id);
  [[nodiscard]] Result<void> resume(bool handled);
  [[nodiscard]] Result<void> single_step();
  [[nodiscard]] Result<std::vector<ThreadInfo>> threads() const;
  [[nodiscard]] Result<HardwareBreakpoint> add_hardware_breakpoint(
      std::uint32_t thread_id, std::uint64_t address,
      HardwareBreakpointAccess access, std::uint8_t size,
      std::optional<std::uint8_t> requested_slot);
  [[nodiscard]] Result<bool> remove_hardware_breakpoint(std::uint64_t id);
  [[nodiscard]] Result<std::uint32_t> suspend_thread(std::uint32_t thread_id);
  [[nodiscard]] Result<std::uint32_t> resume_thread(std::uint32_t thread_id);
  [[nodiscard]] Result<RegisterContext> registers(std::uint32_t thread_id);
  [[nodiscard]] Result<std::vector<StackFrame>> stack_trace(
      std::uint32_t thread_id, std::size_t max_frames);
  [[nodiscard]] Result<std::uint32_t> paused_thread_id();
  [[nodiscard]] Result<std::optional<Event>> wait_event(
      std::chrono::milliseconds timeout);
  [[nodiscard]] Result<void> detach();

 private:
  DebugSession(std::uint64_t id, std::uint32_t pid);

  template <typename T, typename Function>
  Result<T> invoke(Function&& function) {
    if (!active_.load(std::memory_order_acquire)) {
      return std::unexpected(Error{ERROR_INVALID_HANDLE, "Debugger session is not active"});
    }
    auto promise = std::make_shared<std::promise<Result<T>>>();
    auto future = promise->get_future();
    {
      std::lock_guard lock(command_mutex_);
      commands_.emplace_back(
          [promise, function = std::forward<Function>(function)]() mutable {
            promise->set_value(function());
          });
    }
    command_ready_.notify_one();
    return future.get();
  }

  void run(std::promise<Result<void>> ready);
  void process_commands();
  void handle_event(const DEBUG_EVENT& event);
  void publish(Event event);
  Result<void> write_byte(std::uint64_t address, std::byte value);
  Result<void> continue_pending(bool handled);
  Result<void> prepare_breakpoint_resume(std::uint32_t thread_id) const;
  Result<void> rewind_instruction_pointer(std::uint32_t thread_id) const;
  Result<RegisterContext> read_registers(std::uint32_t thread_id) const;
  Result<std::vector<StackFrame>> walk_stack(std::uint32_t thread_id,
                                             std::size_t max_frames) const;
  Result<void> restore_breakpoints();
  Result<void> configure_hardware_breakpoint(const HardwareBreakpoint& breakpoint,
                                             bool enabled) const;
  Result<void> restore_hardware_breakpoints();
  std::optional<std::uint64_t> hardware_breakpoint_hit(
      std::uint32_t thread_id) const;

  std::uint64_t id_;
  std::uint32_t pid_;
  process::UniqueHandle process_;
  process::Architecture architecture_{process::Architecture::unknown};
  std::jthread thread_;
  std::atomic_bool active_{false};
  bool stop_{false};
  bool paused_{false};
  bool initial_breakpoint_seen_{false};
  std::optional<DEBUG_EVENT> pending_event_;
  std::optional<std::uint64_t> reinsert_breakpoint_;
  bool user_single_step_{false};

  std::mutex command_mutex_;
  std::condition_variable command_ready_;
  std::deque<std::move_only_function<void()>> commands_;

  std::mutex event_mutex_;
  std::condition_variable event_ready_;
  std::deque<Event> events_;
  std::uint64_t next_event_{1};

  std::unordered_map<std::uint64_t, Breakpoint> breakpoints_;
  std::unordered_map<std::uint64_t, std::uint64_t> breakpoint_by_address_;
  std::uint64_t next_breakpoint_{1};
  std::unordered_map<std::uint64_t, HardwareBreakpoint> hardware_breakpoints_;
  std::unordered_map<std::uint32_t, std::uint32_t> owned_suspensions_;
  std::uint64_t next_hardware_breakpoint_{1};
};

[[nodiscard]] std::string_view to_string(HardwareBreakpointAccess access) noexcept;

class DebugEngine final {
 public:
  [[nodiscard]] Result<std::shared_ptr<DebugSession>> attach(std::uint32_t pid);
  [[nodiscard]] std::shared_ptr<DebugSession> session(std::uint64_t id) const;
  [[nodiscard]] Result<bool> detach(std::uint64_t id);

 private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::uint64_t, std::shared_ptr<DebugSession>> sessions_;
  std::atomic_uint64_t next_session_{1};
};

}  // namespace reverseplugin::debug
