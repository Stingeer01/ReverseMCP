#include "reverseplugin/debug/debug_engine.hpp"

#include <algorithm>
#include <utility>

namespace reverseplugin::debug {
namespace {

Error system_error(std::string message, DWORD code = GetLastError()) {
  return {.native_code = code, .message = std::move(message)};
}

process::Architecture architecture_of(HANDLE handle) {
  USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
  USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
  if (!IsWow64Process2(handle, &process_machine, &native_machine)) {
    return process::Architecture::unknown;
  }
  const auto machine = process_machine == IMAGE_FILE_MACHINE_UNKNOWN
                           ? native_machine
                           : process_machine;
  if (machine == IMAGE_FILE_MACHINE_I386) {
    return process::Architecture::x86;
  }
  if (machine == IMAGE_FILE_MACHINE_AMD64) {
    return process::Architecture::x64;
  }
  return process::Architecture::unknown;
}

}  // namespace

DebugSession::DebugSession(std::uint64_t id, std::uint32_t pid)
    : id_(id), pid_(pid) {}

DebugSession::~DebugSession() {
  if (active_.load(std::memory_order_acquire)) {
    static_cast<void>(detach());
  }
}

Result<std::shared_ptr<DebugSession>> DebugSession::attach(std::uint64_t id,
                                                           std::uint32_t pid) {
  auto session = std::shared_ptr<DebugSession>(new DebugSession(id, pid));
  std::promise<Result<void>> ready;
  auto future = ready.get_future();
  auto* raw_session = session.get();
  session->thread_ = std::jthread(
      [raw_session](std::stop_token, std::promise<Result<void>> signal) mutable {
        raw_session->run(std::move(signal));
      },
      std::move(ready));
  auto started = future.get();
  if (!started) {
    return std::unexpected(std::move(started.error()));
  }
  return session;
}

void DebugSession::run(std::promise<Result<void>> ready) {
  if (!DebugActiveProcess(pid_)) {
    ready.set_value(std::unexpected(system_error("DebugActiveProcess failed")));
    return;
  }
  DebugSetProcessKillOnExit(FALSE);
  process_ = process::UniqueHandle{OpenProcess(
      PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
          PROCESS_VM_OPERATION,
      FALSE, pid_)};
  if (!process_) {
    const auto error = system_error("OpenProcess for debugger failed");
    DebugActiveProcessStop(pid_);
    ready.set_value(std::unexpected(error));
    return;
  }
  architecture_ = architecture_of(process_.get());
  if (architecture_ != process::Architecture::x86 &&
      architecture_ != process::Architecture::x64) {
    DebugActiveProcessStop(pid_);
    ready.set_value(std::unexpected(
        Error{ERROR_NOT_SUPPORTED, "Debugger currently supports x86 and x64 targets"}));
    return;
  }

  active_.store(true, std::memory_order_release);
  ready.set_value(Result<void>{});
  while (!stop_) {
    process_commands();
    if (stop_) {
      break;
    }
    if (paused_) {
      std::unique_lock lock(command_mutex_);
      command_ready_.wait_for(lock, std::chrono::milliseconds{50},
                              [this] { return !commands_.empty() || stop_; });
      continue;
    }

    DEBUG_EVENT event{};
    if (WaitForDebugEventEx(&event, 25)) {
      handle_event(event);
    } else if (GetLastError() != ERROR_SEM_TIMEOUT) {
      publish({.type = "debugger_error",
               .process_id = pid_,
               .exception_code = GetLastError()});
      stop_ = true;
    }
  }
  process_commands();
  active_.store(false, std::memory_order_release);
  event_ready_.notify_all();
}

void DebugSession::process_commands() {
  std::deque<std::move_only_function<void()>> pending;
  {
    std::lock_guard lock(command_mutex_);
    pending.swap(commands_);
  }
  for (auto& command : pending) {
    command();
  }
}

void DebugSession::handle_event(const DEBUG_EVENT& event) {
  if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
    if (event.u.CreateProcessInfo.hFile != nullptr) {
      CloseHandle(event.u.CreateProcessInfo.hFile);
    }
    ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
    return;
  }
  if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
    if (event.u.LoadDll.hFile != nullptr) {
      CloseHandle(event.u.LoadDll.hFile);
    }
    ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
    return;
  }
  if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
    publish({.type = "process_exit",
             .process_id = event.dwProcessId,
             .thread_id = event.dwThreadId,
             .exception_code = event.u.ExitProcess.dwExitCode});
    ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
    stop_ = true;
    return;
  }
  if (event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT) {
    ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
    return;
  }

  const auto& record = event.u.Exception.ExceptionRecord;
  const auto code = record.ExceptionCode;
  const auto address = reinterpret_cast<std::uint64_t>(record.ExceptionAddress);
  if (code == EXCEPTION_BREAKPOINT) {
    const auto found = breakpoint_by_address_.find(address);
    if (found != breakpoint_by_address_.end()) {
      auto& breakpoint = breakpoints_.at(found->second);
      const auto restored = write_byte(address, breakpoint.original_byte);
      const auto rewound = restored ? rewind_instruction_pointer(event.dwThreadId)
                                     : Result<void>{std::unexpected(restored.error())};
      if (!rewound) {
        publish({.type = "debugger_error", .process_id = pid_,
                 .thread_id = event.dwThreadId,
                 .exception_code = rewound.error().native_code,
                 .address = address});
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
        return;
      }
      breakpoint.enabled = false;
      reinsert_breakpoint_ = breakpoint.id;
      pending_event_ = event;
      paused_ = true;
      publish({.type = "breakpoint", .process_id = event.dwProcessId,
               .thread_id = event.dwThreadId, .exception_code = code,
               .address = address, .first_chance = event.u.Exception.dwFirstChance != 0,
               .breakpoint_id = breakpoint.id});
      return;
    }
    if (!initial_breakpoint_seen_) {
      initial_breakpoint_seen_ = true;
      ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
      return;
    }
  }

  if (code == EXCEPTION_SINGLE_STEP && reinsert_breakpoint_) {
    auto& breakpoint = breakpoints_.at(*reinsert_breakpoint_);
    const auto inserted = write_byte(breakpoint.address, std::byte{0xCC});
    if (inserted) {
      breakpoint.enabled = true;
    }
    reinsert_breakpoint_.reset();
    if (inserted && user_single_step_) {
      user_single_step_ = false;
      pending_event_ = event;
      paused_ = true;
      publish({.type = "single_step", .process_id = event.dwProcessId,
               .thread_id = event.dwThreadId, .exception_code = code,
               .address = address, .first_chance = true});
      return;
    }
    ContinueDebugEvent(event.dwProcessId, event.dwThreadId,
                       inserted ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED);
    return;
  }

  if (code == EXCEPTION_SINGLE_STEP) {
    const auto hardware_id = hardware_breakpoint_hit(event.dwThreadId);
    if (hardware_id) {
      pending_event_ = event;
      paused_ = true;
      publish({.type = "hardware_breakpoint", .process_id = event.dwProcessId,
               .thread_id = event.dwThreadId, .exception_code = code,
               .address = address, .first_chance = true,
               .breakpoint_id = *hardware_id});
      return;
    }
  }

  if (code == EXCEPTION_SINGLE_STEP && user_single_step_) {
    user_single_step_ = false;
    pending_event_ = event;
    paused_ = true;
    publish({.type = "single_step", .process_id = event.dwProcessId,
             .thread_id = event.dwThreadId, .exception_code = code,
             .address = address, .first_chance = true});
    return;
  }

  if (event.u.Exception.dwFirstChance != 0) {
    ContinueDebugEvent(event.dwProcessId, event.dwThreadId,
                       DBG_EXCEPTION_NOT_HANDLED);
    return;
  }

  pending_event_ = event;
  paused_ = true;
  publish({.type = code == EXCEPTION_SINGLE_STEP ? "single_step" : "exception",
           .process_id = event.dwProcessId,
           .thread_id = event.dwThreadId,
           .exception_code = code,
           .address = address,
           .first_chance = event.u.Exception.dwFirstChance != 0});
}

void DebugSession::publish(Event event) {
  std::lock_guard lock(event_mutex_);
  event.sequence = next_event_++;
  events_.push_back(std::move(event));
  event_ready_.notify_one();
}

Result<void> DebugSession::write_byte(std::uint64_t address, std::byte value) {
  DWORD old_protection = 0;
  auto* target = reinterpret_cast<void*>(address);
  if (!VirtualProtectEx(process_.get(), target, 1, PAGE_EXECUTE_READWRITE,
                        &old_protection)) {
    return std::unexpected(system_error("VirtualProtectEx failed"));
  }
  SIZE_T written = 0;
  const auto ok = WriteProcessMemory(process_.get(), target, &value, 1, &written);
  DWORD ignored = 0;
  VirtualProtectEx(process_.get(), target, 1, old_protection, &ignored);
  if (!ok || written != 1) {
    return std::unexpected(system_error("WriteProcessMemory failed"));
  }
  if (!FlushInstructionCache(process_.get(), target, 1)) {
    return std::unexpected(system_error("FlushInstructionCache failed"));
  }
  return {};
}

Result<Breakpoint> DebugSession::add_breakpoint(std::uint64_t address) {
  return invoke<Breakpoint>([this, address]() -> Result<Breakpoint> {
    if (breakpoint_by_address_.contains(address)) {
      return std::unexpected(Error{ERROR_ALREADY_EXISTS, "Breakpoint already exists at address"});
    }
    std::byte original{};
    SIZE_T read = 0;
    if (!ReadProcessMemory(process_.get(), reinterpret_cast<void*>(address),
                           &original, 1, &read) || read != 1) {
      return std::unexpected(system_error("Could not read breakpoint address"));
    }
    auto inserted = write_byte(address, std::byte{0xCC});
    if (!inserted) {
      return std::unexpected(std::move(inserted.error()));
    }
    Breakpoint breakpoint{.id = next_breakpoint_++, .address = address,
                          .original_byte = original, .enabled = true};
    breakpoint_by_address_.emplace(address, breakpoint.id);
    breakpoints_.emplace(breakpoint.id, breakpoint);
    return breakpoint;
  });
}

Result<bool> DebugSession::remove_breakpoint(std::uint64_t breakpoint_id) {
  return invoke<bool>([this, breakpoint_id]() -> Result<bool> {
    const auto entry = breakpoints_.find(breakpoint_id);
    if (entry == breakpoints_.end()) {
      return false;
    }
    if (entry->second.enabled) {
      auto restored = write_byte(entry->second.address, entry->second.original_byte);
      if (!restored) {
        return std::unexpected(std::move(restored.error()));
      }
    }
    breakpoint_by_address_.erase(entry->second.address);
    if (reinsert_breakpoint_ == breakpoint_id) {
      reinsert_breakpoint_.reset();
    }
    breakpoints_.erase(entry);
    return true;
  });
}

Result<void> DebugSession::resume(bool handled) {
  return invoke<void>([this, handled] { return continue_pending(handled); });
}

Result<void> DebugSession::single_step() {
  return invoke<void>([this]() -> Result<void> {
    if (!paused_ || !pending_event_) {
      return std::unexpected(Error{ERROR_INVALID_STATE,
                                   "Single-step requires a paused debug event"});
    }
    auto prepared = prepare_breakpoint_resume(pending_event_->dwThreadId);
    if (!prepared) {
      return prepared;
    }
    user_single_step_ = true;
    return continue_pending(true);
  });
}

Result<void> DebugSession::continue_pending(bool handled) {
  if (!paused_ || !pending_event_) {
    return std::unexpected(Error{ERROR_INVALID_STATE, "No paused debug event to continue"});
  }
  if (reinsert_breakpoint_) {
    auto prepared = prepare_breakpoint_resume(pending_event_->dwThreadId);
    if (!prepared) {
      return prepared;
    }
  }
  const auto event = *pending_event_;
  if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId,
                          handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED)) {
    return std::unexpected(system_error("ContinueDebugEvent failed"));
  }
  pending_event_.reset();
  paused_ = false;
  return {};
}

Result<std::optional<Event>> DebugSession::wait_event(
    std::chrono::milliseconds timeout) {
  std::unique_lock lock(event_mutex_);
  event_ready_.wait_for(lock, timeout, [this] {
    return !events_.empty() || !active_.load(std::memory_order_acquire);
  });
  if (events_.empty()) {
    return std::optional<Event>{};
  }
  auto event = std::move(events_.front());
  events_.pop_front();
  return std::optional<Event>{std::move(event)};
}

Result<void> DebugSession::restore_breakpoints() {
  for (auto& [id, breakpoint] : breakpoints_) {
    static_cast<void>(id);
    if (breakpoint.enabled) {
      auto restored = write_byte(breakpoint.address, breakpoint.original_byte);
      if (!restored) {
        return restored;
      }
      breakpoint.enabled = false;
    }
  }
  return {};
}

Result<void> DebugSession::restore_hardware_breakpoints() {
  for (const auto& [id, breakpoint] : hardware_breakpoints_) {
    static_cast<void>(id);
    auto cleared = configure_hardware_breakpoint(breakpoint, false);
    if (!cleared) return cleared;
  }
  hardware_breakpoints_.clear();
  return {};
}

Result<void> DebugSession::detach() {
  if (!active_.load(std::memory_order_acquire)) {
    return {};
  }
  return invoke<void>([this]() -> Result<void> {
    auto restored = restore_breakpoints();
    if (!restored) {
      return restored;
    }
    auto hardware_restored = restore_hardware_breakpoints();
    if (!hardware_restored) return hardware_restored;
    for (const auto& [thread_id, count] : owned_suspensions_) {
      process::UniqueHandle thread{OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_id)};
      if (!thread) continue;
      for (std::uint32_t index = 0; index < count; ++index)
        if (ResumeThread(thread.get()) == static_cast<DWORD>(-1)) break;
    }
    owned_suspensions_.clear();
    if (pending_event_) {
      if (!ContinueDebugEvent(pending_event_->dwProcessId,
                              pending_event_->dwThreadId, DBG_CONTINUE)) {
        return std::unexpected(system_error("ContinueDebugEvent during detach failed"));
      }
      pending_event_.reset();
      paused_ = false;
    }
    if (!DebugActiveProcessStop(pid_)) {
      return std::unexpected(system_error("DebugActiveProcessStop failed"));
    }
    stop_ = true;
    active_.store(false, std::memory_order_release);
    return {};
  });
}

std::string_view to_string(HardwareBreakpointAccess access) noexcept {
  switch (access) {
    case HardwareBreakpointAccess::execute: return "execute";
    case HardwareBreakpointAccess::write: return "write";
    case HardwareBreakpointAccess::read_write: return "read_write";
  }
  return "unknown";
}

Result<std::shared_ptr<DebugSession>> DebugEngine::attach(std::uint32_t pid) {
  const auto id = next_session_.fetch_add(1, std::memory_order_relaxed);
  auto session = DebugSession::attach(id, pid);
  if (!session) {
    return std::unexpected(std::move(session.error()));
  }
  std::unique_lock lock(mutex_);
  sessions_.emplace(id, *session);
  return *session;
}

std::shared_ptr<DebugSession> DebugEngine::session(std::uint64_t id) const {
  std::shared_lock lock(mutex_);
  const auto entry = sessions_.find(id);
  return entry == sessions_.end() ? nullptr : entry->second;
}

Result<bool> DebugEngine::detach(std::uint64_t id) {
  std::shared_ptr<DebugSession> session;
  {
    std::shared_lock lock(mutex_);
    const auto entry = sessions_.find(id);
    if (entry == sessions_.end()) {
      return false;
    }
    session = entry->second;
  }
  auto detached = session->detach();
  if (!detached) {
    return std::unexpected(std::move(detached.error()));
  }
  std::unique_lock lock(mutex_);
  sessions_.erase(id);
  return true;
}

}  // namespace reverseplugin::debug
