#include "reverseplugin/debug/debug_engine.hpp"

#include <TlHelp32.h>

#include <ranges>

namespace reverseplugin::debug {
namespace {

Error context_error(std::string message) {
  return {.native_code = GetLastError(), .message = std::move(message)};
}

process::UniqueHandle open_context_thread(std::uint32_t thread_id, bool write) {
  auto access = THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION;
  if (write) {
    access |= THREAD_SET_CONTEXT;
  }
  return process::UniqueHandle{OpenThread(access, FALSE, thread_id)};
}

std::uint64_t access_bits(HardwareBreakpointAccess access) noexcept {
  switch (access) {
    case HardwareBreakpointAccess::execute: return 0;
    case HardwareBreakpointAccess::write: return 1;
    case HardwareBreakpointAccess::read_write: return 3;
  }
  return 0;
}

std::uint64_t length_bits(std::uint8_t size) noexcept {
  switch (size) {
    case 1: return 0;
    case 2: return 1;
    case 4: return 3;
    case 8: return 2;
    default: return 0;
  }
}

}  // namespace

Result<void> DebugSession::prepare_breakpoint_resume(std::uint32_t thread_id) const {
  auto thread = open_context_thread(thread_id, true);
  if (!thread) return std::unexpected(context_error("OpenThread failed"));
  if (architecture_ == process::Architecture::x86) {
    WOW64_CONTEXT context{.ContextFlags = WOW64_CONTEXT_CONTROL};
    if (!Wow64GetThreadContext(thread.get(), &context))
      return std::unexpected(context_error("Wow64GetThreadContext failed"));
    context.EFlags |= 0x100U;
    if (!Wow64SetThreadContext(thread.get(), &context))
      return std::unexpected(context_error("Wow64SetThreadContext failed"));
    return {};
  }
  CONTEXT context{.ContextFlags = CONTEXT_CONTROL};
  if (!GetThreadContext(thread.get(), &context))
    return std::unexpected(context_error("GetThreadContext failed"));
  context.EFlags |= 0x100U;
  if (!SetThreadContext(thread.get(), &context))
    return std::unexpected(context_error("SetThreadContext failed"));
  return {};
}

Result<void> DebugSession::rewind_instruction_pointer(std::uint32_t thread_id) const {
  auto thread = open_context_thread(thread_id, true);
  if (!thread) return std::unexpected(context_error("OpenThread failed"));
  if (architecture_ == process::Architecture::x86) {
    WOW64_CONTEXT context{.ContextFlags = WOW64_CONTEXT_CONTROL};
    if (!Wow64GetThreadContext(thread.get(), &context))
      return std::unexpected(context_error("Wow64GetThreadContext failed"));
    --context.Eip;
    if (!Wow64SetThreadContext(thread.get(), &context))
      return std::unexpected(context_error("Wow64SetThreadContext failed"));
    return {};
  }
  CONTEXT context{.ContextFlags = CONTEXT_CONTROL};
  if (!GetThreadContext(thread.get(), &context))
    return std::unexpected(context_error("GetThreadContext failed"));
  --context.Rip;
  if (!SetThreadContext(thread.get(), &context))
    return std::unexpected(context_error("SetThreadContext failed"));
  return {};
}

Result<RegisterContext> DebugSession::registers(std::uint32_t thread_id) {
  return invoke<RegisterContext>([this, thread_id] { return read_registers(thread_id); });
}

Result<RegisterContext> DebugSession::read_registers(std::uint32_t thread_id) const {
  if (!paused_ || !pending_event_)
    return std::unexpected(Error{ERROR_INVALID_STATE, "Registers are stable only while paused"});
  if (thread_id == 0) thread_id = pending_event_->dwThreadId;
  auto thread = open_context_thread(thread_id, false);
  if (!thread) return std::unexpected(context_error("OpenThread failed"));
  RegisterContext result;
  if (architecture_ == process::Architecture::x86) {
    WOW64_CONTEXT c{.ContextFlags = WOW64_CONTEXT_ALL};
    if (!Wow64GetThreadContext(thread.get(), &c))
      return std::unexpected(context_error("Wow64GetThreadContext failed"));
    result.architecture = "x86";
    result.registers = {{"eip", c.Eip}, {"esp", c.Esp}, {"ebp", c.Ebp},
                        {"eax", c.Eax}, {"ebx", c.Ebx}, {"ecx", c.Ecx},
                        {"edx", c.Edx}, {"esi", c.Esi}, {"edi", c.Edi},
                        {"eflags", c.EFlags}};
    return result;
  }
  CONTEXT c{.ContextFlags = CONTEXT_ALL};
  if (!GetThreadContext(thread.get(), &c))
    return std::unexpected(context_error("GetThreadContext failed"));
  result.architecture = "x64";
  result.registers = {{"rip", c.Rip}, {"rsp", c.Rsp}, {"rbp", c.Rbp},
                      {"rax", c.Rax}, {"rbx", c.Rbx}, {"rcx", c.Rcx},
                      {"rdx", c.Rdx}, {"rsi", c.Rsi}, {"rdi", c.Rdi},
                      {"r8", c.R8}, {"r9", c.R9}, {"r10", c.R10},
                      {"r11", c.R11}, {"r12", c.R12}, {"r13", c.R13},
                      {"r14", c.R14}, {"r15", c.R15}, {"eflags", c.EFlags}};
  return result;
}

Result<std::vector<ThreadInfo>> DebugSession::threads() const {
  process::UniqueHandle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)};
  if (!snapshot) return std::unexpected(context_error("Thread snapshot failed"));
  THREADENTRY32 entry{.dwSize = sizeof(entry)};
  if (!Thread32First(snapshot.get(), &entry))
    return std::unexpected(context_error("Thread32First failed"));
  std::vector<ThreadInfo> result;
  do {
    if (entry.th32OwnerProcessID == pid_)
      result.push_back({.id = entry.th32ThreadID,
                        .base_priority = entry.tpBasePri});
  } while (Thread32Next(snapshot.get(), &entry));
  return result;
}

Result<void> DebugSession::configure_hardware_breakpoint(
    const HardwareBreakpoint& breakpoint, bool enabled) const {
  auto thread = process::UniqueHandle{OpenThread(
      THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME |
          THREAD_QUERY_INFORMATION,
      FALSE, breakpoint.thread_id)};
  if (!thread) return std::unexpected(context_error("OpenThread failed"));
  const bool suspend = !paused_;
  if (suspend && SuspendThread(thread.get()) == static_cast<DWORD>(-1))
    return std::unexpected(context_error("SuspendThread failed"));
  const auto resume = [&] {
    if (suspend) static_cast<void>(ResumeThread(thread.get()));
  };
  const auto slot = breakpoint.slot;
  const auto enable_mask = std::uint64_t{1} << (slot * 2U);
  const auto control_shift = 16U + slot * 4U;
  const auto control_mask = std::uint64_t{0xF} << control_shift;
  const auto control = (access_bits(breakpoint.access) |
                        (length_bits(breakpoint.size) << 2U)) << control_shift;
  if (architecture_ == process::Architecture::x86) {
    WOW64_CONTEXT context{.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS};
    if (!Wow64GetThreadContext(thread.get(), &context)) {
      resume();
      return std::unexpected(context_error("Wow64GetThreadContext failed"));
    }
    const auto value = enabled ? static_cast<DWORD>(breakpoint.address) : 0;
    switch (slot) {
      case 0: context.Dr0 = value; break;
      case 1: context.Dr1 = value; break;
      case 2: context.Dr2 = value; break;
      case 3: context.Dr3 = value; break;
      default: break;
    }
    auto dr7 = static_cast<std::uint64_t>(context.Dr7);
    dr7 &= ~(enable_mask | control_mask);
    if (enabled) dr7 |= enable_mask | control;
    context.Dr7 = static_cast<DWORD>(dr7);
    context.Dr6 = 0;
    if (!Wow64SetThreadContext(thread.get(), &context)) {
      resume();
      return std::unexpected(context_error("Wow64SetThreadContext failed"));
    }
  } else {
    CONTEXT context{.ContextFlags = CONTEXT_DEBUG_REGISTERS};
    if (!GetThreadContext(thread.get(), &context)) {
      resume();
      return std::unexpected(context_error("GetThreadContext failed"));
    }
    const auto value = enabled ? breakpoint.address : 0;
    switch (slot) {
      case 0: context.Dr0 = value; break;
      case 1: context.Dr1 = value; break;
      case 2: context.Dr2 = value; break;
      case 3: context.Dr3 = value; break;
      default: break;
    }
    context.Dr7 &= ~(enable_mask | control_mask);
    if (enabled) context.Dr7 |= enable_mask | control;
    context.Dr6 = 0;
    if (!SetThreadContext(thread.get(), &context)) {
      resume();
      return std::unexpected(context_error("SetThreadContext failed"));
    }
  }
  resume();
  return {};
}

Result<HardwareBreakpoint> DebugSession::add_hardware_breakpoint(
    std::uint32_t thread_id, std::uint64_t address,
    HardwareBreakpointAccess access, std::uint8_t size,
    std::optional<std::uint8_t> requested_slot) {
  return invoke<HardwareBreakpoint>([this, thread_id, address, access, size,
                                     requested_slot]() -> Result<HardwareBreakpoint> {
    if (thread_id == 0)
      return std::unexpected(Error{ERROR_INVALID_PARAMETER, "thread_id must not be zero"});
    if (access == HardwareBreakpointAccess::execute && size != 1)
      return std::unexpected(Error{ERROR_INVALID_PARAMETER, "Execute breakpoints require size 1"});
    if (size != 1 && size != 2 && size != 4 && size != 8)
      return std::unexpected(Error{ERROR_INVALID_PARAMETER, "Hardware breakpoint size must be 1, 2, 4, or 8"});
    if (architecture_ == process::Architecture::x86 && size == 8)
      return std::unexpected(Error{ERROR_NOT_SUPPORTED, "8-byte hardware breakpoints require x64"});
    if (access != HardwareBreakpointAccess::execute && address % size != 0)
      return std::unexpected(Error{ERROR_INVALID_PARAMETER, "Data breakpoint address must be aligned to its size"});
    std::optional<std::uint8_t> slot = requested_slot;
    if (slot && *slot > 3)
      return std::unexpected(Error{ERROR_INVALID_PARAMETER, "Hardware breakpoint slot must be 0..3"});
    const auto occupied = [this, thread_id](std::uint8_t candidate) {
      return std::ranges::any_of(hardware_breakpoints_, [=](const auto& entry) {
        return entry.second.thread_id == thread_id && entry.second.slot == candidate;
      });
    };
    if (!slot) {
      for (std::uint8_t candidate = 0; candidate < 4; ++candidate)
        if (!occupied(candidate)) { slot = candidate; break; }
    }
    if (!slot || occupied(*slot))
      return std::unexpected(Error{ERROR_NOT_ENOUGH_MEMORY, "No free hardware breakpoint slot on this thread"});
    HardwareBreakpoint breakpoint{.id = next_hardware_breakpoint_++,
      .thread_id = thread_id, .slot = *slot, .address = address,
      .access = access, .size = size};
    auto configured = configure_hardware_breakpoint(breakpoint, true);
    if (!configured) return std::unexpected(std::move(configured.error()));
    hardware_breakpoints_.emplace(breakpoint.id, breakpoint);
    return breakpoint;
  });
}

Result<bool> DebugSession::remove_hardware_breakpoint(std::uint64_t id) {
  return invoke<bool>([this, id]() -> Result<bool> {
    const auto found = hardware_breakpoints_.find(id);
    if (found == hardware_breakpoints_.end()) return false;
    auto cleared = configure_hardware_breakpoint(found->second, false);
    if (!cleared) return std::unexpected(std::move(cleared.error()));
    hardware_breakpoints_.erase(found);
    return true;
  });
}

std::optional<std::uint64_t> DebugSession::hardware_breakpoint_hit(
    std::uint32_t thread_id) const {
  auto thread = open_context_thread(thread_id, false);
  if (!thread) return std::nullopt;
  std::uint64_t dr6 = 0;
  if (architecture_ == process::Architecture::x86) {
    WOW64_CONTEXT context{.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS};
    if (!Wow64GetThreadContext(thread.get(), &context)) return std::nullopt;
    dr6 = context.Dr6;
  } else {
    CONTEXT context{.ContextFlags = CONTEXT_DEBUG_REGISTERS};
    if (!GetThreadContext(thread.get(), &context)) return std::nullopt;
    dr6 = context.Dr6;
  }
  for (const auto& [id, breakpoint] : hardware_breakpoints_)
    if (breakpoint.thread_id == thread_id && (dr6 & (std::uint64_t{1} << breakpoint.slot)) != 0)
      return id;
  return std::nullopt;
}

Result<std::uint32_t> DebugSession::suspend_thread(std::uint32_t thread_id) {
  return invoke<std::uint32_t>([this, thread_id]() -> Result<std::uint32_t> {
    process::UniqueHandle thread{OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_id)};
    if (!thread) return std::unexpected(context_error("OpenThread failed"));
    const auto previous = SuspendThread(thread.get());
    if (previous == static_cast<DWORD>(-1))
      return std::unexpected(context_error("SuspendThread failed"));
    ++owned_suspensions_[thread_id];
    return previous;
  });
}

Result<std::uint32_t> DebugSession::resume_thread(std::uint32_t thread_id) {
  return invoke<std::uint32_t>([this, thread_id]() -> Result<std::uint32_t> {
    const auto owned = owned_suspensions_.find(thread_id);
    if (owned == owned_suspensions_.end() || owned->second == 0)
      return std::unexpected(Error{ERROR_INVALID_STATE, "Thread was not suspended by this debugger session"});
    process::UniqueHandle thread{OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_id)};
    if (!thread) return std::unexpected(context_error("OpenThread failed"));
    const auto previous = ResumeThread(thread.get());
    if (previous == static_cast<DWORD>(-1))
      return std::unexpected(context_error("ResumeThread failed"));
    if (--owned->second == 0) owned_suspensions_.erase(owned);
    return previous;
  });
}

}  // namespace reverseplugin::debug
