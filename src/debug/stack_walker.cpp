#include "reverseplugin/debug/debug_engine.hpp"

#include <DbgHelp.h>

#include <array>
#include <mutex>

namespace reverseplugin::debug {
namespace {

std::mutex dbghelp_mutex;

Error stack_error(std::string message, DWORD code = GetLastError()) {
  return {.native_code = code, .message = std::move(message)};
}

process::UniqueHandle open_stack_thread(std::uint32_t thread_id) {
  return process::UniqueHandle{OpenThread(
      THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, thread_id)};
}

StackFrame resolve_frame(HANDLE process, const STACKFRAME64& frame) {
  StackFrame result{.address = frame.AddrPC.Offset,
                    .stack_pointer = frame.AddrStack.Offset,
                    .frame_pointer = frame.AddrFrame.Offset};
  IMAGEHLP_MODULE64 module{.SizeOfStruct = sizeof(module)};
  if (SymGetModuleInfo64(process, frame.AddrPC.Offset, &module)) {
    result.module_base = module.BaseOfImage;
    result.module = module.ModuleName;
  }
  alignas(SYMBOL_INFO) std::array<std::byte, sizeof(SYMBOL_INFO) + MAX_SYM_NAME> storage{};
  auto* symbol = reinterpret_cast<SYMBOL_INFO*>(storage.data());
  symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
  symbol->MaxNameLen = MAX_SYM_NAME;
  DWORD64 displacement = 0;
  if (SymFromAddr(process, frame.AddrPC.Offset, &displacement, symbol)) {
    result.symbol.assign(symbol->Name, symbol->NameLen);
    result.displacement = displacement;
  }
  return result;
}

template <typename Context>
Result<std::vector<StackFrame>> walk(HANDLE process, HANDLE thread,
                                     DWORD machine, Context& context,
                                     STACKFRAME64 frame,
                                     std::size_t max_frames) {
  std::vector<StackFrame> result;
  result.reserve(max_frames);
  std::uint64_t previous_pc = 0;
  std::uint64_t previous_sp = 0;
  while (result.size() < max_frames && frame.AddrPC.Offset != 0) {
    if (frame.AddrPC.Offset == previous_pc && frame.AddrStack.Offset == previous_sp)
      break;
    previous_pc = frame.AddrPC.Offset;
    previous_sp = frame.AddrStack.Offset;
    result.push_back(resolve_frame(process, frame));
    if (!StackWalk64(machine, process, thread, &frame, &context, nullptr,
                     SymFunctionTableAccess64, SymGetModuleBase64, nullptr))
      break;
  }
  return result;
}

}  // namespace

Result<std::vector<StackFrame>> DebugSession::stack_trace(
    std::uint32_t thread_id, std::size_t max_frames) {
  return invoke<std::vector<StackFrame>>(
      [this, thread_id, max_frames] { return walk_stack(thread_id, max_frames); });
}

Result<std::uint32_t> DebugSession::paused_thread_id() {
  return invoke<std::uint32_t>([this]() -> Result<std::uint32_t> {
    if (!paused_ || !pending_event_)
      return std::unexpected(Error{ERROR_INVALID_STATE,
                                   "No paused debug event is available"});
    return pending_event_->dwThreadId;
  });
}

Result<std::vector<StackFrame>> DebugSession::walk_stack(
    std::uint32_t thread_id, std::size_t max_frames) const {
  if (!paused_ || !pending_event_)
    return std::unexpected(Error{ERROR_INVALID_STATE,
                                 "Stack traces are stable only while paused"});
  if (max_frames == 0 || max_frames > 256)
    return std::unexpected(Error{ERROR_INVALID_PARAMETER,
                                 "max_frames must be between 1 and 256"});
  if (thread_id == 0) thread_id = pending_event_->dwThreadId;
  auto thread = open_stack_thread(thread_id);
  if (!thread) return std::unexpected(stack_error("OpenThread failed"));

  std::lock_guard lock(dbghelp_mutex);
  SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME |
                SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_LOAD_LINES);
  if (!SymInitialize(process_.get(), nullptr, TRUE))
    return std::unexpected(stack_error("SymInitialize failed"));
  struct Cleanup final {
    HANDLE process;
    ~Cleanup() { SymCleanup(process); }
  } cleanup{process_.get()};

  if (architecture_ == process::Architecture::x86) {
    WOW64_CONTEXT context{.ContextFlags = WOW64_CONTEXT_FULL};
    if (!Wow64GetThreadContext(thread.get(), &context))
      return std::unexpected(stack_error("Wow64GetThreadContext failed"));
    STACKFRAME64 frame{};
    frame.AddrPC = {.Offset = context.Eip, .Mode = AddrModeFlat};
    frame.AddrStack = {.Offset = context.Esp, .Mode = AddrModeFlat};
    frame.AddrFrame = {.Offset = context.Ebp, .Mode = AddrModeFlat};
    return walk(process_.get(), thread.get(), IMAGE_FILE_MACHINE_I386,
                context, frame, max_frames);
  }

  CONTEXT context{.ContextFlags = CONTEXT_FULL};
  if (!GetThreadContext(thread.get(), &context))
    return std::unexpected(stack_error("GetThreadContext failed"));
  STACKFRAME64 frame{};
  frame.AddrPC = {.Offset = context.Rip, .Mode = AddrModeFlat};
  frame.AddrStack = {.Offset = context.Rsp, .Mode = AddrModeFlat};
  frame.AddrFrame = {.Offset = context.Rbp, .Mode = AddrModeFlat};
  return walk(process_.get(), thread.get(), IMAGE_FILE_MACHINE_AMD64,
              context, frame, max_frames);
}

}  // namespace reverseplugin::debug
