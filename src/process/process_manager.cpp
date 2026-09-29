#include "reverseplugin/process/process_manager.hpp"

#include <TlHelp32.h>

#include <algorithm>
#include <limits>
#include <mutex>
#include <utility>

namespace reverseplugin::process {
namespace {

Error win32_error(std::string message, DWORD code = GetLastError()) {
  return {.native_code = code, .message = std::move(message)};
}

std::string narrow(const wchar_t* value) {
  if (value == nullptr || *value == L'\0') {
    return {};
  }
  const auto length = static_cast<int>(wcslen(value));
  const auto bytes = WideCharToMultiByte(CP_UTF8, 0, value, length, nullptr, 0,
                                         nullptr, nullptr);
  if (bytes <= 0) {
    return {};
  }
  std::string result(static_cast<std::size_t>(bytes), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value, length, result.data(), bytes, nullptr,
                      nullptr);
  return result;
}

Architecture architecture_of(HANDLE process) {
  USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
  USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
  if (!IsWow64Process2(process, &process_machine, &native_machine)) {
    return Architecture::unknown;
  }
  const auto machine = process_machine == IMAGE_FILE_MACHINE_UNKNOWN
                           ? native_machine
                           : process_machine;
  switch (machine) {
    case IMAGE_FILE_MACHINE_I386:
      return Architecture::x86;
    case IMAGE_FILE_MACHINE_AMD64:
      return Architecture::x64;
    case IMAGE_FILE_MACHINE_ARM64:
      return Architecture::arm64;
    default:
      return Architecture::unknown;
  }
}

std::string image_path(HANDLE process) {
  std::wstring buffer(32768, L'\0');
  DWORD length = static_cast<DWORD>(buffer.size());
  if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &length)) {
    return {};
  }
  buffer.resize(length);
  return narrow(buffer.c_str());
}

DWORD base_protection(DWORD protection) noexcept {
  return protection & 0xFFU;
}

bool is_readable(DWORD protection) noexcept {
  if ((protection & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
    return false;
  }
  switch (base_protection(protection)) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
      return true;
    default:
      return false;
  }
}

bool is_writable(DWORD protection) noexcept {
  switch (base_protection(protection)) {
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
      return true;
    default:
      return false;
  }
}

bool is_executable(DWORD protection) noexcept {
  switch (base_protection(protection)) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
      return true;
    default:
      return false;
  }
}

}  // namespace

UniqueHandle::~UniqueHandle() {
  if (*this) {
    CloseHandle(handle_);
  }
}

UniqueHandle::UniqueHandle(UniqueHandle&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)) {}

UniqueHandle& UniqueHandle::operator=(UniqueHandle&& other) noexcept {
  if (this != &other) {
    if (*this) {
      CloseHandle(handle_);
    }
    handle_ = std::exchange(other.handle_, nullptr);
  }
  return *this;
}

UniqueHandle::operator bool() const noexcept {
  return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
}

ProcessSession::ProcessSession(std::uint64_t id, std::uint32_t pid,
                               UniqueHandle handle, Architecture architecture,
                               std::string image_path)
    : id_(id),
      pid_(pid),
      handle_(std::move(handle)),
      architecture_(architecture),
      image_path_(std::move(image_path)) {}

Result<std::vector<ProcessInfo>> ProcessManager::list_processes() const {
  UniqueHandle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
  if (!snapshot) {
    return std::unexpected(win32_error("CreateToolhelp32Snapshot failed"));
  }

  PROCESSENTRY32W entry{.dwSize = sizeof(entry)};
  if (!Process32FirstW(snapshot.get(), &entry)) {
    return std::unexpected(win32_error("Process32FirstW failed"));
  }

  std::vector<ProcessInfo> result;
  do {
    result.push_back({.pid = entry.th32ProcessID,
                      .parent_pid = entry.th32ParentProcessID,
                      .thread_count = entry.cntThreads,
                      .name = narrow(entry.szExeFile)});
  } while (Process32NextW(snapshot.get(), &entry));
  return result;
}

Result<std::shared_ptr<const ProcessSession>> ProcessManager::attach(
    std::uint32_t pid) {
  UniqueHandle handle{OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                  FALSE, pid)};
  if (!handle) {
    return std::unexpected(win32_error("OpenProcess failed"));
  }

  const auto id = next_session_.fetch_add(1, std::memory_order_relaxed);
  const auto architecture = architecture_of(handle.get());
  auto path = image_path(handle.get());
  auto value = std::make_shared<ProcessSession>(
      id, pid, std::move(handle), architecture, std::move(path));
  {
    std::unique_lock lock(mutex_);
    sessions_.emplace(id, value);
  }
  return value;
}

bool ProcessManager::detach(std::uint64_t session_id) {
  std::unique_lock lock(mutex_);
  return sessions_.erase(session_id) != 0;
}

std::shared_ptr<const ProcessSession> ProcessManager::session(
    std::uint64_t session_id) const {
  std::shared_lock lock(mutex_);
  const auto entry = sessions_.find(session_id);
  return entry == sessions_.end() ? nullptr : entry->second;
}

Result<std::vector<ModuleInfo>> ProcessManager::list_modules(
    const ProcessSession& session) const {
  UniqueHandle snapshot{CreateToolhelp32Snapshot(
      TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, session.pid())};
  if (!snapshot) {
    return std::unexpected(win32_error("Module snapshot failed"));
  }

  MODULEENTRY32W entry{.dwSize = sizeof(entry)};
  if (!Module32FirstW(snapshot.get(), &entry)) {
    return std::unexpected(win32_error("Module32FirstW failed"));
  }

  std::vector<ModuleInfo> result;
  do {
    result.push_back({.name = narrow(entry.szModule),
                      .path = narrow(entry.szExePath),
                      .base = reinterpret_cast<std::uint64_t>(entry.modBaseAddr),
                      .size = entry.modBaseSize});
  } while (Module32NextW(snapshot.get(), &entry));
  return result;
}

Result<std::vector<MemoryRegion>> ProcessManager::query_regions(
    const ProcessSession& session, std::uint64_t start,
    std::size_t max_regions) const {
  std::vector<MemoryRegion> result;
  result.reserve(max_regions);
  auto address = start;

  while (result.size() < max_regions) {
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQueryEx(session.handle(), reinterpret_cast<LPCVOID>(address),
                       &info, sizeof(info)) == 0) {
      const auto code = GetLastError();
      if (code == ERROR_INVALID_PARAMETER) {
        break;
      }
      return std::unexpected(win32_error("VirtualQueryEx failed", code));
    }

    const auto base = reinterpret_cast<std::uint64_t>(info.BaseAddress);
    result.push_back({.base = base,
                      .size = info.RegionSize,
                      .state = info.State,
                      .protection = info.Protect,
                      .type = info.Type,
                      .readable = info.State == MEM_COMMIT && is_readable(info.Protect),
                      .writable = info.State == MEM_COMMIT && is_writable(info.Protect),
                      .executable = info.State == MEM_COMMIT && is_executable(info.Protect)});

    if (info.RegionSize > std::numeric_limits<std::uint64_t>::max() - base) {
      break;
    }
    const auto next = base + info.RegionSize;
    if (next <= address) {
      break;
    }
    address = next;
  }
  return result;
}

Result<std::vector<std::byte>> ProcessManager::read(
    const ProcessSession& session, std::uint64_t address,
    std::size_t size) const {
  std::vector<std::byte> result(size);
  std::size_t offset = 0;

  while (offset < size) {
    const auto current = address + offset;
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQueryEx(session.handle(), reinterpret_cast<LPCVOID>(current),
                       &info, sizeof(info)) == 0) {
      return std::unexpected(win32_error("VirtualQueryEx failed"));
    }
    if (info.State != MEM_COMMIT || !is_readable(info.Protect)) {
      return std::unexpected(Error{
          .native_code = ERROR_NOACCESS,
          .message = "Requested range contains unreadable memory"});
    }

    const auto region_end = reinterpret_cast<std::uint64_t>(info.BaseAddress) +
                            info.RegionSize;
    const auto chunk = static_cast<std::size_t>(std::min<std::uint64_t>(
        size - offset, region_end - current));
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(session.handle(), reinterpret_cast<LPCVOID>(current),
                           result.data() + offset, chunk, &bytes_read) ||
        bytes_read != chunk) {
      return std::unexpected(win32_error("ReadProcessMemory failed"));
    }
    offset += chunk;
  }
  return result;
}

Result<std::size_t> ProcessManager::write(
    const ProcessSession& session, std::uint64_t address,
    std::span<const std::byte> bytes) const {
  if (bytes.empty()) return std::size_t{0};
  if (address > std::numeric_limits<std::uint64_t>::max() - bytes.size()) {
    return std::unexpected(Error{ERROR_ARITHMETIC_OVERFLOW,
                                 "Write range overflows virtual address space"});
  }
  UniqueHandle process{OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE |
                                       PROCESS_VM_OPERATION,
                                   FALSE, session.pid())};
  if (!process) return std::unexpected(win32_error("OpenProcess for writing failed"));

  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto current = address + offset;
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQueryEx(process.get(), reinterpret_cast<LPCVOID>(current), &info,
                       sizeof(info)) == 0)
      return std::unexpected(win32_error("VirtualQueryEx before write failed"));
    if (info.State != MEM_COMMIT || !is_writable(info.Protect) ||
        (info.Protect & PAGE_GUARD) != 0) {
      return std::unexpected(Error{ERROR_NOACCESS,
                                   "Requested range contains non-writable memory"});
    }
    const auto region_end = reinterpret_cast<std::uint64_t>(info.BaseAddress) +
                            info.RegionSize;
    const auto chunk = static_cast<std::size_t>((std::min)(
        static_cast<std::uint64_t>(bytes.size() - offset), region_end - current));
    SIZE_T written = 0;
    if (!WriteProcessMemory(process.get(), reinterpret_cast<void*>(current),
                            bytes.data() + offset, chunk, &written) ||
        written != chunk)
      return std::unexpected(win32_error("WriteProcessMemory failed"));
    offset += chunk;
  }
  if (!FlushInstructionCache(process.get(), reinterpret_cast<void*>(address),
                             bytes.size()))
    return std::unexpected(win32_error("FlushInstructionCache failed"));
  return offset;
}

std::string_view to_string(Architecture architecture) noexcept {
  switch (architecture) {
    case Architecture::x86:
      return "x86";
    case Architecture::x64:
      return "x64";
    case Architecture::arm64:
      return "arm64";
    case Architecture::unknown:
      return "unknown";
  }
  return "unknown";
}

}  // namespace reverseplugin::process
