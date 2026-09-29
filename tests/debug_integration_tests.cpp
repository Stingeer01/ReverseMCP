#include <Windows.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <string>

#include "reverseplugin/debug/debug_engine.hpp"

namespace {

void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

struct Child final {
  HANDLE process{};
  HANDLE thread{};
  HANDLE output{};
  ~Child() {
    if (process) {
      TerminateProcess(process, 0);
      WaitForSingleObject(process, 5000);
      CloseHandle(process);
    }
    if (thread) CloseHandle(thread);
    if (output) CloseHandle(output);
  }
};

Child launch_target(std::string& first_line) {
  std::array<wchar_t, 32768> self{};
  require(GetModuleFileNameW(nullptr, self.data(), static_cast<DWORD>(self.size())) != 0,
          "GetModuleFileNameW failed");
  const auto target = std::filesystem::path{self.data()}.parent_path() /
                      L"reverseplugin-debug-target.exe";
  SECURITY_ATTRIBUTES security{.nLength = sizeof(security), .bInheritHandle = TRUE};
  HANDLE read_pipe = nullptr;
  HANDLE write_pipe = nullptr;
  require(CreatePipe(&read_pipe, &write_pipe, &security, 0) != 0, "CreatePipe failed");
  SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);
  STARTUPINFOW startup{.cb = sizeof(startup), .dwFlags = STARTF_USESTDHANDLES,
                       .hStdOutput = write_pipe, .hStdError = write_pipe};
  PROCESS_INFORMATION info{};
  auto command = std::wstring{L"\""} + target.wstring() + L"\"";
  const auto created = CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE,
                                      CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info);
  CloseHandle(write_pipe);
  if (!created) {
    CloseHandle(read_pipe);
    throw std::runtime_error("CreateProcessW failed");
  }
  std::array<char, 256> buffer{};
  DWORD read = 0;
  require(ReadFile(read_pipe, buffer.data(), static_cast<DWORD>(buffer.size() - 1),
                   &read, nullptr) != 0,
          "Could not read debug target metadata");
  first_line.assign(buffer.data(), read);
  return Child{.process = info.hProcess, .thread = info.hThread, .output = read_pipe};
}

}  // namespace

int main() {
  std::string metadata;
  auto child = launch_target(metadata);
  std::uint32_t pid = 0;
  std::uint32_t thread_id = 0;
  std::uint64_t address = 0;
  std::istringstream stream{metadata};
  stream >> pid >> thread_id >> address;
  require(pid != 0 && thread_id != 0 && address != 0, "Invalid debug target metadata");

  reverseplugin::debug::DebugEngine engine;
  auto session_result = engine.attach(pid);
  require(session_result.has_value(), "Debug attach failed");
  auto session = *session_result;

  auto hardware = session->add_hardware_breakpoint(
      thread_id, address, reverseplugin::debug::HardwareBreakpointAccess::execute,
      1, std::nullopt);
  require(hardware.has_value(), "Could not set hardware breakpoint");
  auto event = session->wait_event(std::chrono::seconds{5});
  require(event && *event && (**event).type == "hardware_breakpoint",
          "Hardware breakpoint did not trigger");
  require((**event).breakpoint_id == hardware->id, "Wrong hardware breakpoint id");
  auto removed_hardware = session->remove_hardware_breakpoint(hardware->id);
  require(removed_hardware && *removed_hardware, "Could not clear hardware breakpoint");
  require(session->resume(true).has_value(), "Could not resume hardware event");

  auto software = session->add_breakpoint(address);
  require(software.has_value(), "Could not set software breakpoint");
  event = session->wait_event(std::chrono::seconds{5});
  require(event && *event && (**event).type == "breakpoint",
          "Software breakpoint did not trigger");
  auto frames = session->stack_trace(thread_id, 32);
  require(frames && !frames->empty(), "Could not unwind paused target stack");
  require(frames->front().address != 0, "Stack trace returned a null instruction address");
  auto context = session->registers(thread_id);
  require(context && context->registers.contains("rip"), "Could not read paused registers");
  require(session->single_step().has_value(), "Single-step command failed");
  event = session->wait_event(std::chrono::seconds{5});
  require(event && *event && (**event).type == "single_step", "Single-step did not trigger");
  auto removed_software = session->remove_breakpoint(software->id);
  require(removed_software && *removed_software, "Could not clear software breakpoint");
  require(session->resume(true).has_value(), "Could not resume single-step event");
  auto detached = engine.detach(session->id());
  require(detached && *detached, "Debug detach failed");
}
