#include <algorithm>
#include <iostream>
#include <thread>
#include <utility>

#include "reverseplugin/mcp/server.hpp"
#include "reverseplugin/tools.hpp"

int main() {
  reverseplugin::mcp::ToolRegistry registry;
  auto processes = std::make_shared<reverseplugin::process::ProcessManager>();
  auto disassembler = std::make_shared<reverseplugin::disasm::Disassembler>();
  auto debugger = std::make_shared<reverseplugin::debug::DebugEngine>();
  reverseplugin::register_builtin_tools(registry, std::move(processes),
                                        std::move(disassembler),
                                        std::move(debugger));

  const auto worker_count = std::clamp(std::thread::hardware_concurrency(), 1U, 8U);
  reverseplugin::mcp::Server server{std::move(registry), std::cin, std::cout,
                                    worker_count};
  return server.run();
}
