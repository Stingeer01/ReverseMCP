#pragma once

#include <memory>

#include "reverseplugin/disasm/disassembler.hpp"
#include "reverseplugin/debug/debug_engine.hpp"
#include "reverseplugin/mcp/tool_registry.hpp"
#include "reverseplugin/process/process_manager.hpp"

namespace reverseplugin {

void register_builtin_tools(
    mcp::ToolRegistry& registry,
    std::shared_ptr<process::ProcessManager> processes,
    std::shared_ptr<disasm::Disassembler> disassembler,
    std::shared_ptr<debug::DebugEngine> debugger);

}  // namespace reverseplugin
