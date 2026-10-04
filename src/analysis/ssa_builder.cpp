#include "reverseplugin/analysis/ssa_builder.hpp"

#include <algorithm>
#include <format>
#include <ranges>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include "reverseplugin/analysis/decompiler.hpp"
#include "reverseplugin/analysis/register_model.hpp"

namespace reverseplugin::analysis {
namespace {

using State = std::unordered_map<std::string, std::string>;

struct Access final {
  RegisterSlice reg;
  std::string role;
};

bool trackable(std::string_view storage) {
  return storage != "rip" && storage != "eip";
}

RegisterSlice normalized(std::string_view value, bool x64) {
  if (auto reg = resolve_register(value, x64)) return std::move(*reg);
  return {.canonical = std::string{value}, .write = RegisterWrite::opaque};
}

void add_access(std::vector<Access>& values, RegisterSlice reg,
                std::string_view role) {
  if (!trackable(reg.canonical)) return;
  const auto duplicate = std::ranges::find_if(values, [&](const Access& current) {
    return current.reg.canonical == reg.canonical &&
           current.reg.offset_bits == reg.offset_bits &&
           current.reg.size_bits == reg.size_bits && current.role == role;
  });
  if (duplicate == values.end())
    values.push_back({std::move(reg), std::string{role}});
}

std::vector<Access> uses(const DecompilerStatement& statement, bool x64) {
  std::vector<Access> result;
  result.reserve(statement.uses.size() + 4);
  for (const auto& value : statement.uses)
    add_access(result, normalized(value, x64), "instruction");
  for (const auto& memory : statement.memory_accesses) {
    if (memory.action == "read" || memory.action == "read_write")
      add_access(result,
                 {.canonical = memory.alias_set,
                  .write = RegisterWrite::opaque},
                 "memory_read");
  }
  return result;
}

std::vector<Access> definitions(const DecompilerStatement& statement, bool x64) {
  std::vector<Access> result;
  result.reserve(statement.definitions.size() + 16);
  for (const auto& value : statement.definitions) {
    auto access = normalized(value, x64);
    if (statement.source.starts_with('v') && access.canonical.starts_with("zmm") &&
        (value.starts_with("xmm") || value.starts_with("ymm")))
      access.write = RegisterWrite::full;
    add_access(result, std::move(access), "instruction");
  }
  for (const auto& memory : statement.memory_accesses) {
    if (memory.action == "write" || memory.action == "read_write")
      add_access(result,
                 {.canonical = memory.alias_set,
                  .write = RegisterWrite::full},
                 "memory_write");
  }
  if (statement.operation == "call") {
    if (x64) {
      for (const auto reg : {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11",
                             "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5",
                             "rflags"})
        add_access(result, normalized(reg, true), "call_clobber");
    } else {
      for (const auto reg : {"eax", "ecx", "edx", "zmm0", "zmm1", "zmm2",
                             "zmm3", "zmm4", "zmm5", "eflags"})
        add_access(result, normalized(reg, false), "call_clobber");
    }
  }
  return result;
}

std::string entry_value(std::string_view storage) {
  return std::format("{}_entry", storage);
}

std::string definition_value(std::string_view storage, std::uint64_t address) {
  return std::format("{}_{:x}", storage, address);
}

std::string phi_value(std::string_view storage, std::uint32_t block) {
  return std::format("{}_phi_{:x}", storage, block);
}

struct Graph final {
  std::vector<std::vector<std::size_t>> predecessors;
  std::vector<std::vector<std::size_t>> successors;
  std::unordered_map<std::uint32_t, std::size_t> by_rva;
};

Graph make_graph(const std::vector<DecompilerBlock>& blocks,
                 const std::vector<ControlFlowEdge>& edges,
                 std::uint64_t image_base) {
  Graph graph{.predecessors = std::vector<std::vector<std::size_t>>(blocks.size()),
              .successors = std::vector<std::vector<std::size_t>>(blocks.size())};
  std::unordered_map<std::uint32_t, std::size_t> owner;
  for (std::size_t i = 0; i < blocks.size(); ++i) {
    graph.by_rva.emplace(blocks[i].rva, i);
    for (const auto& statement : blocks[i].statements) {
      const auto rva = statement.address - image_base;
      if (rva <= UINT32_MAX) owner.emplace(static_cast<std::uint32_t>(rva), i);
    }
  }
  for (const auto& edge : edges) {
    const auto from = owner.find(edge.from_rva);
    const auto to = graph.by_rva.find(edge.to_rva);
    if (from == owner.end() || to == graph.by_rva.end()) continue;
    auto& values = graph.predecessors[to->second];
    if (std::ranges::find(values, from->second) == values.end())
      values.push_back(from->second);
    auto& successors = graph.successors[from->second];
    if (std::ranges::find(successors, to->second) == successors.end())
      successors.push_back(to->second);
  }
  return graph;
}

std::unordered_set<std::string> storage_universe(
    const std::vector<DecompilerBlock>& blocks, bool x64) {
  std::unordered_set<std::string> result;
  for (const auto& block : blocks) {
    for (const auto& statement : block.statements) {
      for (const auto& access : uses(statement, x64)) result.insert(access.reg.canonical);
      for (const auto& access : definitions(statement, x64))
        result.insert(access.reg.canonical);
    }
  }
  return result;
}

State transfer(const DecompilerBlock& block, State state, bool x64) {
  for (const auto& statement : block.statements) {
    for (const auto& access : definitions(statement, x64))
      state[access.reg.canonical] =
          definition_value(access.reg.canonical, statement.address);
  }
  return state;
}

struct Liveness final {
  std::vector<std::unordered_set<std::string>> in;
  std::vector<std::unordered_set<std::string>> out;
};

Liveness liveness(const std::vector<DecompilerBlock>& blocks,
                  const Graph& graph, bool x64) {
  std::vector<std::unordered_set<std::string>> used(blocks.size());
  std::vector<std::unordered_set<std::string>> defined(blocks.size());
  for (std::size_t i = 0; i < blocks.size(); ++i) {
    for (const auto& statement : blocks[i].statements) {
      auto read = uses(statement, x64);
      const auto written = definitions(statement, x64);
      for (const auto& definition : written)
        if (definition.reg.write == RegisterWrite::partial)
          add_access(read, definition.reg, "partial_write_dependency");
      for (const auto& access : read)
        if (!defined[i].contains(access.reg.canonical))
          used[i].insert(access.reg.canonical);
      for (const auto& access : written)
        defined[i].insert(access.reg.canonical);
    }
  }

  Liveness result{.in = std::vector<std::unordered_set<std::string>>(blocks.size()),
                  .out = std::vector<std::unordered_set<std::string>>(blocks.size())};
  bool changed = true;
  while (changed) {
    changed = false;
    for (std::size_t reverse = blocks.size(); reverse-- > 0;) {
      std::unordered_set<std::string> next_out;
      for (const auto successor : graph.successors[reverse])
        next_out.insert(result.in[successor].begin(), result.in[successor].end());
      auto next_in = used[reverse];
      for (const auto& storage : next_out)
        if (!defined[reverse].contains(storage)) next_in.insert(storage);
      if (next_in != result.in[reverse] || next_out != result.out[reverse])
        changed = true;
      result.in[reverse] = std::move(next_in);
      result.out[reverse] = std::move(next_out);
    }
  }
  return result;
}

State merged_state(std::size_t block, const Graph& graph,
                   const std::vector<State>& outgoing,
                   const std::unordered_set<std::string>& universe,
                   const std::unordered_set<std::string>& live_in,
                   std::uint32_t block_rva, bool function_entry) {
  State result;
  result.reserve(universe.size());
  for (const auto& storage : universe) {
    std::string value = entry_value(storage);
    bool first = !function_entry;
    bool differs = false;
    for (const auto predecessor : graph.predecessors[block]) {
      const auto found = outgoing[predecessor].find(storage);
      const auto& incoming = found == outgoing[predecessor].end()
                                 ? entry_value(storage)
                                 : found->second;
      if (first) {
        value = incoming;
        first = false;
      } else if (value != incoming) {
        differs = true;
      }
    }
    result.emplace(storage, differs && live_in.contains(storage)
                                ? phi_value(storage, block_rva)
                                : value);
  }
  return result;
}

}  // namespace

SsaResult build_ssa(std::vector<DecompilerBlock>& blocks,
                    const std::vector<ControlFlowEdge>& edges,
                    std::uint64_t image_base, bool x64) {
  if (blocks.empty()) return {.converged = true};
  const auto graph = make_graph(blocks, edges, image_base);
  const auto universe = storage_universe(blocks, x64);
  const auto live = liveness(blocks, graph, x64);
  State entry;
  entry.reserve(universe.size());
  for (const auto& storage : universe) entry.emplace(storage, entry_value(storage));

  std::vector<State> incoming(blocks.size(), entry);
  std::vector<State> outgoing(blocks.size(), entry);
  bool changed = true;
  std::size_t iteration = 0;
  const auto limit = std::max<std::size_t>(16, blocks.size() * 4);
  while (changed && iteration++ < limit) {
    changed = false;
    for (std::size_t i = 0; i < blocks.size(); ++i) {
      auto next_in = merged_state(i, graph, outgoing, universe, live.in[i],
                                  blocks[i].rva, i == 0);
      auto next_out = transfer(blocks[i], next_in, x64);
      if (next_in != incoming[i] || next_out != outgoing[i]) changed = true;
      incoming[i] = std::move(next_in);
      outgoing[i] = std::move(next_out);
    }
  }

  SsaResult result{.converged = !changed};
  for (std::size_t i = 0; i < blocks.size(); ++i) {
    auto& block = blocks[i];
    for (const auto& [storage, value] : incoming[i]) {
      if (!value.starts_with(storage + "_phi_")) continue;
      PhiNode phi{.storage = storage, .output = value};
      if (i == 0)
        phi.inputs.push_back({.value = entry_value(storage),
                              .function_entry = true});
      for (const auto predecessor : graph.predecessors[i]) {
        const auto found = outgoing[predecessor].find(storage);
        phi.inputs.push_back(
            {.predecessor_rva = blocks[predecessor].rva,
             .value = found == outgoing[predecessor].end()
                          ? entry_value(storage)
                          : found->second});
      }
      block.phi_nodes.push_back(std::move(phi));
      ++result.phi_count;
    }

    auto state = incoming[i];
    for (auto& statement : block.statements) {
      auto read = uses(statement, x64);
      const auto written = definitions(statement, x64);
      if (statement.operation == "call" && x64) {
        for (const auto reg : {"rcx", "rdx", "r8", "r9", "zmm0", "zmm1",
                               "zmm2", "zmm3"}) {
          auto access = normalized(reg, true);
          const auto found = state.find(access.canonical);
          if (found != state.end() && found->second != entry_value(access.canonical))
            add_access(read, std::move(access), "abi_argument_candidate");
        }
      }
      for (const auto& definition : written) {
        if (definition.reg.write == RegisterWrite::partial)
          add_access(read, definition.reg, "partial_write_dependency");
      }
      for (const auto& access : read) {
        const auto found = state.find(access.reg.canonical);
        statement.ssa_uses.push_back(
            {.storage = access.reg.canonical,
             .value = found == state.end() ? entry_value(access.reg.canonical)
                                           : found->second,
             .role = access.role,
             .offset_bits = access.reg.offset_bits,
             .size_bits = access.reg.size_bits});
        for (auto& memory : statement.memory_accesses)
          if (memory.alias_set == access.reg.canonical &&
              (memory.action == "read" || memory.action == "read_write"))
            memory.ssa_input = statement.ssa_uses.back().value;
      }
      for (const auto& access : written) {
        const auto found = state.find(access.reg.canonical);
        const auto previous = found == state.end()
                                  ? entry_value(access.reg.canonical)
                                  : found->second;
        const auto value = definition_value(access.reg.canonical, statement.address);
        statement.ssa_definitions.push_back(
            {.storage = access.reg.canonical,
             .value = value,
             .previous_value = previous,
             .write = std::string{name(access.reg.write)},
             .role = access.role,
             .offset_bits = access.reg.offset_bits,
             .size_bits = access.reg.size_bits});
        for (auto& memory : statement.memory_accesses)
          if (memory.alias_set == access.reg.canonical &&
              (memory.action == "write" || memory.action == "read_write"))
            memory.ssa_output = value;
        state[access.reg.canonical] = value;
        ++result.definition_count;
      }
    }
  }
  return result;
}

}  // namespace reverseplugin::analysis
