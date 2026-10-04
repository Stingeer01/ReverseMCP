#include "reverseplugin/analysis/control_regions.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <limits>
#include <queue>
#include <ranges>
#include <unordered_map>
#include <unordered_set>

#include "reverseplugin/analysis/decompiler.hpp"

namespace reverseplugin::analysis {
namespace {

class Bits final {
 public:
  explicit Bits(std::size_t size, bool set = false)
      : size_(size), words_((size + 63) / 64, set ? UINT64_MAX : 0) {
    if (set && size % 64 != 0) words_.back() &= (UINT64_C(1) << (size % 64)) - 1;
  }

  void set(std::size_t index) { words_[index / 64] |= UINT64_C(1) << (index % 64); }
  void reset(std::size_t index) { words_[index / 64] &= ~(UINT64_C(1) << (index % 64)); }
  [[nodiscard]] bool contains(std::size_t index) const {
    return (words_[index / 64] & (UINT64_C(1) << (index % 64))) != 0;
  }
  [[nodiscard]] std::size_t count() const {
    std::size_t result = 0;
    for (const auto word : words_) result += std::popcount(word);
    return result;
  }
  Bits& intersect(const Bits& other) {
    for (std::size_t i = 0; i < words_.size(); ++i) words_[i] &= other.words_[i];
    return *this;
  }
  [[nodiscard]] bool operator==(const Bits&) const = default;

 private:
  std::size_t size_{};
  std::vector<std::uint64_t> words_;
};

struct Successor final {
  std::size_t block{};
  std::string type;
};

struct Graph final {
  std::vector<std::vector<Successor>> successors;
  std::vector<std::vector<std::size_t>> predecessors;
  std::unordered_map<std::uint32_t, std::size_t> by_rva;
};

Graph make_graph(const std::vector<DecompilerBlock>& blocks,
                 const std::vector<ControlFlowEdge>& edges,
                 std::uint64_t image_base) {
  Graph graph{.successors = std::vector<std::vector<Successor>>(blocks.size()),
              .predecessors = std::vector<std::vector<std::size_t>>(blocks.size())};
  std::unordered_map<std::uint32_t, std::size_t> owner;
  for (std::size_t i = 0; i < blocks.size(); ++i) {
    graph.by_rva.emplace(blocks[i].rva, i);
    for (const auto& statement : blocks[i].statements) {
      const auto rva = statement.address - image_base;
      if (rva <= std::numeric_limits<std::uint32_t>::max())
        owner.emplace(static_cast<std::uint32_t>(rva), i);
    }
  }
  for (const auto& edge : edges) {
    const auto from = owner.find(edge.from_rva);
    const auto to = graph.by_rva.find(edge.to_rva);
    if (from == owner.end() || to == graph.by_rva.end()) continue;
    auto& successors = graph.successors[from->second];
    if (std::ranges::find(successors, to->second, &Successor::block) ==
        successors.end())
      successors.push_back({to->second, edge.type});
    auto& predecessors = graph.predecessors[to->second];
    if (std::ranges::find(predecessors, from->second) == predecessors.end())
      predecessors.push_back(from->second);
  }
  return graph;
}

std::vector<Bits> dominators(const Graph& graph, std::size_t entry) {
  const auto n = graph.successors.size();
  std::vector<Bits> result;
  result.reserve(n);
  for (std::size_t i = 0; i < n; ++i) result.emplace_back(n, i != entry);
  result[entry] = Bits{n};
  result[entry].set(entry);
  bool changed = true;
  while (changed) {
    changed = false;
    for (std::size_t block = 0; block < n; ++block) {
      if (block == entry) continue;
      Bits next{n, true};
      if (graph.predecessors[block].empty()) next = Bits{n};
      for (const auto predecessor : graph.predecessors[block])
        next.intersect(result[predecessor]);
      next.set(block);
      if (next == result[block]) continue;
      result[block] = std::move(next);
      changed = true;
    }
  }
  return result;
}

std::vector<Bits> postdominators(const Graph& graph) {
  const auto n = graph.successors.size();
  std::vector<Bits> result;
  result.reserve(n);
  bool has_exit = false;
  for (std::size_t i = 0; i < n; ++i) {
    const bool exit = graph.successors[i].empty();
    has_exit = has_exit || exit;
    result.emplace_back(n, !exit);
    if (exit) result.back().set(i);
  }
  if (!has_exit) return {};
  bool changed = true;
  while (changed) {
    changed = false;
    for (std::size_t block = 0; block < n; ++block) {
      if (graph.successors[block].empty()) continue;
      Bits next{n, true};
      for (const auto& successor : graph.successors[block])
        next.intersect(result[successor.block]);
      next.set(block);
      if (next == result[block]) continue;
      result[block] = std::move(next);
      changed = true;
    }
  }
  return result;
}

std::vector<std::size_t> natural_loop(const Graph& graph, std::size_t header,
                                      std::size_t latch) {
  std::unordered_set<std::size_t> members{header, latch};
  std::vector<std::size_t> pending{latch};
  while (!pending.empty()) {
    const auto current = pending.back();
    pending.pop_back();
    for (const auto predecessor : graph.predecessors[current]) {
      if (members.insert(predecessor).second && predecessor != header)
        pending.push_back(predecessor);
    }
  }
  std::vector<std::size_t> result{members.begin(), members.end()};
  std::ranges::sort(result);
  return result;
}

std::vector<std::uint32_t> region_members(const Graph& graph,
                                          const std::vector<DecompilerBlock>& blocks,
                                          std::size_t first, std::size_t second,
                                          std::optional<std::size_t> merge) {
  std::vector<std::uint32_t> result;
  std::vector<bool> visited(blocks.size());
  std::queue<std::size_t> pending;
  pending.push(first);
  pending.push(second);
  while (!pending.empty()) {
    const auto current = pending.front();
    pending.pop();
    if (merge && current == *merge) continue;
    if (visited[current]) continue;
    visited[current] = true;
    result.push_back(blocks[current].rva);
    for (const auto& successor : graph.successors[current]) pending.push(successor.block);
  }
  std::ranges::sort(result);
  return result;
}

}  // namespace

std::vector<ControlRegion> recover_control_regions(
    const std::vector<DecompilerBlock>& blocks,
    const std::vector<ControlFlowEdge>& edges, std::uint64_t image_base,
    std::uint32_t entry_rva) {
  std::vector<ControlRegion> result;
  if (blocks.empty()) return result;
  const auto graph = make_graph(blocks, edges, image_base);
  const auto entry = graph.by_rva.contains(entry_rva) ? graph.by_rva.at(entry_rva) : 0;
  const auto dom = dominators(graph, entry);

  for (std::size_t latch = 0; latch < blocks.size(); ++latch) {
    for (const auto& successor : graph.successors[latch]) {
      if (!dom[latch].contains(successor.block)) continue;
      const auto members = natural_loop(graph, successor.block, latch);
      ControlRegion loop{.kind = "natural_loop",
                         .header_rva = blocks[successor.block].rva,
                         .entries = {blocks[successor.block].rva},
                         .confidence = "exact"};
      std::unordered_set<std::size_t> member_set{members.begin(), members.end()};
      for (const auto member : members) {
        loop.members.push_back(blocks[member].rva);
        for (const auto& target : graph.successors[member]) {
          if (!member_set.contains(target.block))
            loop.exits.push_back(blocks[target.block].rva);
        }
      }
      std::ranges::sort(loop.exits);
      loop.exits.erase(std::ranges::unique(loop.exits).begin(), loop.exits.end());
      result.push_back(std::move(loop));
    }
  }

  const auto postdom = postdominators(graph);
  for (std::size_t header = 0; header < blocks.size(); ++header) {
    const auto& successors = graph.successors[header];
    if (successors.size() != 2) continue;
    std::optional<std::size_t> merge;
    if (!postdom.empty()) {
      std::size_t best_depth = 0;
      for (std::size_t candidate = 0; candidate < blocks.size(); ++candidate) {
        if (candidate == header || !postdom[successors[0].block].contains(candidate) ||
            !postdom[successors[1].block].contains(candidate))
          continue;
        const auto depth = postdom[candidate].count();
        if (!merge || depth > best_depth) {
          merge = candidate;
          best_depth = depth;
        }
      }
    }
    ControlRegion conditional{
        .kind = "conditional",
        .header_rva = blocks[header].rva,
        .merge_rva = merge ? blocks[*merge].rva : 0,
        .entries = {blocks[successors[0].block].rva,
                    blocks[successors[1].block].rva},
        .members = region_members(graph, blocks, successors[0].block,
                                  successors[1].block, merge),
        .confidence = merge ? "inferred" : "partial"};
    if (merge) conditional.exits.push_back(blocks[*merge].rva);
    result.push_back(std::move(conditional));
  }
  return result;
}

}  // namespace reverseplugin::analysis
