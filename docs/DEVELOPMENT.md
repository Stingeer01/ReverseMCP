# Development guide

## Configure, build, and test

```powershell
cmake --preset release
cmake --build --preset release
ctest --preset release
```

`scripts/build.ps1` runs the same configure, build, and test sequence. `scripts/release.ps1` adds a clean rebuild and package staging.

## Source layout

- `include/reverseplugin` — public SDK headers.
- `src/analysis` — PE images, indexes, function analysis, and persistent cache.
- `src/engine` — bounded game-installation discovery and artifact signature inspection.
- `src/debug` — debugger state and stack walking.
- `src/disasm` — decoder adapter.
- `src/mcp` — transport and tool registry.
- `src/memory` — patterns and snapshots.
- `src/process` — process handles and memory operations.
- `src/runtime` — bounded worker infrastructure.
- `src/tools` — MCP-facing adapters.
- `tests` — unit, integration, and stress executables.
- `skills` — agent procedures and references.

## Code rules

- Target C++23 and keep `/W4 /WX /permissive-` clean under MSVC.
- Use RAII for all Windows handles and debugger state.
- Use `std::expected` for recoverable failures at domain boundaries.
- Accept non-owning input as `std::span` or `std::string_view` where lifetime is clear.
- Keep OS calls, analysis algorithms, MCP conversion, and skill guidance in separate layers.
- Bound work at both schema and backend levels.
- Do not place exceptions on normal invalid-input paths.
- Preserve address precision in JSON by returning hexadecimal strings.
- Add comments only for invariants, operating-system constraints, and non-obvious low-level behavior.

## Adding a tool

1. Put reusable behavior in the appropriate domain module.
2. Add a final `mcp::Tool` adapter under `src/tools`.
3. Give the tool a task-specific name and complete argument descriptions.
4. Define closed input and output schemas with `additionalProperties: false`.
5. Set accurate MCP annotations, especially for writes and debugger state changes.
6. Register the tool in its feature group.
7. Add success, limit, and invalid-input tests.
8. Update `docs/TOOLS.md` and the README tool count if it changed.

## Adding or changing a skill

Keep the entry workflow short. Put version-sensitive layouts and larger models in `references`. Prefer platform specifications, vendor documentation, upstream source, and primary research. Run:

```powershell
python scripts/validate_knowledge.py skills
```

## Test boundaries

Unit tests must not depend on a third-party target. The debugger integration test launches the repository's own child process. Stress tests check completeness and state integrity while printing local throughput; they should not assert a speed measured on one machine.
