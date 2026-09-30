---
name: reverse-analysis
description: Route authorized reverse-engineering work through ReversePlugin's structured MCP tools and focused engine, binary, protection, decompiler, or debugger skills. Use for native disassembly, memory inspection, pointer analysis, signatures, or live debugging when no narrower ReversePlugin skill has already been selected.
---

# Reverse Analysis

## Route by target

- Unity, `GameAssembly`, `libil2cpp`, or `global-metadata.dat`: use `unity-il2cpp-analysis`.
- Unreal Engine, UObject reflection, PAK/IoStore, or UAsset: use `unreal-engine-analysis`.
- Godot, PCK, GDScript, ClassDB, or GDExtension: use `godot-engine-analysis`.
- Source/Source 2, `CreateInterface`, entity tables/schema, BSP, or VPK: use `source-engine-analysis`.
- CRYENGINE, CrySystem, CryPak, GameSDK, or `.cryproject`: use `cryengine-analysis`.
- Cocos2d-x, cocos2d native libraries, `cocos2d::Ref`, Lua, or JavaScript bindings: use `cocos2d-x-analysis`.
- .NET, Mono, ReadyToRun, trimmed, single-file, or NativeAOT: use `managed-runtime-analysis`.
- Unknown PE/ELF/Mach-O or toolchain identification: use `native-binary-triage`.
- Packers, self-modification, anti-debugging, flattening, or virtualized code: use `protected-binary-analysis`.
- Decompiled pseudocode, calling conventions, types, CFG, or indirect calls: use `decompiler-guided-analysis`.
- Breakpoint-driven runtime investigation: use `runtime-debugging`.

Combine skills only when their domains truly overlap. Keep one shared evidence ledger so names, hashes, module bases, address forms, and confidence do not diverge between phases.

Use `get_server_info` first when the available native modules are unknown. Only call tools listed by the server; a module absent from `modules` is not available in the current build.

For an unknown game directory, call `open_engine_workspace` before selecting an engine skill. Treat `engine` and `confidence` as a ranked artifact-based hypothesis: inspect `evidence` and `candidates`, especially when several engines use `.pak` or `.dll` files. Use `list_engine_artifacts` to choose exact native modules and containers, `inspect_engine_artifact` for bounded signature validation, and `close_engine_workspace` after the index is no longer needed.

For static PE analysis, call `open_binary` once and retain `binary_id`. Inspect sections, imports, and exports with `get_binary_index`; index strings and functions with `find_binary_strings` and `discover_binary_functions`; use `find_binary_xrefs` for callers and data users; then call `analyze_binary_function` at evidence-backed seeds. Use `read_binary_bytes`, `disassemble_binary`, and `scan_binary_pattern` for targeted verification. Preserve recovered names, comments, and type hypotheses with binary annotations. Treat recursive discovery as bounded evidence, not proof that every byte is code. Results are keyed by the binary SHA-256 fingerprint and may be served from persistent cache. Call `close_binary` when the in-memory workspace is no longer needed.

For live analysis, locate a target with `list_processes`, create one reusable session with `attach_process`, and release it with `detach_process` when the analysis is complete. Resolve module-relative addresses through `list_modules`. Check unknown ranges with `query_memory_regions` before requesting large reads.

Use `disassemble_memory` for code. Its `operands`, `absolute_address`, `registers_read`, and `registers_written` fields are authoritative for reasoning; `text` is a presentation field. Use `read_memory` for headers, data structures, strings, and verification of exact bytes.

Use `scan_memory_pattern` for bounded AOB searches and `read_pointer_chain` for runtime object graphs. Prefer executable-only scans for code signatures. `write_memory` is deliberately limited to existing writable committed pages and should use verification unless the user explicitly needs a transient write.

Use typed memory snapshots for unknown runtime values: capture the narrowest justified region, then repeatedly refine with `changed`, `unchanged`, `increased`, or `decreased`. Delete snapshots after use so the bounded server-side memory budget is released.

Prefer structured fields over parsing rendered assembly text. Preserve exact hexadecimal addresses in conclusions, distinguish observed facts from inferences, and never request memory writes unless the user explicitly asks to modify the target process.

Keep reads narrow. Start with the smallest address range that can answer the question, then expand based on returned region metadata or control flow.

Use debugger tools only when the user asks for live debugging or breakpoint-driven analysis. Start with `debug_attach`, install breakpoints only at validated instruction boundaries, and consume events with `wait_debug_event`. At a breakpoint, read registers before `continue_debug_event`. Always call `debug_detach` when finished so original bytes are restored and the target is left running.

Use `list_debug_threads` before thread-specific analysis. Call `single_step` only while execution is paused, then call `wait_debug_event` to receive the resulting `single_step` event before reading the new register state or continuing.

Use hardware breakpoints when modifying code bytes is unsafe. They are per-thread and limited to four slots; choose size 1 for execute traps and align data-watch addresses to their 1/2/4/8-byte width. Pair every explicit `suspend_debug_thread` with `resume_debug_thread`; detach also releases suspensions owned by the session.

Unknown first-chance exceptions are passed to the target by default. Managed breakpoint hits and second-chance exceptions pause execution. Use `handled: false` when continuing an exception that should remain visible to the target's own handlers.
