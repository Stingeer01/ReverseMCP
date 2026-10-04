# Changelog

This project follows Semantic Versioning. Dates use ISO 8601.

## [Unreleased]

## [1.3.0] - 2026-10-04

### Added

- `decompile_binary_function`, a bounded x86/x64 semantic decompiler with address-linked C-like pseudocode, canonical register slices, pruned inter-block register and memory SSA, phi nodes, normalized stack variables, ABI parameter candidates, natural-loop and conditional-region recovery, type/field evidence, confidence levels, and explicit unsupported-instruction intrinsics.
- PE32+ runtime-function boundary parsing, tail-call references, and import/export symbol propagation for static function analysis.
- Live function names, target names, comments, and prototypes from persistent annotations, including on decompiler cache hits.
- Concurrent decompiler stress coverage plus focused register-alias, loop SSA, memory SSA, control-region, annotation-overlay, and end-to-end MCP tests.

## [1.2.0] - 2026-09-30

### Added

- Four bounded game-engine workspace tools for detection, artifact indexing, signature inspection, and lifecycle cleanup.
- Evidence-ranked support for Unity, Unreal Engine, Godot, Source, Source 2, CRYENGINE, and Cocos2d-x installations.
- PE, Valve VPK, and standalone or executable-embedded Godot PCK header inspection.
- CRYENGINE and Cocos2d-x analysis Skills, plus native-tool routing in the Unity, Unreal, Godot, Source, and triage Skills.
- Synthetic Unity, Source 2, and Godot engine-workspace tests.

## [1.1.0] - 2026-09-30

### Added

- Four IL2CPP tools for workspace lifecycle, filtered type inspection, and atomic JSONL export.
- Strict compact `global-metadata.dat` v38/v39 parsing for images, types, fields, methods, and parameters.
- Static x86-64 `GameAssembly.dll` code-registration discovery and method-token to native-RVA mapping.
- File-identity workspace reuse and SHA-256 reporting for metadata and native images.
- Synthetic metadata and token-mapping tests plus validation against a current Rust installation.

## [1.0.0] - 2026-09-29

### Added

- Native C++23 MCP server with newline-delimited JSON-RPC over stdio and a fixed worker pool.
- Forty tools for PE32/PE32+ analysis, process memory, typed snapshots, Zydis disassembly, native debugging, and stack walking.
- Function discovery, bounded CFG recovery, direct xrefs, string indexing, call graphs, and SHA-256-keyed persistent analysis.
- Persistent analyst names, comments, and type declarations.
- Managed software and hardware breakpoints, single-step, register contexts, thread control, and DbgHelp stack traces.
- Ten composable analysis skills covering native binaries, protected code, managed runtimes, Unity IL2CPP, Unreal Engine, Godot, and Source.
- SDK, MCP, cache, debugger integration, knowledge validation, and high-volume stress tests.

[Unreleased]: https://github.com/Stingeer01/ReverseMCP/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/Stingeer01/ReverseMCP/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Stingeer01/ReverseMCP/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Stingeer01/ReverseMCP/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Stingeer01/ReverseMCP/releases/tag/v1.0.0
