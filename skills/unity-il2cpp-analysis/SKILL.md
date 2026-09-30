---
name: unity-il2cpp-analysis
description: Analyze authorized Unity Mono or IL2CPP games, recover type and method metadata, correlate native code with managed identities, inspect runtime objects, and assess Unity assets. Use when GameAssembly, libil2cpp, global-metadata.dat, UnityPlayer, MonoBehaviour, or Unity serialized assets are involved.
---

# Unity and IL2CPP Analysis

Identify the scripting backend and Unity generation before assuming layouts. Read [references/il2cpp-model.md](references/il2cpp-model.md) for IL2CPP artifacts, version-sensitive structures, runtime validation, and tool-selection criteria.

## Workflow

1. Inventory the executable, `UnityPlayer`, `GameAssembly.dll` or `libil2cpp`, `global-metadata.dat`, `*_Data`, managed assemblies, asset bundles, and platform/architecture.
2. Classify Mono versus IL2CPP. Treat dummy assemblies as metadata projections, never recovered source code.
3. Establish the image base and distinguish VA, RVA, file offset, metadata index, token, and method pointer in every result.
4. For compact metadata v38/v39 on Windows x86-64, call `open_il2cpp_workspace` with the matching metadata and `GameAssembly.dll`. Use `dump_il2cpp_types` for bounded investigation or `export_il2cpp_jsonl` for a complete dump. Use runtime observation only when registration, metadata, or code is transformed after load.
5. Correlate `image → namespace → type → method/field` with native method addresses. A null `native_rva` means the pointer is absent or runtime-initialized, not that the method is absent. Validate a sample of resolved RVAs through `open_binary` and `disassemble_binary` before bulk naming.
6. For objects, prove the class/type identity before walking fields. Record pointer width, object header assumption, field offset source, and whether the value was read statically or live.
7. Analyze serialized assets separately from executable code; reconnect `MonoScript`/`MonoBehaviour` identities through GUID, file ID, assembly, namespace, and class evidence.

Use ReverseMCP for IL2CPP workspaces, modules, bounded signature scans, pointer chains, structured disassembly, and breakpoints. Close large IL2CPP workspaces after export. Do not write memory unless the user explicitly requests a target modification.

## Output

Return an evidence ledger containing Unity version estimate, backend, metadata version, modules/bases, registrations or APIs found, recovered identities with confidence, unresolved version assumptions, and reproducible next probes.

## Done

The analysis is complete when each claimed managed-to-native mapping has at least two independent anchors, address spaces are normalized, version assumptions are explicit, and the result can be reproduced without parsing decompiler prose.
