# IL2CPP analysis model

## Artifact map

- Windows commonly places generated game code in `GameAssembly.dll`; Android commonly uses `libil2cpp.so`. `UnityPlayer` is engine code, not the primary game-code image.
- `global-metadata.dat` describes managed images, strings, type definitions, fields, methods, generics, attributes, and usages. Its layout changes across metadata versions and may be transformed on disk.
- Code registration links generated methods/modules and invokers. Metadata registration links native runtime tables to metadata identities. Newer releases increasingly organize code per assembly/module.
- A dummy DLL preserves enough managed shape for browsing and tooling, but its method bodies do not reconstruct the original C#.

## Recognition order

1. Obtain the Unity version from player files, resources, package metadata, or engine strings; label heuristic estimates.
2. Verify metadata magic/version before selecting a parser. A failed parser is not proof of encryption.
3. Locate registration through symbols/exports when present, initializer call graphs, pointer-array cardinalities, or runtime IL2CPP API enumeration.
4. Validate candidates using multiple counts and pointer ranges. Registrations should point into plausible readable tables and executable method targets.
5. Resolve generic sharing, adjustor thunks, invokers, reverse P/Invoke wrappers, and stripped methods as distinct concepts; do not force one-to-one mappings.

## Runtime checks

- Prefer exported IL2CPP APIs when available: enumerate domains, assemblies, images, classes, methods, and fields rather than guessing private layouts.
- If APIs are stripped, identify call sites semantically and confirm calling convention and argument flow before naming.
- For field reads, distinguish instance, static, thread-static, literal, and RVA-backed fields. Static storage is not an instance offset.
- Garbage collection can relocate or invalidate assumptions. Re-read roots and validate object class pointers before long chains.
- Burst-compiled jobs and native engine code may not correspond to ordinary IL2CPP method definitions.

## Tool choice

- Il2CppDumper: broad PE/ELF/Mach-O/NSO/WASM metadata extraction and IDA/Ghidra exports.
- Il2CppInspector: rich type scaffolding, shim assemblies, and analysis scripts.
- Cpp2IL: higher-level reconstruction experiments; validate output against native code.
- AssetRipper: serialized assets and project-shaped export; code recovery quality is a separate question.

Never treat one tool's output as ground truth. Preserve its version and input hashes, then cross-check sample method RVAs and field offsets.

## Primary references

- Unity IL2CPP pipeline: https://docs.unity3d.com/Manual/il2cpp-introduction.html
- Il2CppDumper: https://github.com/Perfare/Il2CppDumper
- Il2CppInspector: https://github.com/djkaty/Il2CppInspector
- Cpp2IL: https://github.com/SamboyCoding/Cpp2IL
- AssetRipper: https://github.com/AssetRipper/AssetRipper
