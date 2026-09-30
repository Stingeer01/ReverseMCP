---
name: unreal-engine-analysis
description: Analyze authorized Unreal Engine games and tools through UObject reflection, names, object arrays, properties, functions, Blueprints, and cooked asset containers. Use for UE4/UE5 binaries, UObjects, FName, GNames, GUObjectArray, ProcessEvent, UAsset, PAK, IoStore, UTOC, or USMAP investigations.
---

# Unreal Engine Analysis

Read [references/unreal-model.md](references/unreal-model.md) before interpreting layouts. Engine minor versions, licensee changes, case-preserving names, and UE5 object/property changes make fixed offsets unreliable.

## Workflow

1. Call `open_engine_workspace` on the game root. Confirm the Unreal candidate score from more than a `.pak` extension, then use `list_engine_artifacts` to inventory native modules, PDBs, AssetRegistry, cooked assets, PAK, and paired UTOC/UCAS files.
2. Inspect representative containers with `inspect_engine_artifact`. This identifies the container family and bounded header/trailer bytes; it does not decrypt indexes or claim to enumerate encrypted content. Establish UE generation, platform, architecture, and build configuration from independent binary or configuration evidence.
3. Separate reflection/runtime work from cooked-asset work. Normalize module-relative addresses.
4. Recover and validate name storage, the global object array, object/class relationships, and reflection field chains before generating SDK-like output.
5. Validate candidates with invariants: readable aligned pointers, stable indices, plausible name decoding, class ancestry, object flags, and cross-references from known engine routines.
6. Find behavior through reflected `UFunction` metadata and `ProcessEvent`, then correlate native function pointers or Blueprint bytecode where applicable.
7. For assets, require the matching engine version and mappings for unversioned properties.

Use hardware breakpoints for hot reflection structures where code patching is undesirable. Avoid scanning the entire address space when module/section bounds are known.

## Output and done

Report version evidence, recovered global structures, layout assumptions, named types/functions/properties, asset-container state, and confidence per mapping. Completion requires sampled object walks and names to agree across independent roots, with no silent reliance on community offsets.
