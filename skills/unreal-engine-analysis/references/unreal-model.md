# Unreal runtime and asset model

## Runtime anchors

- `UObject` identity is driven by class, outer, name, flags, and object-array registration. Do not identify objects from vtable shape alone.
- `FName` is an indexed/interned name representation whose pool layout varies. Validate decoding on many known engine names and numbered-name behavior.
- The global object array may be chunked and may track serial numbers for weak references. Prove chunk boundaries and valid-item predicates.
- Reflection represents classes, structs, functions, enums, and properties. UE4 and UE5 differ materially in field/property representation.
- `ProcessEvent` dispatches reflected calls. A cross-reference is useful only after the candidate's argument flow and `UFunction` relationship are verified.

## Cooked content

- Traditional packages may use `.uasset`, `.uexp`, and `.ubulk`; containerized releases may use PAK or UE5 IoStore `.utoc`/`.ucas`.
- Unversioned properties omit enough schema that a matching `.usmap` or equivalent mappings can be essential.
- Blueprint behavior may exist as serialized Kismet bytecode rather than a direct native function. Nativization and shipping settings change this boundary.
- Preserve package path, object path, export index, class, and container offset when correlating assets to runtime objects.

## Validation traps

- Never import offsets from another game/build without structural validation.
- Distinguish `FString`, `FName`, `FText`, `TArray`, `TMap`, weak/object pointers, and handles; identical-looking pointer fields have different invariants.
- Shipping builds can strip console commands, stats, checks, and symbols without removing reflection.
- Anti-cheat or integrity controls are authorization boundaries, not merely technical obstacles.

## Primary references

- Reflection system: https://dev.epicgames.com/documentation/unreal-engine/reflection-system-in-unreal-engine
- Asset Registry: https://dev.epicgames.com/documentation/unreal-engine/asset-registry-in-unreal-engine
- Unreal source: https://github.com/EpicGames/UnrealEngine
- UAssetAPI/UAssetGUI: https://github.com/atenfyr/UAssetGUI
