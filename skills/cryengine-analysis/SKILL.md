---
name: cryengine-analysis
description: Analyze authorized CRYENGINE games through CrySystem modules, gEnv subsystems, entity and reflection interfaces, CryPak archives, GameSDK plugins, configuration, and level assets. Use when CrySystem, CryPak, GameSDK, system.cfg, .cryproject, or CRYENGINE modules are present.
---

# CRYENGINE Analysis

Read [references/cryengine-model.md](references/cryengine-model.md) before transferring interfaces or layouts between CRYENGINE generations.

## Workflow

1. Call `open_engine_workspace` on the game root. Confirm CRYENGINE using `CrySystem.dll`, a `.cryproject`, renderer modules, or configuration evidence; `.pak` alone is ambiguous.
2. Use `list_engine_artifacts` to separate engine/game modules, symbols, configuration, shaders, scripts, levels, and PAK files. `inspect_engine_artifact` reports bounded evidence but does not decrypt signed or encrypted PAKs.
3. Read `system.cfg` evidence for the game folder and game DLL, then analyze those native modules with the ordinary PE tools.
4. Recover the global environment and subsystem interfaces from validated initialization paths. Keep `ISystem`, `IEntitySystem`, `ICryPak`, renderer, script, and plugin ownership distinct.
5. Use matching public engine headers only after establishing a generation and compiler ABI. Validate virtual layouts through call sites or runtime objects.
6. Treat entity components, Flow Graph, Schematyc, legacy GameSDK, and modern plugins as generation-specific systems rather than one stable reflection model.

## Output and done

Report version evidence, selected game module, subsystem roots, interface/layout assumptions, package state, levels/scripts, and confidence. Completion requires each transferred interface slot or field to be tied to the target build by code or runtime invariants.
