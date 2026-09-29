---
name: source-engine-analysis
description: Analyze authorized Valve Source and Source 2 games through module interfaces, entities, reflection/schema metadata, networking tables, ConVars, materials, maps, and VPK resources. Use when engine/client/server modules, CreateInterface, datamaps, recv/send tables, SchemaSystem, VPK, BSP, or Source resource files are involved.
---

# Source Engine Analysis

Read [references/source-model.md](references/source-model.md) before transferring SDK layouts. Source 1 branches and Source 2 are different object/reflection systems.

## Workflow

1. Identify engine generation, game branch/build, platform, architecture, and client/server/tool module inventory.
2. Enumerate exported interfaces and trace `CreateInterface` registrations before signature-scanning private globals.
3. Source 1: recover entities through client/server class metadata, recv/send tables, and datamaps. Source 2: prefer SchemaSystem class/field metadata.
4. Validate field offsets using several live instances, type/range invariants, and access-site disassembly.
5. Keep simulation state, render state, networking state, and resource identifiers distinct even when names overlap.
6. Analyze VPK/maps/resources as a separate layer and retain paths, hashes, resource type, and build compatibility.

## Output and done

Report build evidence, modules/interfaces, reflection source, entity/type layouts, networked versus local fields, resources, and confidence. Completion requires offsets to be derived from the target build or validated runtime metadata—not pasted from another release.
