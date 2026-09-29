---
name: godot-engine-analysis
description: Analyze authorized Godot 3/4 games, native engine modules, ClassDB reflection, Object and Variant layouts, GDScript or C# assemblies, GDExtension libraries, resources, scenes, and PCK containers. Use when Godot, PCK, GDScript, ClassDB, GDExtension, Variant, or packed resources are present.
---

# Godot Engine Analysis

Read [references/godot-model.md](references/godot-model.md) for version boundaries and runtime invariants.

## Workflow

1. Identify Godot major/minor, standard versus custom export template, architecture, scripting languages, embedded/adjacent PCK, and native extensions.
2. Inventory `.pck`, scenes/resources, GDScript bytecode/source, .NET assemblies, and GDExtension libraries separately.
3. Use open-source engine code from the matching tag as the structural oracle. Confirm compiler ABI and build options before transferring layouts.
4. Recover `ClassDB` registrations and `StringName` identities before interpreting `Object`, `Variant`, method binds, signals, or property metadata.
5. Correlate script/resource paths with runtime nodes and classes using multiple names or method bindings.
6. Treat custom modules and extensions as independent native targets while retaining their engine registration boundary.

## Output and done

Report the exact or estimated engine tag, export model, package contents, script formats, reflection anchors, native extensions, and validated type layouts. Completion requires every transferred layout to cite a matching source tag or runtime invariant.
