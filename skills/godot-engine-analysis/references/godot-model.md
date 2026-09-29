# Godot analysis model

## Version boundaries

- Godot 3 and 4 differ substantially in scripting bytecode, Variant representation, StringName internals, extension APIs, rendering, and resource formats.
- Export templates may be custom compiled. Feature defines, precision, tools/debug status, and modules can change observable layouts.
- Match source by version/tag and platform before using offsets. Prefer registrations and behavior over raw structure matching.

## Runtime anchors

- `Object` supplies instance identity, class behavior, properties, methods, and signals.
- `ClassDB` registers engine and extension classes plus methods/properties; registration call graphs provide stronger evidence than isolated strings.
- `Variant` is tagged storage. Decode the type tag first and respect ownership/reference semantics.
- `StringName` is interned; validate table candidates through repeated names and stable identity.
- GDExtension crosses a versioned C ABI. Locate initialization and interface negotiation before analyzing extension methods.

## Resources

- A PCK is a resource container, not proof that scripts are recoverable source.
- Text `.tscn`/`.tres` and binary `.scn`/`.res` represent scenes/resources. Preserve paths, resource IDs, subresources, and dependencies.
- C# exports should be handled as .NET plus native Godot interop; GDScript bytecode requires a version-matched decoder.

## Primary references

- Godot source: https://github.com/godotengine/godot
- ClassDB: https://github.com/godotengine/godot/blob/master/core/object/class_db.h
- Resource loaders: https://docs.godotengine.org/en/stable/contributing/development/core_and_modules/custom_resource_format_loaders.html
- GDExtension: https://docs.godotengine.org/en/stable/tutorials/scripting/gdextension/index.html
