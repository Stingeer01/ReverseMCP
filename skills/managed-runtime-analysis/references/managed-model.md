# Managed runtime model

## Identity layers

- Assembly/module identity and MVID.
- Metadata table plus row/token.
- Type/method signature including generic context.
- Runtime descriptor (`MethodDesc` or Mono equivalent).
- Entry stub/precode versus current JIT/AOT native body.

Keep these layers separate in outputs.

## Deployment variants

- Ordinary IL: CLI metadata and method bodies remain primary.
- ReadyToRun: native code coexists with full input IL/metadata and fixup/runtime structures; execution may still fall back or re-JIT.
- Mono JIT/AOT: runtime registries and AOT modules map methods; LLVM/full/hybrid AOT change code shape.
- Single-file: assemblies may be bundled/extracted/mapped; inspect the bundle manifest before assuming missing files.
- NativeAOT: platform-native object code and self-describing runtime data replace the ordinary CoreCLR deployment model; reflection/trimming choices determine retained metadata.

## Runtime pitfalls

- Tiered compilation can change active code addresses.
- Generic code may be shared and receive hidden context arguments.
- Delegates and interface dispatch introduce stubs before the target.
- Managed object references are GC-tracked; a raw address is not a durable identity.
- P/Invoke marshalling stubs are distinct from both managed and imported native implementations.

## Primary references

- ECMA-335 CLI specification: https://ecma-international.org/publications-and-standards/standards/ecma-335/
- .NET runtime: https://github.com/dotnet/runtime
- ReadyToRun format: https://github.com/dotnet/runtime/blob/main/docs/design/coreclr/botr/readytorun-format.md
- NativeAOT overview: https://github.com/dotnet/runtime/blob/main/docs/workflow/building/coreclr/nativeaot.md
- Mono runtime design: https://www.mono-project.com/docs/advanced/runtime/
