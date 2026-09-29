# Native triage model

## Loader-first checklist

- PE: DOS/NT headers, section table, data directories, imports/delay imports, exports, base relocations, TLS callbacks, exception/unwind tables, load configuration, resources, debug directory, certificate table, overlay.
- ELF: ELF/program/section headers, interpreter, dynamic table, relocations, PLT/GOT, init/fini arrays, notes, symbols/versioning, GNU properties, build ID.
- Mach-O: headers/load commands, segments/sections, dyld info/chained fixups, exports trie, function starts, code signature, UUID, Objective-C/Swift metadata.

## Packing indicators

Treat these as evidence, not verdicts: entry point in an unusual section, writable-executable mappings, tiny imports with runtime resolution, compressed/high-entropy regions, mismatched raw/virtual sizes, self-modifying behavior, discarded headers, overlay payloads, or a transfer into newly written executable memory.

## Compiler and language anchors

- MSVC: PE exception metadata, RTTI, security cookie helpers, PDB identifiers, decorated names.
- GCC/Clang: ELF unwind/DWARF, Itanium ABI RTTI, compiler runtime helpers.
- Rust: panic/runtime strings, language items, monomorphized symbols when unstripped; do not identify Rust from one string.
- Go: pclntab/moduledata/build info, goroutine/runtime helpers.
- .NET Native/NativeAOT and IL2CPP require runtime-specific metadata analysis rather than ordinary C++ assumptions.

## Primary references

- Microsoft PE/COFF: https://learn.microsoft.com/windows/win32/debug/pe-format
- System V ABI: https://gitlab.com/x86-psABIs/x86-64-ABI
- ELF specification: https://refspecs.linuxfoundation.org/elf/elf.pdf
- Mach-O loader definitions: https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h
- DWARF: https://dwarfstd.org/
