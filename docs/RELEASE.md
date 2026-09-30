# ReverseMCP 1.2 release contract

ReverseMCP 1.2 targets authorized x86/x64 Windows PE and game-engine analysis. The shipped MCP server provides evidence-ranked installation workspaces for seven engine families, static PE workspaces, compact IL2CPP metadata v38/v39 dumps, x86-64 GameAssembly method mapping, structured Zydis decoding, bounded function and string discovery, direct xrefs, persistent annotations, validated process-memory access, and native Win32 debugging.

## Safety and resource boundaries

- Input files are read-only and capped at 2 GiB.
- String, xref, function, CFG, memory-read, snapshot, and result counts have explicit limits.
- Persistent results are isolated by SHA-256 content identity and written with atomic replacement.
- Runtime writes require writable committed pages and support read-back verification.
- Debug detach restores managed software breakpoints and owned suspensions.
- Addresses are serialized as hexadecimal strings to preserve 64-bit precision.
- IL2CPP native mappings are accepted only when registration and module counts agree with metadata; unavailable runtime-initialized method pointers remain null.
- Engine scans do not follow symlinks and enforce recursion, file, and retained-artifact budgets.

## Compatibility boundary

The native static loader supports PE32 and PE32+. Native IL2CPP mapping supports compact metadata versions 38 and 39 paired with an x86-64 Windows `GameAssembly.dll`. Engine workspaces identify and inventory Unity, Unreal Engine, Godot, Source, Source 2, CRYENGINE, and Cocos2d-x, but do not promise deep extraction of encrypted PAK, IoStore, VPK, or PCK content. Older IL2CPP metadata, transformed metadata, ELF, Mach-O, processor families other than x86/x64, graphical IDA databases, and native pseudocode decompilation are outside the 1.2 contract.

## Release verification

`scripts/release.ps1` performs a clean Release build, executes the complete CTest suite, stages the plugin with its MCP executable and skills, creates a ZIP archive, and writes a SHA-256 checksum beside it.

The archive includes the project license and all required third-party notices.
