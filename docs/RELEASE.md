# ReverseMCP 1.0 release contract

ReverseMCP 1.0 targets authorized x86/x64 Windows PE analysis. The shipped MCP server provides static PE workspaces, structured Zydis decoding, bounded function and string discovery, direct xrefs, persistent annotations, validated process-memory access, and native Win32 debugging.

## Safety and resource boundaries

- Input files are read-only and capped at 2 GiB.
- String, xref, function, CFG, memory-read, snapshot, and result counts have explicit limits.
- Persistent results are isolated by SHA-256 content identity and written with atomic replacement.
- Runtime writes require writable committed pages and support read-back verification.
- Debug detach restores managed software breakpoints and owned suspensions.
- Addresses are serialized as hexadecimal strings to preserve 64-bit precision.

## Compatibility boundary

The native static loader supports PE32 and PE32+. ELF, Mach-O, processor families other than x86/x64, graphical IDA databases, and native pseudocode decompilation are outside the 1.0 contract. The intended AI workflow uses structured instructions, CFG edges, call graphs, xrefs, register effects, and persistent annotations instead of parsing decompiler prose.

## Release verification

`scripts/release.ps1` performs a clean Release build, executes the complete CTest suite, stages the plugin with its MCP executable and skills, creates a ZIP archive, and writes a SHA-256 checksum beside it.

The archive includes the project license and all required third-party notices.
