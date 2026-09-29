---
name: native-binary-triage
description: Perform evidence-first static triage of authorized PE, ELF, Mach-O, or raw native binaries. Use to identify format, architecture, compiler/runtime, imports, sections, symbols, mitigations, likely packers, and the smallest productive next analysis step.
---

# Native Binary Triage

Read [references/triage-model.md](references/triage-model.md) when interpreting executable-format structures or packing indicators.

## Workflow

1. Hash and identify the exact input before transformation. Preserve provenance for extracted or memory-dumped derivatives.
2. Parse headers and loader metadata before disassembly. For PE inputs, use `open_binary` and `get_binary_index` to preserve RVA-stable sections, imports, exports, ordinals, IAT locations, and forwarders. Record architecture, endianness, image base, entry point, sections/segments, imports/exports, relocations, TLS/init arrays, unwind data, overlays, signatures, and debug identifiers.
3. Infer toolchain/runtime from multiple independent signals: CRT/runtime imports, exception machinery, mangling, language metadata, section conventions, and library fingerprints.
4. Score packing/obfuscation from converging evidence. High entropy alone is insufficient.
5. Build an address map explicitly relating file offset, RVA, VA, and loaded module base.
6. Select a small set of behavioral anchors—entry/init, parsers, dispatchers, allocators, crypto boundaries, engine registration—and follow xrefs/data flow.

## Output and done

Return a structured triage record with hashes, format, architecture, loader map, mitigations, imports/exports, toolchain hypotheses, packing evidence, high-value anchors, uncertainties, and next probes. Triage is done when another analyst can reproduce every claim from the same artifact.
