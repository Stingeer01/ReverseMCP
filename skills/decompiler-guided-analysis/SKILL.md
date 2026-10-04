---
name: decompiler-guided-analysis
description: Recover trustworthy semantics from disassembly and decompiler output in authorized native binaries. Use for function boundaries, calling conventions, types, structures, vtables, indirect calls, data flow, control flow, compiler artifacts, or disagreements between IDA, Ghidra, Binary Ninja, and raw instructions.
---

# Decompiler-Guided Analysis

When IDA is unavailable, use `discover_binary_functions` as the function/call-graph index and `decompile_binary_function` as the first semantic view. Read SSA uses and definitions, phi nodes, memory alias sets, control regions, type evidence, and field evidence before relying on rendered pseudocode. Treat `exact` statements as lifted ISA semantics, validate `inferred` and `partial` statements against their address-linked source instructions, and inspect every `unmodeled` intrinsic through `analyze_binary_function` or `disassemble_binary`. Persist confirmed names, comments, and type declarations with `set_binary_annotation`; cached decompilations receive the latest annotation overlay.

Read [references/semantic-recovery.md](references/semantic-recovery.md) for the validation hierarchy and common compiler artifacts.

## Rules

- Machine bytes and architecture semantics outrank rendered assembly; rendered assembly outranks decompiler syntax.
- Treat types, variable names, function boundaries, calling conventions, switch recovery, and stack analysis as hypotheses until cross-validated.
- Rename only from evidence and include semantic role over guessed source spelling.
- Apply types incrementally. A wrong early prototype can corrupt the entire decompilation graph.

## Workflow

1. Establish function entry/exit and reachable basic blocks from direct control flow, unwind data, symbols, call targets, and runtime traces. Start with `decompile_binary_function`; never hide truncation or unresolved intrinsics.
2. Recover ABI: arguments, return values, preserved registers, stack alignment, hidden parameters, variadic behavior, and exception/unwind obligations.
3. Build a data-flow ledger for important values from SSA versions and phi inputs: definition, transformations, aliases, memory alias set, base/index/scale, consumers, and observed runtime values. Treat `memory:unknown` as may-alias rather than a distinct object.
4. Infer structures from repeated offset/type/use patterns across several functions. Separate inheritance/vtables from composition and callbacks.
5. Resolve indirect calls through points-to evidence, vtable slots, jump tables, imports, callbacks, or runtime targets.
6. Compare decompiler output to structured disassembly whenever casts, signedness, shifts, flags, intrinsics, atomics, or undefined behavior affect the conclusion.

## Done

Produce a call/data-flow narrative, normalized prototypes, recovered types with confidence, unresolved alternatives, and exact addresses supporting each major conclusion.
