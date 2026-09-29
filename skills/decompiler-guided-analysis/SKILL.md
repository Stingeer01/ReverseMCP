---
name: decompiler-guided-analysis
description: Recover trustworthy semantics from disassembly and decompiler output in authorized native binaries. Use for function boundaries, calling conventions, types, structures, vtables, indirect calls, data flow, control flow, compiler artifacts, or disagreements between IDA, Ghidra, Binary Ninja, and raw instructions.
---

# Decompiler-Guided Analysis

When IDA is unavailable, use `discover_binary_functions` as the function/call-graph index and `analyze_binary_function` as the structured IR presented to the model. Prefer operands, register effects, CFG edges, and xrefs over reconstructing meaning from formatted assembly. Persist confirmed names, comments, and type declarations with `set_binary_annotation`.

Read [references/semantic-recovery.md](references/semantic-recovery.md) for the validation hierarchy and common compiler artifacts.

## Rules

- Machine bytes and architecture semantics outrank rendered assembly; rendered assembly outranks decompiler syntax.
- Treat types, variable names, function boundaries, calling conventions, switch recovery, and stack analysis as hypotheses until cross-validated.
- Rename only from evidence and include semantic role over guessed source spelling.
- Apply types incrementally. A wrong early prototype can corrupt the entire decompilation graph.

## Workflow

1. Establish function entry/exit and reachable basic blocks from direct control flow, unwind data, symbols, call targets, and runtime traces.
2. Recover ABI: arguments, return values, preserved registers, stack alignment, hidden parameters, variadic behavior, and exception/unwind obligations.
3. Build a data-flow ledger for important values: definition, transformations, aliases, memory base/index/scale, consumers, and observed runtime values.
4. Infer structures from repeated offset/type/use patterns across several functions. Separate inheritance/vtables from composition and callbacks.
5. Resolve indirect calls through points-to evidence, vtable slots, jump tables, imports, callbacks, or runtime targets.
6. Compare decompiler output to structured disassembly whenever casts, signedness, shifts, flags, intrinsics, atomics, or undefined behavior affect the conclusion.

## Done

Produce a call/data-flow narrative, normalized prototypes, recovered types with confidence, unresolved alternatives, and exact addresses supporting each major conclusion.
