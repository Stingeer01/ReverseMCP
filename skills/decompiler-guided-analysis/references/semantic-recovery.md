# Semantic recovery reference

## Validation hierarchy

1. Bytes and ISA semantics.
2. Loader/runtime metadata: relocations, imports, unwind, RTTI, symbols.
3. Cross-function consistency and call-site ABI.
4. Dynamic observations under controlled inputs.
5. Decompiler output and inferred types.

Decompiler output is valuable compression of evidence, not source recovery.

## Common distortions

- Tail calls and thunk chains mistaken for ordinary calls.
- Inlined constructors/destructors, templates, allocators, and security checks obscuring the core behavior.
- Split or merged variables from register allocation and SSA recovery.
- Wrong signedness, width, enum, pointer level, or calling convention.
- Jump tables, exception landing pads, and non-returning calls producing false edges.
- SIMD/vectorized loops rendered as noisy scalar pseudocode.

## Type recovery invariants

- Field offset consistency across accesses.
- Access width and signedness.
- Constructor initialization order and destructor ownership.
- Array stride, count/capacity relationships, pointer validity, and alignment.
- Vtable slot consistency across derived instances.
- Atomic/volatile access patterns and synchronization context.

## Primary references

- Zydis: https://github.com/zyantific/zydis
- Ghidra source/decompiler: https://github.com/NationalSecurityAgency/ghidra
- Ghidra SLEIGH/p-code docs: https://ghidra.re/ghidra_docs/languages/index.html
- Microsoft x64 ABI: https://learn.microsoft.com/cpp/build/x64-calling-convention
- System V AMD64 ABI: https://gitlab.com/x86-psABIs/x86-64-ABI
