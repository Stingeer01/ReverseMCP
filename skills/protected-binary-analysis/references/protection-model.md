# Protection analysis model

## Packing and runtime recovery

- Verify known packers through structural fingerprints plus stub behavior. For standard UPX, test/list before using the official decompressor on trusted samples.
- A runtime dump is not automatically a valid executable. Track image base, committed regions, original section boundaries, relocations, imports, exception metadata, TLS, and the actual transfer point.
- Prefer capture after bulk decoding and import resolution but before destructive cleanup. Multiple stages may exist.
- Treat RW→RX/RWX changes and execution from private memory as signals; JIT engines and legitimate runtimes produce similar behavior.

## Anti-analysis classification

- Debugger-state queries, timing, exception behavior, parent/process/window enumeration, breakpoints checks, debug-register checks, and integrity checks need individual evidence.
- Do not globally patch every check. Isolate a check's inputs and downstream branch, then determine whether observation or minimal controlled neutralization is necessary.
- First-chance exceptions may be deliberate control flow. Passing or consuming the wrong event changes program semantics.

## Obfuscation and virtualization

- Flattening: recover dispatcher variable, state updates, case targets, and real edges. Reconstruct a normalized CFG before naming behavior.
- Opaque predicates: prove with constants/data-flow, symbolic constraints, or repeated traces; never remove because a branch “looks dead.”
- Virtual machines: identify VM entry, bytecode boundaries, virtual PC/state, dispatcher, handlers, operand decoding, and exit. Summarize handlers as state transformations, then lift traces to a small IR.
- Mixed-mode protectors may virtualize only selected functions. Avoid extrapolating one handler set globally.

## Instrumentation choices

- Hardware breakpoints avoid code modification but provide four per-thread slots.
- Guard/page monitoring scales by page and may report only first access until rearmed.
- Dynamic binary instrumentation gives coverage at higher perturbation and overhead; compare traces when anti-instrumentation is suspected.

## Primary references

- UPX: https://github.com/upx/upx
- Windows debugger exception model: https://learn.microsoft.com/windows/win32/debug/debugger-exception-handling
- x64dbg conditional breakpoints: https://help.x64dbg.com/en/latest/introduction/ConditionalBreakpoint.html
- Frida Stalker: https://frida.re/docs/stalker/
- Frida memory monitoring: https://frida.re/docs/javascript-api/#memoryaccessmonitor
- DynamoRIO: https://dynamorio.org/page_docs.html
