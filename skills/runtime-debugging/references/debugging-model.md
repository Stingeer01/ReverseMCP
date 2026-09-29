# Runtime debugging model

## Breakpoint choice

- Software execute breakpoint: scalable and precise, but modifies one code byte and requires restore/rewind/trap/reinsert handling.
- Hardware execute/data breakpoint: no code patch; per-thread, four slots, data width/alignment constraints.
- Page/guard monitoring: broad range observation with page granularity and rearm requirements.
- Instrumentation/tracing: high coverage with higher overhead and changed timing.

## Windows event semantics

- The debugger owns a pending debug event until `ContinueDebugEvent`.
- First-chance exceptions are offered before application handlers. Second-chance means no application handler accepted the exception.
- Breakpoint and single-step state belongs to the event thread. Other threads may still matter for shared data and breakpoint configuration.
- A software breakpoint reports after `INT3`; correct continuation restores the byte, rewinds IP, trap-steps the original instruction, then reinserts.
- Debug registers are thread-local. New threads do not inherit a breakpoint policy automatically.

## Evidence capture

Use module-relative addresses, not only VAs. Capture enough bytes to reproduce disassembly, exact pointer-chain hops, breakpoint ID/type, thread ID, register subset, timestamps where timing matters, and before/after memory for mutations.

## Primary references

- Debug events: https://learn.microsoft.com/windows/win32/debug/debugging-events
- Exception handling: https://learn.microsoft.com/windows/win32/debug/debugger-exception-handling
- Thread context: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext
- x64dbg hardware breakpoints: https://help.x64dbg.com/en/latest/commands/breakpoint-control/SetHardwareBreakpoint.html
