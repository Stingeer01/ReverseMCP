# Architecture

ReverseMCP separates protocol handling, analysis state, operating-system access, and model guidance. A tool handler can coordinate these layers, but no backend depends on MCP JSON shapes.

## Process model

`reverseplugin-mcp.exe` is a long-running stdio server. The main thread reads one newline-delimited JSON-RPC request at a time, validates the envelope, and dispatches tool calls to a fixed worker pool. Responses carry their original request IDs and may complete out of order.

The debugger is the exception to ordinary worker ownership. Windows requires debugger event waiting and continuation to stay on the thread that attached. Each debug session therefore owns a dedicated event-loop thread and communicates with MCP workers through synchronized commands and event queues.

## Layer ownership

### MCP core

`include/reverseplugin/mcp` defines the stable tool, registry, server, and error interfaces. `src/mcp` owns JSON-RPC validation, lifecycle methods, schema publication, result envelopes, and concurrent response serialization.

A tool returns `std::expected<Json, ToolError>`. Invalid external input is data, not an exception path. Top-level containment prevents an unexpected handler failure from terminating the server.

### Tool adapters

`src/tools` owns names, descriptions, MCP annotations, JSON Schemas, argument parsing, and conversion from domain values to structured JSON. Registration is split by feature group. Duplicate names fail during startup.

### Static analysis

`BinaryImage` validates and owns immutable file bytes plus normalized PE metadata. `BinaryStore` reuses images by canonical path, size, and modification time. Analysis algorithms consume immutable spans and return bounded value objects.

The static index and function analyzer are independent of MCP. They operate on RVAs and only derive virtual addresses from the preferred image base for presentation.

### Process and memory

`ProcessManager` owns reusable Win32 handles through RAII sessions. Access rights are selected by the operation: normal attachment requests query/read access, while write operations still require the target pages themselves to be writable.

Every memory range is checked against `VirtualQueryEx` data before `ReadProcessMemory` or `WriteProcessMemory`. Scans iterate committed readable regions in chunks; they do not allocate a buffer for an entire process range.

### Debugger

`DebugEngine` owns session discovery and lifetime. `DebugContext` owns the event thread, event queue, pending event, breakpoint maps, per-thread debug-register state, and suspend ownership. `StackWalker` isolates DbgHelp setup and frame recovery.

Software breakpoints are state machines, not raw byte writes. On a hit, the engine restores the original byte, rewinds the instruction pointer, enables the trap flag, executes one instruction, handles the single-step event, and reinserts `INT3`.

### Disassembly

The Zydis adapter maps library records to project-owned instruction and operand values. Callers never hold Zydis pointers. Input uses `std::span<const std::byte>`, and decoding is bounded by both bytes and instruction count.

### Skills

Skills are analysis procedures and domain models. They select tools, state invariants, preserve evidence, and identify authoritative sources. They cannot read memory or execute debugger commands on their own. This boundary allows the knowledge layer to evolve without changing the native protocol surface.

## State and identity

There are three independent state scopes:

1. A binary workspace is immutable and identified in-process by `binary_id`; persistent derived data is identified across runs by binary SHA-256.
2. A process session is identified by `session_id` and owns a cached query/read handle.
3. A debugger session is identified by `debug_session_id` and owns target execution state.

Keeping process and debugger sessions separate prevents a read-only inspection from acquiring debugger privileges implicitly. It also makes cleanup explicit.

## Persistent cache

The default root is `%LOCALAPPDATA%/ReversePlugin/analysis-cache-v1`. Each binary hash owns a directory containing versioned derived records and annotations. Cache keys include the analysis inputs that change a deterministic result, such as scan limits or a function start RVA.

Writes use a temporary sibling followed by replacement, so interrupted writes do not expose partial JSON. Cache parsing is treated as untrusted input. A malformed or incompatible record is ignored or reported; it is never allowed to corrupt the live workspace.

The version in `analysis-cache-v1` is a schema boundary. A future incompatible layout must use a new directory or provide an explicit migration.

## Bounded work

Public schemas enforce file size, read length, scan byte count, result count, CFG block count, decoded-byte count, snapshot size, frame count, and wait timeout. Backends repeat these checks instead of trusting the protocol layer. This defense is necessary because the SDK can be called without MCP.

Long operations execute on workers. The input thread remains available for unrelated requests, and the debugger event loop remains available for target events.

## Error model

Expected failures use project error values: invalid arguments, absent sessions, invalid PE structures, inaccessible pages, partial OS operations, decoder failures, resource limits, and invalid debugger state. Tool errors include a stable category, a direct message, and structured details where the caller can act on them.

The server never substitutes partial data where exactness matters. A read that crosses into an invalid page fails. A verified write that reads back different bytes fails. A stack frame without a symbol remains a valid frame with an empty symbol field.

## Extension points

- Add a new MCP tool by implementing `mcp::Tool` and registering it in the relevant tool group.
- Add an analysis primitive below `src/tools` when it has value outside one JSON request.
- Add a loader or instruction architecture behind a domain interface; do not add format branches to MCP handlers.
- Add a skill when the target has a distinct object model, ABI, metadata format, or investigation workflow.
- Add a reference to an existing skill for version-specific layouts or examples.

IL2CPP support follows this model: metadata and registration parsers belong in a native domain module, reusable lookups belong in tools, and version-selection guidance stays in the Unity skill.
