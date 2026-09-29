# Tool reference

ReverseMCP 1.0 exposes 40 MCP tools. Names and schemas are part of the public interface. The exact input and output schemas returned by `tools/list` take precedence over this human-readable guide.

## Common conventions

- Use `0x`-prefixed strings for addresses. Responses always encode addresses as hexadecimal strings so 64-bit values survive JSON and model conversions.
- `binary_id` identifies an immutable static-analysis workspace returned by `open_binary`.
- `session_id` identifies a read-only process session returned by `attach_process`.
- `debug_session_id` identifies a debugger session returned by `debug_attach`.
- IDs are local to one server process and become invalid after their corresponding close or detach call.
- Static results use RVAs as stable identities and include virtual addresses where useful.
- Every request rejects unknown properties. Limits are enforced before expensive work begins.

## Server

### `get_server_info`

Returns the server version, transport, execution model, and compiled feature modules. It takes no arguments and is safe to use as a capability probe.

## Static binary lifecycle

### `open_binary`

Opens a PE32 or PE32+ executable or DLL without executing it. The input is `path`. The response includes `binary_id`, architecture, image base, entry point, sections, imports, exports, and a SHA-256 fingerprint. An unchanged image already held by the server is reused.

Files are read-only and limited to 2 GiB. Invalid DOS, NT, optional, section, import, export, or mapping data produces a structured error.

### `close_binary`

Releases an in-memory workspace by `binary_id`. Fingerprinted persistent results remain on disk and can be reused when the same content is opened later.

### `get_binary_index`

Pages through normalized `sections`, `imports`, or `exports`. `offset` defaults to 0 and `limit` defaults to 256 with a maximum of 4096. Import records include library, name or ordinal, and IAT location. Export records include name, ordinal, RVA, and forwarder where present.

## Static reads and navigation

### `read_binary_bytes`

Reads exact file-backed bytes by RVA or virtual address. A call is capped at 1 MiB and fails when the requested range is not backed by the file.

### `disassemble_binary`

Decodes file-backed x86/x64 code with Zydis. `max_bytes` defaults to 4096 and is capped at 1 MiB; `max_instructions` defaults to 256 and is capped at 65,536. Each instruction contains exact bytes, formatted text, mnemonic, structured operands, semantic category, branch type, relative target, and read/write register sets where available.

### `scan_binary_pattern`

Searches file-backed sections for a space-separated AOB signature such as `48 8B ?? ?? 89`. `?` and `??` are byte wildcards. Results include section identity, RVA, and virtual address. Set `executable_only` to exclude data sections. Result count is capped at 65,536.

### `find_binary_strings`

Indexes printable ASCII and UTF-16LE strings in readable sections. `minimum_length` defaults to 4. `max_scan_bytes` defaults to 64 MiB and is capped at 512 MiB; `max_results` defaults to 10,000 and is capped at 100,000. Results include encoding, byte length, RVA, and virtual address. Deterministic results can be loaded from the persistent cache.

### `find_binary_xrefs`

Scans executable sections with Zydis for direct calls, jumps, immediate references, and RIP-relative data references to a target RVA or virtual address. The default scan budget is 64 MiB and the maximum is 512 MiB. Results are classified rather than returned as formatted assembly text.

## Static function analysis

### `discover_binary_functions`

Builds a bounded function index from the PE entry point, exports, x64 unwind records, and recursively reached direct calls. The default limits are 10,000 functions and 64 MiB of decoded instructions; hard limits are 100,000 functions and 512 MiB. Each function records its discovery provenance, CFG metrics, and direct call edges.

### `analyze_binary_function`

Recovers a bounded control-flow graph from an RVA or virtual address. It returns basic blocks, structured instructions, typed fallthrough/conditional/unconditional edges, and direct call references. Defaults are 1024 blocks and 64 KiB of decoded bytes; hard limits are 4096 blocks and 1 MiB. Deterministic results are cached by binary content hash.

### `set_binary_annotation`

Sets an analyst name, comment, or type expression at an address. Empty fields clear their individual values; `remove: true` removes the complete record. Names are limited to 1024 characters, type expressions to 4096, and comments to 65,536. This tool modifies ReverseMCP's analysis cache, not the binary.

### `get_binary_annotations`

Returns paged annotations for the exact binary SHA-256. The default page size is 1000 and the maximum is 10,000.

## Process lifecycle and memory map

### `list_processes`

Returns PID, parent PID, thread count, and executable name. `name_contains` applies a case-insensitive filter before the bounded result is returned. `limit` defaults to 100 and is capped at 1000.

### `attach_process`

Opens a reusable process session from a PID. The handle requests query and memory-read rights only. This does not start a debugger and does not modify the target.

### `detach_process`

Invalidates a read-only session and releases its cached Windows handle. Work that already holds a shared session reference can finish safely.

### `list_modules`

Lists executable images and DLLs in an attached process with module name, path, base address, and image size.

### `query_memory_regions`

Walks the virtual address space from an optional starting address. `max_regions` defaults to 64 and is capped at 512. Each record includes range, allocation state, type, native protection, and normalized readable/writable/executable flags.

## Runtime reads, writes, and scans

### `read_memory`

Reads an exact range from an attached process. Calls are capped at 65,536 bytes. Every covered region must be committed, readable, and unguarded; partial or cross-boundary invalid reads fail instead of returning ambiguous data.

### `write_memory`

Writes up to 65,536 bytes expressed as contiguous hexadecimal. The complete range must already be committed and writable. Page protection is never changed. The response includes previous bytes, and `verify` defaults to true for a read-back comparison.

### `read_pointer_chain`

Dereferences the current address, then adds the corresponding signed offset at every hop. It supports up to 64 offsets and `auto`, 32-bit, or 64-bit pointer widths. The response includes every intermediate pointer and computed address so a failed chain can be diagnosed.

### `scan_memory_pattern`

Scans readable committed memory for an AOB signature. A single request covers at most 256 MiB and returns at most 4096 matches. Work is performed in bounded chunks while preserving matches that span chunk boundaries. `executable_only` restricts the scan to readable executable pages.

### `disassemble_memory`

Reads and decodes live x86/x64 code. Decoder mode can follow the target architecture or be selected explicitly. Intel and AT&T formatting are available; structured operands do not depend on display syntax. One call returns at most 512 instructions.

## Typed memory snapshots

### `create_memory_snapshot`

Captures up to 64 MiB of readable memory as candidates of type `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`, `f32`, or `f64`. Natural alignment advances by the value width; packed mode tests every byte offset.

### `compare_memory_snapshot`

Compares current memory with the previous typed baseline using `changed`, `unchanged`, `increased`, or `decreased`. The total candidate count is always reported; at most 4096 candidate details are returned. With `refine: true`, non-matching candidates are discarded and current values become the next baseline.

### `delete_memory_snapshot`

Deletes a snapshot and immediately releases its bounded server-side storage.

## Debugger lifecycle and execution

### `debug_attach`

Starts a native Windows debugger session for an x86 or x64 process. A dedicated thread owns event waiting and continuation. The target is configured to remain alive if the MCP server exits.

### `debug_detach`

Restores managed software breakpoints, unwinds thread suspensions owned by the session, continues a pending event when required, and detaches without terminating the target.

### `wait_debug_event`

Waits for the next queued debugger event for up to `timeout_ms`, which defaults to 1000 and is capped at 30,000. The MCP input loop remains available while the worker waits. Breakpoint and exception events leave the target paused.

### `continue_debug_event`

Continues the current event. `handled` defaults to true; set it to false to pass an unknown exception to the target. Managed software-breakpoint continuation performs the required original-byte restore, instruction-pointer rewind, trap-step, and `INT3` reinsertion.

### `single_step`

Executes exactly one instruction in the thread that produced the paused event and waits for the resulting step event. Software-breakpoint state is preserved correctly.

## Breakpoints and threads

### `set_software_breakpoint`

Installs a managed `INT3` at an executable address and returns a breakpoint ID. The original instruction byte is retained by the session.

### `remove_breakpoint`

Removes a managed software breakpoint and restores the original byte. Repeated removal reports that the breakpoint was already absent.

### `set_hardware_breakpoint`

Configures one of the four per-thread x86/x64 debug-register slots. Access can be `execute`, `write`, or `read_write`; size is 1, 2, 4, or 8 bytes. Execute breakpoints require size 1. Data breakpoints require natural address alignment. Omit `slot` to use the first free DR0–DR3 slot.

### `remove_hardware_breakpoint`

Clears the identified hardware breakpoint and releases its slot.

### `list_debug_threads`

Lists thread identifiers and base priorities for the debug target. These IDs are used for per-thread contexts, suspension, and hardware breakpoints.

### `suspend_debug_thread`

Increments a thread's suspend count and records ownership in the debugger session. Detach can therefore undo only suspensions created through ReverseMCP.

### `resume_debug_thread`

Releases one suspension owned by the current debugger session. It refuses to alter suspend counts it does not own.

### `get_thread_context`

Returns integer and control registers while the target is paused. Omit `thread_id`, or pass 0, to select the thread that produced the current event.

### `get_stack_trace`

Walks a paused thread through Windows unwind metadata and DbgHelp symbols. The default is 64 frames and the maximum is 256. Frames include instruction, stack, and frame pointers, module base and name, resolved symbol, and displacement where available.

## Mutability summary

Most tools are read-only. The operations with side effects are:

- `set_binary_annotation`, which changes the local content-addressed analysis cache;
- `write_memory`, which changes already writable target memory;
- debugger attach/detach, breakpoint, execution, and thread-control tools, which change target execution state;
- lifecycle close, detach, and snapshot deletion tools, which release server-side resources.

MCP annotations expose read-only, destructive, idempotent, and open-world hints so compatible clients can apply their own approval policy.
