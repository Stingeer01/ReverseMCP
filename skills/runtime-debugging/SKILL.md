---
name: runtime-debugging
description: Debug authorized native Windows processes with minimal perturbation using ReversePlugin events, register contexts, software or hardware breakpoints, single-step, memory inspection, and thread control. Use for crash analysis, runtime value tracing, control-flow validation, and locating writers or callers.
---

# Runtime Debugging

Read [references/debugging-model.md](references/debugging-model.md) for event semantics, breakpoint selection, and reproducibility requirements.

## Workflow

1. State the hypothesis, target module/RVA, triggering input, and expected observation before attaching.
2. Record module bases and thread IDs; never reuse absolute addresses across runs without rebasing.
3. Choose the least perturbing breakpoint that answers the question. Validate software breakpoints on instruction boundaries and hardware data breakpoints for size/alignment.
4. At every stop, capture event type/chance, thread, instruction pointer, relevant registers, bounded memory, and nearby structured disassembly before continuing.
5. Capture `get_stack_trace` at a paused event when caller provenance matters; preserve module-relative frame addresses and symbol displacements.
6. Use single-step only for a small ambiguous transition. Prefer conditional observation points or data breakpoints for hot paths.
6. Pair owned thread suspensions and always detach. Pass unrelated first-chance exceptions to the target unless the analysis specifically requires handling them.

## Output and done

Return a reproducible timeline of observations with module-relative addresses, triggering conditions, state deltas, and the conclusion each event supports. Debugging is complete when the hypothesis is confirmed or falsified without leaving breakpoints, altered bytes, or owned suspensions behind.
