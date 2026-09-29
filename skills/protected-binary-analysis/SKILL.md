---
name: protected-binary-analysis
description: Analyze packing, anti-debugging, self-modifying code, control-flow flattening, opaque predicates, import hiding, and virtualization in binaries the user is authorized to inspect. Use when static code is sparse or misleading, runtime code diverges from disk, or protectors obstruct ordinary debugging. Do not use to bypass licensing, anti-cheat, access controls, or third-party security enforcement.
---

# Protected Binary Analysis

Read [references/protection-model.md](references/protection-model.md) before choosing static unpacking, runtime capture, tracing, or devirtualization.

## Workflow

1. Confirm authorization and preserve the original hash. Run untrusted samples only in an isolated lab with controlled networking and snapshots.
2. Classify observed transformations independently: compression/packing, encryption, anti-debugging, anti-VM, self-modification, control-flow obfuscation, API resolution, or virtualized execution.
3. Prefer reversible static recovery when the packer is positively identified and supports it. Never execute a sample merely to save time.
4. For runtime recovery, define the observation point before running: what event marks stable decoded code, what regions will be captured, and how imports/relocations will be reconstructed.
5. Use write/execute transitions, transfers into newly populated memory, and protection changes as evidence. Snapshot before and after, then diff.
6. Reduce obfuscation semantically: reconstruct CFG, prove opaque predicates, collapse dispatcher state, identify handler semantics, and validate against concrete traces.
7. Keep protector/bootstrap code separate from the protected program and preserve provenance for every dump.

## Output and done

Return protection evidence, hypotheses with confidence, observation points, recovered artifacts and hashes, address rebasing, import/relocation state, unresolved transformations, and validation traces. Completion means the recovered code is internally consistent and behaviorally matches the authorized original for the analyzed path.
