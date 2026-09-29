---
name: managed-runtime-analysis
description: Analyze authorized .NET Framework, CoreCLR, Mono, ReadyToRun, single-file, trimmed, and NativeAOT applications. Use for CLI metadata, IL, assemblies, MethodDesc, JIT/AOT code, reflection, generics, managed/native boundaries, or Unity Mono investigations; use unity-il2cpp-analysis instead for IL2CPP.
---

# Managed Runtime Analysis

Read [references/managed-model.md](references/managed-model.md) to distinguish IL, JIT, ReadyToRun, Mono AOT, and NativeAOT artifacts.

## Workflow

1. Classify runtime and deployment model before selecting tools: .NET Framework/CoreCLR, Mono, ReadyToRun, single-file, trimmed, or NativeAOT.
2. Parse CLI metadata tables, heaps, tokens, signatures, method bodies, resources, and assembly references before native disassembly when IL survives.
3. Preserve the distinction between metadata token, method definition, generic instantiation, runtime descriptor, precode/stub, and active native code address.
4. At runtime, account for tiered compilation, rejitting, generic sharing, delegates, reflection, P/Invoke, reverse P/Invoke, and GC movement.
5. For AOT, locate runtime-specific headers/maps and validate native mappings against metadata; do not assume every method retains IL or a unique body.
6. Treat trimming as absence by reachability policy, not obfuscation by default.

## Output and done

Report runtime/deployment evidence, assemblies/modules, metadata identities, IL/native mappings, generic/shared code, interop boundaries, and uncertainty. Completion requires stable identity across token/name/signature and observed implementation address.
