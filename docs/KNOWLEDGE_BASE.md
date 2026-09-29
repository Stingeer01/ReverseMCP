# ReverseMCP knowledge base

The knowledge layer is organized as small composable skills rather than a single universal prompt. This keeps engine-specific layouts out of unrelated analysis and makes version assumptions visible.

## Design criteria

- Evidence first: claims retain hashes, exact addresses, module bases, tool versions, and confidence.
- Loader and runtime semantics outrank decompiler presentation.
- Static analysis precedes execution of unknown code; dynamic work starts from an explicit hypothesis and observation point.
- Engine layouts are version-sensitive and must be validated against runtime invariants or matching source tags.
- Skills never imply permission to bypass licensing, anti-cheat, access controls, or third-party security enforcement.
- Every workflow defines a reproducible completion condition instead of stopping at plausible-looking pseudocode.

## Research basis

The structure was informed by public agent-skill collections that emphasize focused composition, evidence traceability, static-first work, validation, and clear safety boundaries:

- https://github.com/hackersifu/reverse-engineering-skills
- https://github.com/th3vib3coder/RevEng
- https://github.com/meltedinhex/analyst-ai-pack

Technical content is original and anchored primarily to vendor documentation, format specifications, upstream engine source, and the official repositories listed in each skill reference.

## Extension policy

Add a new skill when the target has a genuinely different object model, metadata format, ABI, or investigative workflow. Add a reference to an existing skill when the difference is version- or mode-specific. Keep executable mechanics in MCP tools and analytical decisions in skills.
