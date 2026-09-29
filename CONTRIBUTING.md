# Contributing

ReverseMCP accepts focused changes that preserve the separation between MCP transport, native backends, and analysis skills.

## Before opening an issue

Search existing issues and the documented 1.0 limitations. Include the server version, Windows version, target architecture, build configuration, and the smallest reproducible input. Do not upload proprietary binaries or memory dumps unless you have the right to distribute them.

Security vulnerabilities should not be filed publicly. Follow [SECURITY.md](SECURITY.md).

## Pull requests

Keep a pull request to one coherent change. Explain the observed behavior, the intended contract, the implementation boundary, and the tests that prove it. New tools need closed JSON Schemas, accurate MCP annotations, backend limits, documentation, and tests for invalid input.

Run before submitting:

```powershell
cmake --preset release
cmake --build --preset release
ctest --preset release
```

The compiler treats warnings as errors. CI runs the same release preset on Windows.

## Compatibility

Tool names, required arguments, response fields, session lifecycles, cache layout, and address conventions are public contracts. Breaking changes require a documented migration and an appropriate version change. Additive optional fields are preferred.

## Knowledge contributions

Engine and protection guidance must distinguish verified facts, version-sensitive assumptions, and heuristics. Cite primary sources wherever possible. Skills must not instruct users to bypass licensing, anti-cheat, access controls, or third-party security enforcement.

## Conduct

Keep discussion technical and direct. Review the repository's [Code of Conduct](CODE_OF_CONDUCT.md) before participating.
