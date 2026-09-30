---
name: cocos2d-x-analysis
description: Analyze authorized Cocos2d-x native games, scene graphs, Ref ownership, scripting bindings, assets, and platform modules. Use when cocos2d-x libraries, cocos2d::Ref, Director, Node, Lua/JavaScript bindings, or Cocos Creator 1.x/2.x native runtimes are involved.
---

# Cocos2d-x Analysis

Read [references/cocos2d-x-model.md](references/cocos2d-x-model.md) before assigning engine types or scripting boundaries.

## Workflow

1. Call `open_engine_workspace` and require a cocos2d native library, directory layout, symbols, or several binary strings before selecting this workflow. A generic Resources directory is not sufficient.
2. Use `list_engine_artifacts` to separate native modules, Lua/JavaScript bytecode or source, shaders, configuration, and assets. Analyze selected PE modules through `open_binary`.
3. Establish the Cocos2d-x or Cocos Creator generation, platform, architecture, renderer, and scripting language. Do not transfer layouts between Cocos2d-x and the incompatible cocos2d-cpp rewrite.
4. Recover `Application`, `Director`, scene, scheduler, event dispatcher, and resource-loading paths before walking nodes.
5. Validate `Ref` ownership and autorelease behavior before retaining runtime pointers. Confirm node class, parent/child structure, and transforms across multiple instances.
6. For Lua or JavaScript games, map registration thunks and binding names to native implementations; keep VM objects and native `Ref` objects as separate identities.

## Output and done

Report engine generation evidence, modules, scripting boundary, scene roots, ownership assumptions, resources, and validated native mappings. Completion requires stable scene/object walks and independently confirmed binding names or call sites.
