# Cocos2d-x analysis model

## Boundaries

- Cocos2d-x is a C++ engine with optional Lua and JavaScript bindings. A native build may link the engine statically, so the absence of a standalone cocos2d DLL does not exclude it.
- `Ref` uses intrusive reference counting and autorelease pools. A readable pointer is not evidence that an object remains live after the current frame.
- Scene graph identity, rendering state, scheduler callbacks, and VM wrapper identity are distinct even when they refer to the same gameplay object.
- Cocos Creator 1.x/2.x uses Cocos2d-x as a native foundation but adds its own JavaScript runtime and generated bindings.

## Validation

- Establish a version from symbols, source paths, binding names, or several characteristic strings before transferring types.
- Confirm `Director` and scene roots through callers and repeated runtime observations.
- Validate `Ref` fields and virtual slots against target-build code, not a current upstream checkout.
- Identify bytecode and packaged scripts by signature before assuming source encoding.

## Primary references

- Official Cocos2d-x source and architecture summary: https://github.com/cocos2d/cocos2d-x
- Cocos2d-x v4 Windows documentation: https://docs.cocos.com/cocos2d-x/v4/manual/en/installation/Windows.html
