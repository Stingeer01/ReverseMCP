# CRYENGINE analysis model

## Stable anchors

- `system.cfg` can select the game folder and game DLL. Treat these values as configuration evidence, not proof that the referenced module loaded successfully.
- `gEnv` connects major engine subsystems, but its concrete layout and interface vtables vary by generation, compiler, and licensee changes.
- CryPak presents both loose files and PAK contents through one file-system boundary. Preserve load order and source provenance when duplicate virtual paths exist.
- Legacy GameSDK, entity components, Schematyc, Flow Graph, and modern plugins require separate version-aware models.

## Validation

- Match public source or headers to the closest supported engine tag before assigning interface slots.
- Confirm subsystem pointers through initialization xrefs and multiple virtual calls.
- Confirm entity/component fields on more than one live instance before naming offsets.
- Do not interpret signed or encrypted PAK contents without authorized keys and a validated format implementation.

## Primary references

- CRYENGINE directory and GameSDK layout: https://www.cryengine.com/docs/static/engines/cryengine-3/categories/1638401/pages/1605746
- Engine API and `gEnv` subsystems: https://www.cryengine.com/docs/static/engines/cryengine-5/categories/23756813/pages/26874885
- Console variables and configuration files: https://www.cryengine.com/docs/static/engines/cryengine-5/categories/23756816/pages/25535264
