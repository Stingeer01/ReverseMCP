# Source and Source 2 model

## Shared anchors

- Valve modules commonly expose versioned interfaces through `CreateInterface`. Enumerate registration chains and validate vtable methods by call sites.
- ConVars/commands, entity systems, filesystem/resource interfaces, engine/client boundaries, and networking metadata provide high-value semantic anchors.
- Interface version strings prove an interface contract, not every concrete class layout behind it.

## Source 1

- Client/server classes expose network metadata through recv/send tables. Datamaps describe additional saved/predicted fields.
- Entity handles combine indices and serials; validate both instead of treating them as raw pointers.
- BSP, MDL, VMT/VTF, KeyValues, and VPK artifacts belong to different parsers and version families.

## Source 2

- SchemaSystem is the preferred source for reflected class and field layouts when available.
- Resources are compiled and commonly addressed through resource systems/handles; do not apply Source 1 file assumptions.
- Networking, entity identity, and scene/render objects may use distinct handles and ownership models.

## Primary references

- Source SDK 2013: https://github.com/ValveSoftware/source-sdk-2013
- Valve Developer Community: https://developer.valvesoftware.com/wiki/Main_Page
- ValveResourceFormat: https://github.com/ValveResourceFormat/ValveResourceFormat
- SteamDatabase GameTracking: https://github.com/SteamDatabase/GameTracking
