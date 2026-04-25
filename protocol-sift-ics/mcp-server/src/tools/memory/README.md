# Memory Analysis Tools (Volatility 3 Wrapper)

This module exposes Volatility 3 plugins to the Protocol SIFT ICS swarm as typed, read-only MCP tool functions.

## Files

| File | Purpose |
|---|---|
| `volatility.ts` | Core wrapper: invocation, validation, allowlist, output spillover |
| `plugins.ts` | Typed wrapper for each individual plugin (vol_pslist, vol_malfind, etc.) |
| `index.ts` | Registration with the MCP server tool registry |

## Why a Wrapper at All?

Volatility 3's `vol` CLI is powerful — it has 80+ plugins, dozens of global flags, and every plugin has its own argument set. Exposing it directly to an LLM agent has three problems:

1. **Argument injection risk.** Even though we use `execFile` (no shell), an LLM might pass a plugin or argument that triggers a write side effect (`vol windows.dumpfiles ...` extracts files).
2. **Output overload.** `vol windows.timeliner` on a real memory dump can return 100+ MB of JSON. An LLM context window cannot absorb that.
3. **Naming variability.** Vol3 plugin names changed across versions (e.g., the `windows.netscan.NetScan` capitalization). The wrapper provides stable names.

This wrapper solves all three:

- **Allowlist** of safe plugins (read-only, no file extraction)
- **Argument validator** rejecting any flag that isn't on a known-safe pattern
- **Output spillover** — large results write to the working directory; the LLM gets a summary + pointer
- **Stable column names** — Vol3's raw column names (`PID`, `ImageFileName`, `LocalAddr`) get normalized to camelCase TypeScript fields

## How a Branch Agent Sees It

The Memory Branch agent calls (via the Tool Broker):

```json
{
  "tool": "vol_pslist",
  "args": { "memory_id": "MEM-001" }
}
```

And gets back:

```json
{
  "executionId": "EXEC-a1b2c3d4-...",
  "plugin": "windows.pslist.PsList",
  "status": "success",
  "rowCount": 87,
  "rowsInline": [
    {
      "pid": 4,
      "ppid": 0,
      "imageFileName": "System",
      "createTime": null,
      ...
    },
    ...
  ]
}
```

The agent never sees the path to the memory image. It never constructs a Volatility command. It never invokes a binary directly. It only calls typed functions with typed parameters.

## Adding a New Plugin

To add support for, say, `windows.svcscan.SvcScan`:

1. **Add to allowlist** in `volatility.ts`:
   ```ts
   "windows.svcscan.SvcScan",
   ```

2. **Add typed wrapper** in `plugins.ts`:
   ```ts
   export interface ServiceRecord { offset: string; pid: number; ... }
   export const VOL_SVCSCAN_SCHEMA = { ... } as const;
   export async function volSvcScan(args, ctx, resolver): Promise<VolatilityResult<ServiceRecord>> {
     const raw = await runVolatilityPlugin<RawSvcScanRow>({...}, ctx, resolver);
     // ... normalize columns ...
   }
   ```

3. **Register in `index.ts`**:
   ```ts
   registry.set("vol_svcscan", {
     name: "vol_svcscan",
     description: "Volatility 3 windows.svcscan — ...",
     inputSchema: VOL_SVCSCAN_SCHEMA,
     execute: (args) => volSvcScan(args as never, ctx, resolver),
   });
   ```

4. **Add to the Memory Branch's allowlist** in `skills/operations/memory-branch/SKILL.md`.

That's it. The wrapper handles invocation, validation, spillover, and audit logging.

## Plugin Inventory (currently wrapped)

| MCP Name | Vol Plugin | Purpose |
|---|---|---|
| `vol_info` | `windows.info.Info` | OS metadata for the memory image |
| `vol_pslist` | `windows.pslist.PsList` | Active processes (EPROCESS walk) |
| `vol_pstree` | `windows.pstree.PsTree` | Process tree with parent/child relationships |
| `vol_psscan` | `windows.psscan.PsScan` | Pool-tag scan for hidden processes |
| `vol_cmdline` | `windows.cmdline.CmdLine` | Process command lines |
| `vol_malfind` | `windows.malfind.Malfind` | Process injection detection |
| `vol_netscan` | `windows.netscan.NetScan` | Network connections from memory |

The Memory Branch SKILL.md declares the full set of plugins it may call (32 listed). Plugins beyond the seven wrapped here are pending implementation — the wrapper pattern is uniform, so each one is a 30-line addition.

## Testing

Unit tests for validation and parsing logic (no Vol required):

```bash
npm run test:unit
```

End-to-end tests requiring a real memory capture live in `test/accuracy/test-cases/`.

## Reference

- Volatility 3 documentation: https://volatility3.readthedocs.io/en/stable/
- Plugin source: https://github.com/volatilityfoundation/volatility3
- Output renderer reference: https://volatility3.readthedocs.io/en/stable/volatility3.cli.text_renderer.html
