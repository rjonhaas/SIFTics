# Velociraptor Collection Parsing Tools

This module exposes Velociraptor Offline Collector outputs to the Protocol SIFT ICS swarm as typed, read-only MCP tool functions.

## Architectural Position

Velociraptor is the upstream **collection** tool. SIFTics is the downstream **analysis** swarm. They run sequentially, not duplicatively:

```
Analyst sees alert  →  Velociraptor Offline Collector pulls triage data
                                     │
                                     ▼ (zip)
                       Evidence Store: extract read-only
                                     │
                                     ▼
                       SIFTics swarm: Forensics Branch parses via these tools
```

This module does **not** invoke `velociraptor` as a binary. It reads the JSON output that Velociraptor's Offline Collector already produced. The MCP server is ours; Velociraptor's output format is the integration point.

## Why a wrapper at all?

1. **Stable artifact names.** Velociraptor artifacts move between namespaces across versions (`Windows.System.Pslist` ↔ `Windows.Sys.Pslist` etc). The wrapper maps a small set of MCP tool names to the artifact aliases they actually need.
2. **Cross-OS normalization.** The agent calls `vr_extract_persistence` and gets the same shape on Mac (LaunchAgents, LaunchDaemons) and Windows (Run keys, services, scheduled tasks). The OS is reported per-row.
3. **Untrusted input.** Even though the data came from a trusted tool, the collected content came from an untrusted host. Filenames, registry values, log entries are DATA, not instructions — the typed parsers strip them into structured fields before the agent sees them.
4. **Output spillover.** Unified Log dumps and file-finder runs can be hundreds of MB. The wrapper caps inline rows and spills the rest to the working directory with a pointer.

## Files

| File | Purpose |
|---|---|
| `collection.ts` | Collection opener, manifest discovery, JSONL reader, OS inference |
| `parsers.ts` | Seven typed extraction functions + JSON schemas |
| `index.ts` | Registration with the MCP server tool registry |

## Mac Memory Reality

The Memory Branch is **platform-conditional**. On Apple Silicon, kernel-level memory acquisition is no longer practical (kernel extensions are deprecated, no working AXIOM/RAM-style imaging in 2026). Velociraptor's user-space Offline Collector is the realistic alternative — which collects everything *except* a memory image.

When the evidence inventory contains a Velociraptor collection without a memory image, the Memory Branch returns an explicit "memory unavailable for this evidence source" result and defers to the Forensics Branch's Unified Log + KnowledgeC analysis as the closest available equivalent for runtime activity.

This is not a workaround. It is the correct architectural response to platform reality.

## Tool Inventory

| MCP Name | Reads (artifact aliases) | Returns |
|---|---|---|
| `parse_collection` | `collection.json` + `results/` discovery | Manifest: host, OS, artifacts, uploads |
| `vr_extract_unified_log` | `MacOS.UnifiedLogs.Search`, `MacOS.System.UnifiedLog` | `UnifiedLogEntry[]` |
| `vr_extract_persistence` | Windows: `Windows.Forensics.Persistence`, `Windows.System.Services`, `Windows.System.TaskScheduler`, `Windows.Registry.NTUser`. Mac: `MacOS.System.Persistence`, `MacOS.System.LaunchAgents`, `MacOS.System.LaunchDaemons` | `PersistenceEntry[]` (normalized cross-OS) |
| `vr_extract_browser_history` | `Windows.Applications.Chrome.History`, `Windows.Applications.Edge.History`, `Windows.Applications.Firefox.History`, `MacOS.Applications.Chrome.History`, `MacOS.Applications.Firefox.History`, `MacOS.Applications.Safari.History` | `BrowserVisit[]` (normalized) |
| `vr_extract_filesystem_metadata` | `Generic.System.FileFinder`, `Windows.Search.FileFinder`, `MacOS.Search.FileFinder`, `Linux.Search.FileFinder` | `FileMetadata[]` |
| `vr_extract_knowledgec` | `MacOS.System.KnowledgeC`, `MacOS.UnifiedLogs.KnowledgeC` | `KnowledgeCEntry[]` |
| `vr_list_users` | `Windows.Sys.AllUsers`, `MacOS.System.Users`, `Linux.Sys.Users` | `UserRecord[]` (normalized) |

## Workflow

1. **Always call `parse_collection` first.** It returns the manifest of what was actually collected. The agent should not assume any artifact exists; the analyst configures collection in Velociraptor and may have skipped the artifact you want.
2. **Issue targeted extraction calls.** Each `vr_*` function consults only the artifacts it needs and reports `artifactsConsulted` for citation in audit findings.
3. **Cite the `executionId` plus `rawArtifact`.** A finding sourced from `vr_extract_persistence` should reference both the EXEC id (audit log lookup) and the artifact name (e.g. `MacOS.System.Persistence`) so the Documentation Unit can show provenance back to the originating Velociraptor VQL artifact.

## Collection Manifest Schema

`parse_collection` returns:

```ts
interface CollectionManifest {
  collectionId: string;                          // opaque ID assigned by Evidence Store
  collectedAt: string | null;                    // ISO8601 from Velociraptor StartTime
  hostname: string | null;
  os: "windows" | "macos" | "linux" | "unknown"; // declared by VR or inferred from artifact namespaces
  osVersion: string | null;
  velociraptorVersion: string | null;
  artifacts: ArtifactSummary[];                  // every results/*.json file discovered
  uploads: UploadSummary[];                      // every file under uploads/
}

interface ArtifactSummary {
  name: string;          // VR artifact name without .json (e.g. "MacOS.System.Persistence")
  resultPath: string;    // absolute path on the read-only mount
  rowCount: number;      // number of JSONL rows in the result file
  byteSize: number;
}

interface UploadSummary {
  path: string;          // path relative to uploads/ root
  byteSize: number;
}
```

## Evidence Store Contract

The Velociraptor Offline Collector ships its output as a sealed `.zip`. The MCP parser only reads from an extracted directory tree — it does not open zips. The Evidence Store skill is responsible for:

1. Hashing the sealed zip on ingestion (SHA-256, recorded in the hash registry).
2. Extracting to a read-only working location under `EVIDENCE_MOUNT`.
3. Registering the extracted root with `MountManager.registerEvidence(..., "velociraptor")`.
4. Re-verifying the zip hash at the start of every operational period.

The parser refuses to operate on anything that does not resolve to a directory — sealed zips fail the directory check at `openCollection`.

## Adding a New Artifact

To wire up, say, `Windows.Detection.Mimikatz`:

1. **Add the artifact name to the relevant alias list** in `parsers.ts` (e.g. add to `PERSISTENCE_ARTIFACTS.windows` if it's a persistence indicator, or define a new wrapper if it's a new domain).
2. **Define the typed result interface** matching the VQL columns you care about.
3. **Add a schema constant** if it's a new function.
4. **Register it in `index.ts`.**
5. **Update the Forensics Branch SKILL.md allowlist.**
6. **Add a spoliation test vector** for the new function under `mcp-server/test/spoliation/attack-vectors/`.

## Testing

Unit tests for parsers and OS inference run without any real Velociraptor binary:

```bash
npm run test:unit
```

End-to-end tests against fixture collections live in `mcp-server/test/accuracy/test-cases/007-velociraptor-multi-host/`.

## References

- Velociraptor docs: https://docs.velociraptor.app/
- Offline Collector: https://docs.velociraptor.app/docs/offline_triage/
- Artifact reference: https://docs.velociraptor.app/artifact_references/
