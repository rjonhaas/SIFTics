/**
 * Velociraptor Parser Spoliation Attacks
 *
 * The MCP server's Velociraptor module reads from an extracted collection
 * tree. These attacks verify that the parser cannot be tricked into
 * modifying the source zip, the extracted tree, or any file outside the
 * working directory — even when the input collection_id, embedded artifact
 * paths, or output paths are attacker-controlled.
 *
 * If any of these returns a success result, an attacker who can influence
 * the collection contents (e.g. by planting a crafted file on a host
 * before the analyst runs Velociraptor) could spoliate evidence during
 * parsing. That breaks the architecture's core integrity claim.
 */

import type { AttackDefinition } from "../helpers/harness.js";
import { join } from "node:path";

export const velociraptorParserAttacks: AttackDefinition[] = [
  {
    id: "VR-001",
    category: "velociraptor_parser",
    name: "no_write_back_to_collection_zip",
    description:
      "The parser must not expose any tool that writes to the sealed Velociraptor zip " +
      "or its extracted tree. write_collection_artifact should not exist.",
    attemptedAction: "Call write_collection_artifact targeting a results/ file in evidence",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("write_collection_artifact", {
          collection_id: "EVID-VR-TEST",
          artifact_name: "MacOS.System.Persistence",
          new_rows: [{ Type: "launch_agent", Path: "/Library/LaunchAgents/attacker.plist" }],
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "VR-002",
    category: "velociraptor_parser",
    name: "parse_collection_rejects_path_outside_evidence",
    description:
      "parse_collection's resolved path must stay within EVIDENCE_MOUNT. A collection_id " +
      "that maps to a path outside evidence (via PathGuard) must fail before any I/O.",
    attemptedAction: "parse_collection on a synthesized id that maps to /etc",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("parse_collection", {
          collection_id: "../../../../etc",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "VR-003",
    category: "velociraptor_parser",
    name: "vr_extract_persistence_no_output_path_into_evidence",
    description:
      "vr_extract_persistence has no output_path parameter, but if a future change adds " +
      "one it must not be allowed to write inside EVIDENCE_MOUNT. Verifies the typed " +
      "schema rejects unknown fields.",
    attemptedAction: "vr_extract_persistence with output_path inside evidence",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("vr_extract_persistence", {
          collection_id: "EVID-VR-TEST",
          output_path: `${ctx.evidenceRoot}/Collection-MAC-DESIGNER/results/MacOS.System.Persistence.json`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "VR-004",
    category: "velociraptor_parser",
    name: "no_repack_zip_function",
    description:
      "There must be no MCP tool that repacks or re-seals a Velociraptor collection. " +
      "Chain of custody requires the original sealed zip to remain byte-identical.",
    attemptedAction: "Call repack_collection / reseal_collection",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("repack_collection", {
          collection_id: "EVID-VR-TEST",
          output_path: `${ctx.evidenceRoot}/Collection-MAC-DESIGNER.zip`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "VR-005",
    category: "velociraptor_parser",
    name: "spillover_artifact_must_land_in_working_dir",
    description:
      "Parsers that spill large results to disk must use the working directory, never " +
      "the evidence mount. Attempt to coerce spillover destination via a crafted " +
      "collection_id with traversal sequences.",
    attemptedAction: "vr_extract_unified_log with collection_id containing path traversal",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("vr_extract_unified_log", {
          collection_id: `../../../${ctx.evidenceRoot}/Collection-MAC-DESIGNER`,
          max_rows: 200000,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "VR-006",
    category: "velociraptor_parser",
    name: "no_direct_zip_open_function",
    description:
      "The parser refuses to operate on a sealed zip. open_zip / extract_zip must not " +
      "be exposed as MCP tools — extraction is Evidence Store's responsibility, and " +
      "exposing it here would let an attacker stage a re-extraction over the original.",
    attemptedAction: "Call extract_zip pointing the destination at the existing extracted tree",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_zip", {
          source: join(ctx.evidenceRoot, "Collection-MAC-DESIGNER.zip"),
          destination: join(ctx.evidenceRoot, "Collection-MAC-DESIGNER"),
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },
];
