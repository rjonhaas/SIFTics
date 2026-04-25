/**
 * Path Traversal Attacks
 *
 * Every one of these attempts to reference a path outside the evidence mount
 * or the working directory. Every one must be blocked by PathGuard BEFORE
 * any filesystem operation occurs.
 */

import type { AttackDefinition } from "../helpers/harness.js";
import { join } from "node:path";
import { writeFile, symlink, mkdir } from "node:fs/promises";

export const pathTraversalAttacks: AttackDefinition[] = [
  {
    id: "PT-001",
    category: "path_traversal",
    name: "dotdot_escape",
    description: "Use ../ sequences to escape the evidence mount",
    attemptedAction: "Reference /etc/passwd via evidence_path=../../etc/passwd",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: `${ctx.evidenceRoot}/../../../etc/passwd`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-002",
    category: "path_traversal",
    name: "encoded_dotdot",
    description: "URL-encoded ../ sequences",
    attemptedAction: "Reference /etc/passwd via %2e%2e%2f encoding",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: `${ctx.evidenceRoot}/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-003",
    category: "path_traversal",
    name: "absolute_path_outside_mount",
    description: "Provide an absolute path to a file outside the evidence mount",
    attemptedAction: "Reference /etc/passwd directly",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: "/etc/passwd",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-004",
    category: "path_traversal",
    name: "null_byte_truncation",
    description: "Inject a null byte to attempt truncation of the validated path",
    attemptedAction: "Path containing \\x00 to fool older path validators",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: `${ctx.evidenceRoot}/Windows/System32/config/SYSTEM\x00/../../../etc/passwd`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-005",
    category: "path_traversal",
    name: "symlink_escape",
    description: "Create a symlink inside the working directory that points into the evidence mount",
    attemptedAction: "Symlink working/link -> evidence/file, then write through the link",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const linkPath = join(ctx.workingDir, "escape_link");
        await symlink(ctx.evidenceRoot, linkPath);
        const result = await ctx.callTool("write_parsed_output", {
          output_path: `${linkPath}/Windows/System32/config/SYSTEM`,
          data: { malicious: true },
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-006",
    category: "path_traversal",
    name: "relative_path",
    description: "Provide a relative path (PathGuard should reject all non-absolute paths)",
    attemptedAction: "Pass 'Windows/System32/config/SYSTEM' with no leading slash",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: "Windows/System32/config/SYSTEM",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-007",
    category: "path_traversal",
    name: "unicode_lookalike",
    description: "Unicode characters that visually resemble directory separators",
    attemptedAction: "Path using fullwidth solidus (U+FF0F) instead of /",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: `${ctx.evidenceRoot}／..／..／etc／passwd`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-008",
    category: "path_traversal",
    name: "trailing_dotdot_after_valid_prefix",
    description: "Path starts inside the mount but traverses out at the end",
    attemptedAction: "evidence/EVID-TEST-001/../../../etc/passwd",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: `${ctx.evidenceRoot}/../../../etc/passwd`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-009",
    category: "path_traversal",
    name: "output_path_into_evidence",
    description: "Attempt to write a parsed artifact output INTO the evidence tree",
    attemptedAction: "output_path points inside EVIDENCE_MOUNT",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("write_parsed_output", {
          output_path: `${ctx.evidenceRoot}/Windows/Prefetch/MALICIOUS.pf`,
          data: { content: "attacker-controlled" },
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-010",
    category: "path_traversal",
    name: "nested_symlink_chain",
    description: "Chain two symlinks together, first inside working, second pointing into evidence",
    attemptedAction: "Create a->b->evidence/file and operate on 'a'",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const chainDir = join(ctx.workingDir, "chain");
        await mkdir(chainDir, { recursive: true });
        const b = join(chainDir, "b");
        const a = join(chainDir, "a");
        await symlink(ctx.evidenceRoot, b);
        await symlink(b, a);
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: `${a}/Windows/System32/config/SYSTEM`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-011",
    category: "path_traversal",
    name: "proc_self_escape",
    description: "Reference /proc/self/root to escape the mount namespace",
    attemptedAction: "/proc/self/root/etc/passwd",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: "/proc/self/root/etc/passwd",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-012",
    category: "path_traversal",
    name: "dev_device_access",
    description: "Reference /dev/sda to access the underlying block device",
    attemptedAction: "/dev/sda",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: "/dev/sda",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-013",
    category: "path_traversal",
    name: "backslash_separator",
    description: "Windows-style path separators on Linux",
    attemptedAction: "Use backslashes as separators",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: `${ctx.evidenceRoot}\\..\\..\\..\\etc\\passwd`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-014",
    category: "path_traversal",
    name: "extra_slashes",
    description: "Multiple consecutive slashes to confuse path normalization",
    attemptedAction: "///etc///passwd",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: "///etc///passwd",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-015",
    category: "path_traversal",
    name: "dot_segments_mixed",
    description: "Mix of . and .. segments to confuse path normalization",
    attemptedAction: "evidence/./../../../etc/passwd",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: `${ctx.evidenceRoot}/./../../../etc/passwd`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-016",
    category: "path_traversal",
    name: "empty_string_path",
    description: "Empty path string",
    attemptedAction: "path=''",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: "",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-017",
    category: "path_traversal",
    name: "single_dot_only",
    description: "Path of just '.'",
    attemptedAction: "path='.'",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: ".",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "PT-018",
    category: "path_traversal",
    name: "typeconfused_path",
    description: "Path parameter provided as an array instead of a string",
    attemptedAction: "path=[...]",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: ["/etc", "passwd"] as unknown as string,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },
];
