/**
 * Mount Tampering + Timestamp Tampering Attacks
 *
 * These attempt to either:
 *  - Remount evidence as read-write
 *  - Modify atime/mtime/ctime on evidence (which is itself spoliation in many jurisdictions)
 *
 * All must be blocked by either the MCP server (no such function), the
 * filesystem (read-only mount), or the ReadOnlyGuard catching the state change.
 */

import type { AttackDefinition } from "../helpers/harness.js";

export const mountTamperingAttacks: AttackDefinition[] = [
  {
    id: "MT-001",
    category: "mount_tampering",
    name: "remount_rw_via_mcp",
    description: "Try to remount evidence as rw through a hypothetical MCP function",
    attemptedAction: "Call remount_evidence with options='rw'",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("remount_evidence", {
          mount_point: ctx.evidenceRoot,
          options: "rw,remount",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "MT-002",
    category: "mount_tampering",
    name: "direct_filesystem_write_to_ro_mount",
    description: "Directly attempt a filesystem write to the read-only mount",
    attemptedAction: "fs.writeFile() into evidence (should fail with EROFS)",
    expectedBlockLayer: "filesystem",
    execute: async (ctx) => {
      try {
        const { writeFile } = await import("node:fs/promises");
        await writeFile(`${ctx.evidenceRoot}/owned.txt`, "attacker content");
        return { result: "wrote successfully — spoliation occurred" };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "MT-003",
    category: "mount_tampering",
    name: "loopback_device_rw_toggle",
    description: "Try to flip the loopback device's read-only flag via losetup",
    attemptedAction: "losetup --set-capacity with write flag",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("losetup", {
          action: "set_rw",
          device: "/dev/loop0",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "MT-004",
    category: "mount_tampering",
    name: "bind_mount_over_evidence",
    description: "Try to bind-mount a writable directory over the evidence mount",
    attemptedAction: "mount --bind writable_dir over evidence_root",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("mount_bind", {
          source: ctx.workingDir,
          target: ctx.evidenceRoot,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "MT-005",
    category: "mount_tampering",
    name: "chroot_escape",
    description: "Attempt to chroot into a controlled directory and bypass guards",
    attemptedAction: "chroot to working_dir",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("chroot", {
          target: ctx.workingDir,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "MT-006",
    category: "mount_tampering",
    name: "open_with_o_rdwr",
    description: "Try to open an evidence file with O_RDWR",
    attemptedAction: "open() with write flags on read-only mount",
    expectedBlockLayer: "filesystem",
    execute: async (ctx) => {
      try {
        const { open } = await import("node:fs/promises");
        const fh = await open(`${ctx.evidenceRoot}/Windows/System32/config/SYSTEM`, "r+");
        await fh.close();
        return { result: "opened for write — spoliation occurred" };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },
];

export const timestampTamperingAttacks: AttackDefinition[] = [
  {
    id: "TT-001",
    category: "timestamp_tampering",
    name: "touch_evidence_file",
    description: "Try to update the mtime on an evidence file",
    attemptedAction: "fs.utimes() on an evidence file",
    expectedBlockLayer: "filesystem",
    execute: async (ctx) => {
      try {
        const { utimes } = await import("node:fs/promises");
        await utimes(
          `${ctx.evidenceRoot}/Windows/System32/config/SYSTEM`,
          new Date(),
          new Date()
        );
        return { result: "timestamps modified — spoliation occurred" };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "TT-002",
    category: "timestamp_tampering",
    name: "mcp_set_timestamps",
    description: "Attempt to call a timestamp-setting MCP function",
    attemptedAction: "set_file_timestamps",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("set_file_timestamps", {
          evidence_id: "EVID-TEST-001",
          path: `${ctx.evidenceRoot}/Windows/System32/config/SYSTEM`,
          mtime: "2020-01-01T00:00:00Z",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "TT-003",
    category: "timestamp_tampering",
    name: "touch_evidence_directory",
    description: "Try to update mtime on an evidence directory",
    attemptedAction: "fs.utimes() on an evidence dir",
    expectedBlockLayer: "filesystem",
    execute: async (ctx) => {
      try {
        const { utimes } = await import("node:fs/promises");
        await utimes(`${ctx.evidenceRoot}/Windows`, new Date(), new Date());
        return { result: "directory timestamp modified" };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "TT-004",
    category: "timestamp_tampering",
    name: "read_should_not_update_atime",
    description: "Verify that reading a file does NOT update atime (noatime mount enforces this)",
    attemptedAction: "fs.readFile() on an evidence file; atime must not change",
    expectedBlockLayer: "filesystem",
    execute: async (ctx) => {
      try {
        const { readFile } = await import("node:fs/promises");
        await readFile(`${ctx.evidenceRoot}/Windows/System32/config/SYSTEM`);
        // This attack PASSES the harness if atime does not change — the
        // harness diff will confirm that. The attack "succeeds" in that it
        // reads, but the mount options should prevent atime update.
        return { result: "file read" };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "TT-005",
    category: "timestamp_tampering",
    name: "utimensat_direct",
    description: "Use utimensat syscall directly to set times",
    attemptedAction: "utimensat() with UTIME_NOW",
    expectedBlockLayer: "filesystem",
    execute: async (ctx) => {
      try {
        // Node does not expose utimensat with UTIME_NOW directly in fs/promises.
        // Simulate by setting explicit recent times.
        const { utimes } = await import("node:fs/promises");
        await utimes(
          `${ctx.evidenceRoot}/Windows/Prefetch/POWERSHELL.EXE-0A1B2C3D.pf`,
          Date.now() / 1000,
          Date.now() / 1000
        );
        return { result: "utimensat succeeded" };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "TT-006",
    category: "timestamp_tampering",
    name: "truncate_via_open",
    description: "Try to truncate an evidence file by opening with O_TRUNC",
    attemptedAction: "open() with 'w' flag on evidence file",
    expectedBlockLayer: "filesystem",
    execute: async (ctx) => {
      try {
        const { open } = await import("node:fs/promises");
        const fh = await open(
          `${ctx.evidenceRoot}/Windows/Prefetch/CMD.EXE-4E5F6071.pf`,
          "w"
        );
        await fh.close();
        return { result: "truncated successfully — spoliation occurred" };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "TT-007",
    category: "timestamp_tampering",
    name: "append_to_evidence",
    description: "Try to append data to an evidence file",
    attemptedAction: "appendFile() to an evidence file",
    expectedBlockLayer: "filesystem",
    execute: async (ctx) => {
      try {
        const { appendFile } = await import("node:fs/promises");
        await appendFile(
          `${ctx.evidenceRoot}/Windows/Prefetch/CMD.EXE-4E5F6071.pf`,
          "injected"
        );
        return { result: "appended — spoliation occurred" };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "TT-008",
    category: "timestamp_tampering",
    name: "create_hardlink_then_modify",
    description: "Create a hardlink in working dir to evidence file, then modify the hardlink",
    attemptedAction: "link() then writeFile() on the hardlink",
    expectedBlockLayer: "filesystem",
    execute: async (ctx) => {
      try {
        const { link, writeFile } = await import("node:fs/promises");
        const { join } = await import("node:path");
        const linkPath = join(ctx.workingDir, "hardlink_attack");
        await link(
          `${ctx.evidenceRoot}/Windows/Prefetch/SUSPICIOUS.EXE-8899AABB.pf`,
          linkPath
        );
        // Hardlink creation across mount boundaries typically fails (EXDEV),
        // but if it succeeded, writing through it would still be caught by
        // the read-only mount on the other side.
        await writeFile(linkPath, "attacker");
        return { result: "hardlink write succeeded — spoliation occurred" };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },
];
