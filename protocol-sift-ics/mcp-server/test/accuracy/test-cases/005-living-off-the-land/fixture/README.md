# Fixture for Test Case 005: Living Off The Land

## Status

**Synthetic fixture — to be generated.**

## What goes here

- `disk_image.E01` — Windows 10 disk image
- `memory.raw` — memory capture
- `manifest.yaml` — SHA-256 hashes
- `generation.md` — generation procedure

## Generation Strategy

This is conceptually the simplest fixture (single host, no malware to drop)
but the most behaviorally subtle. Generation:

1. Win10 VM, baseline configuration
2. Enable PowerShell ScriptBlockLogging and Module Logging via GPO before
   the attack starts (so 4104 events are captured)
3. Drive the attack via PowerShell from an external "attacker" VM:
   - WinRM session inbound from external IP
   - Disable ScriptBlockLogging via registry
   - Reflective .NET assembly load to download stage 2
   - Built-in recon burst (nltest, net, whoami, tasklist, systeminfo)
   - WMI event subscription persistence
   - reg.exe save SAM/SYSTEM
   - Re-enable ScriptBlockLogging
4. Take memory capture WHILE PowerShell session is still active (so
   vol_malfind catches the RWX region and vol_netscan catches the live
   connection)
5. Take disk image after PowerShell session ends

## What Makes This Case Special

This case has the highest concentration of negative test cases (GT-005-011,
GT-005-012). It's measuring NOT just whether the agent finds evil, but
whether it correctly REJECTS findings it's tempted to make.

A common failure mode: agents trained on common IOCs get overconfident and
report a Run-key persistence finding because that's what most cases have.
GT-005-012 explicitly checks that the agent does not invent a Run key entry
when the real persistence is via WMI.

## Privacy

External "attacker" IP uses 203.0.113.45 (TEST-NET-3 per RFC 5737).
