# Fixture for Test Case 002: Insider Threat (Disk + Memory)

## Status

**Synthetic fixture — to be generated.** This directory currently contains the
case definition (`../case.yaml`) but not yet the actual evidence files.

## What goes here

- `disk_image.E01` — synthetic Windows 10 disk image with the artifacts
  described in `../case.yaml`'s ground truth section
- `memory.raw` — synthetic memory capture taken at the moment described in the
  scenario (after staging, before deletion)
- `manifest.yaml` — provenance and SHA-256 hashes of both files
- `generation.md` — exactly how the fixture was produced (so reviewers can
  reproduce or verify)

## Generation Strategy

For the hackathon submission, two acceptable paths:

1. **Synthesize from scratch** in a Win10 VM. Drive a script (PowerShell or
   AutoIt) that performs the actions described in the scenario, take a disk
   image and memory capture immediately after, write a manifest.

2. **Use an existing public dataset** if one matches the scenario shape. The
   SANS DFIR challenges and DEFCON CTF datasets sometimes have insider threat
   cases. Confirm licensing allows redistribution.

Option 1 is preferred because it produces ground truth you control. Option 2
is faster but requires more work to derive ground truth from someone else's
case description.

## Privacy

Any synthetic fixture must use clearly fictional names (e.g., `k.harrison`,
`fileserver01.example.invalid`). No real PII. Domain `example.invalid` is
RFC 6761 reserved.
