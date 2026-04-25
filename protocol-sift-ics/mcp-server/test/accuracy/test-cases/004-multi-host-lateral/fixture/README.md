# Fixture for Test Case 004: Multi-Host Lateral Movement

## Status

**Synthetic fixture — to be generated.**

## What goes here

- `host-WIN-RECEPTION.E01` — patient zero (Windows 10 workstation)
- `host-WIN-FINANCE.E01` — first lateral hop
- `host-DC01.E01` — domain controller (Windows Server 2022)
- `east_west_traffic.pcap` — internal network traffic spanning the lateral
  movement window
- `manifest.yaml` — SHA-256 hashes for all four files
- `generation.md` — generation procedure

## Generation Strategy

This is the most expensive fixture to generate because it requires a small
working Active Directory lab. Recommended approach:

1. Build a 3-VM AD lab in an isolated network: 1 DC, 2 workstations
2. Domain join the workstations
3. Drive a script that performs the kill chain described in `../case.yaml`:
   email-with-macro → reception execution → credential theft → SMB lateral to
   finance → PsExec → BloodHound → RDP to DC → ntds.dit dump → log clear
4. Capture network traffic with `tcpdump` on the DC's segment for the entire
   window (start ~5 min before initial access, end ~5 min after log clear)
5. After log clear is complete, take disk images of all three VMs
6. Compute SHA-256 hashes, write manifest

## Sizing

Even minimal Win10/Server 2022 disk images run 20-40 GB. For the hackathon
submission, consider:

- Submitting the full images via the SIFT Workstation OVA download mechanism
  (the SANS team has bandwidth for this)
- Alternatively, providing parsed-artifact JSON exports per host so the
  accuracy harness can run without the full images. The trade-off: smaller
  reproduction package, but reviewers can't verify the parsing layer.

The harness supports both modes via the `evidence` block in `case.yaml` —
type `disk_image` for full images, type `parsed_artifacts_json` for the
pre-parsed alternative.

## Privacy

All hostnames, usernames, and IPs are fictional. RFC 5737 IP ranges only.
