# Fixture for Test Case 003: C2 Detection (PCAP only)

## Status

**Synthetic fixture — to be generated.**

## What goes here

- `traffic.pcap` — synthetic PCAP containing Cobalt Strike beacon traffic
  mixed with normal HTTPS browsing
- `manifest.yaml` — SHA-256 hash and provenance
- `generation.md` — generation procedure

## Generation Strategy

Cobalt Strike traffic shapes are well-documented. Two acceptable paths:

1. **Replay a known sample.** Several public DFIR challenge sets include
   Cobalt Strike PCAPs with known ground truth (e.g., Wireshark Sample Captures,
   Netresec sample captures, SANS DFIR challenges). Take one of these and
   merge with normal browsing traffic to produce a realistic mixed PCAP.
   Verify license permits redistribution.

2. **Synthesize via a CS team server in an isolated lab.** Stand up an
   isolated CS team server, configure a default Malleable C2 profile, run a
   beacon on a victim VM, capture the traffic with `tcpdump`. Mix with normal
   browsing PCAP via `mergecap`. Sanitize internal IPs to RFC 5737 ranges
   (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) before publishing.

For external IPs, this fixture uses 198.51.100.77 (TEST-NET-2 per RFC 5737).
For DNS tunneling, the suffix `lookup.exfildata.example.invalid` uses the
RFC 6761 reserved `.invalid` TLD.

## Why Trickier Than It Looks

The benign-but-suspicious-looking GT-003-012 entry (Chrome Safe Browsing) is
deliberately included. A naive beacon detector that just looks at "many DNS
queries to one domain" will flag this as malicious. The agent should NOT
flag it. Including this case measures false-positive resistance, not just
detection capability.
