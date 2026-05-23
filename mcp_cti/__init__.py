"""SIFTics CTI MCP — multi-source threat intelligence enrichment.

Backends:
    • abuse.ch URLhaus       URL → malware association
    • abuse.ch MalwareBazaar SHA-256 → sample metadata
    • abuse.ch ThreatFox     IOC (hash, ip, domain, url) → ATT&CK + actor
    • abuse.ch Feodo Tracker IP → botnet C2 indicator
    • OpenSourceMalware      STIX 2.1 indicator bundle (API key required)

Multi-source by design — Valhuntir's opencti-mcp is tied to one vendor.
"""
__version__ = "0.1.0"
