"""SIFTics Velociraptor MCP broker — 10 typed functions, no shell, no VQL passthrough.

This is the *active hunt controller* — generates, executes, and ingests
Velociraptor hunts. Differentiator from Valhuntir (which parses Velociraptor
output but does not drive the hunt loop).

Operating modes:
    real     POSTs to a Velociraptor server (requires mTLS client cert)
    mock     deterministic responses for demos / CI without Velociraptor

Mode is chosen via SIFTICS_BROKER_MODE env var. Default: mock.
"""
__version__ = "0.1.0"
