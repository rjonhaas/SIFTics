"""SIFTics baseline MCP — Rathbun known-good lookups.

Backed by AndrewRathbun/VanillaWindowsReference + VanillaWindowsRegistryHives.
Stored in a SQLite database for fast equality lookups (no embeddings, no LLM).

The agent uses this to filter out everything that is *expected* on a clean
Windows install, so suspicious-on-its-face entries stand out without LLM cost.
"""
__version__ = "0.1.0"
