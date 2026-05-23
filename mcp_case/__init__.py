"""SIFTics Case-State MCP server.

Custom MCP Server architectural pattern (Find Evil! hackathon approach #2).
Exposes typed functions for COP / ASR / CET / ITQ / Briefing manipulation —
never raw shell, never eval, never SQL passthrough.

Transports: stdio (for Claude Code subprocess) and SSE (for any MCP client).
"""
__version__ = "0.1.0"
