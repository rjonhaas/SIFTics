"""mcp_cti — Custom MCP for IOC enrichment across multiple free CTI feeds.

Environment:
    SIFTICS_OSM_API_KEY      OpenSourceMalware STIX feed key (optional)
    SIFTICS_ABUSECH_API_KEY  abuse.ch API key (optional for higher rate limits)
    SIFTICS_CTI_CACHE_DIR    where to cache lookups (defaults to $CASE/cti_cache/)

All lookups are typed; the agent cannot use this MCP to fire arbitrary HTTP.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("siftics-cti")

# ---------------------------------------------------------------------------
# Local cache (so repeated lookups in a single case don't re-hit upstream)
# ---------------------------------------------------------------------------


def _cache_dir() -> Path:
    if env := os.environ.get("SIFTICS_CTI_CACHE_DIR"):
        return Path(env)
    case_dir = os.environ.get("SIFTICS_CASE_DIR")
    if case_dir:
        return Path(case_dir) / "cti_cache"
    return Path.home() / ".cache" / "siftics" / "cti"


def _cache_key(parts: dict[str, Any]) -> str:
    raw = json.dumps(parts, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _cache_read(key: str, max_age_seconds: int = 86400) -> dict | None:
    p = _cache_dir() / f"{key}.json"
    if not p.exists():
        return None
    age = time.time() - p.stat().st_mtime
    if age > max_age_seconds:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _cache_write(key: str, value: dict) -> None:
    d = _cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{key}.json").write_text(json.dumps(value, indent=0,
                                              separators=(",", ":")),
                                    encoding="utf-8")


# ---------------------------------------------------------------------------
# abuse.ch — URLhaus / MalwareBazaar / ThreatFox / Feodo Tracker
# ---------------------------------------------------------------------------


def _abusech_headers() -> dict[str, str]:
    h = {"User-Agent": "SIFTics/0.1 (https://github.com/rjonhaas/SIFTics)"}
    key = os.environ.get("SIFTICS_ABUSECH_API_KEY")
    if key:
        h["Auth-Key"] = key
    return h


@mcp.tool()
def lookup_hash(sha256: str) -> dict:
    """Look up a SHA-256 across abuse.ch MalwareBazaar.

    Returns {'found': bool, 'sample': {...}} or {'found': false} if no hit.
    """
    key = _cache_key({"src": "mb", "sha256": sha256.lower()})
    cached = _cache_read(key)
    if cached is not None:
        return cached
    try:
        r = httpx.post("https://mb-api.abuse.ch/api/v1/",
                        data={"query": "get_info", "hash": sha256.lower()},
                        headers=_abusech_headers(), timeout=15)
        data = r.json()
    except Exception as e:
        return {"found": False, "error": str(e)}
    if data.get("query_status") == "ok":
        out = {"found": True, "sample": data.get("data", [{}])[0]}
    else:
        out = {"found": False, "query_status": data.get("query_status")}
    _cache_write(key, out)
    return out


@mcp.tool()
def lookup_url(url: str) -> dict:
    """Look up a URL across abuse.ch URLhaus.

    Returns {'found': bool, 'url': {...}, 'tags': [...]} or empty.
    """
    key = _cache_key({"src": "urlhaus", "url": url})
    cached = _cache_read(key)
    if cached is not None:
        return cached
    try:
        r = httpx.post("https://urlhaus-api.abuse.ch/v1/url/",
                        data={"url": url},
                        headers=_abusech_headers(), timeout=15)
        data = r.json()
    except Exception as e:
        return {"found": False, "error": str(e)}
    if data.get("query_status") == "ok":
        out = {"found": True, "url_data": data,
               "tags": data.get("tags", []),
               "threat": data.get("threat", "")}
    else:
        out = {"found": False, "query_status": data.get("query_status")}
    _cache_write(key, out)
    return out


@mcp.tool()
def lookup_ioc(ioc_value: str, ioc_type: str = "auto") -> dict:
    """Look up an IOC (hash, IP, domain, URL) across abuse.ch ThreatFox.

    Args:
        ioc_value: the indicator string.
        ioc_type: "auto" | "sha256" | "md5" | "domain" | "ip" | "url".
    Returns ThreatFox metadata if found, including ATT&CK mappings.
    """
    key = _cache_key({"src": "threatfox", "v": ioc_value.lower(), "t": ioc_type})
    cached = _cache_read(key)
    if cached is not None:
        return cached
    try:
        r = httpx.post("https://threatfox-api.abuse.ch/api/v1/",
                        data={"query": "search_ioc", "search_term": ioc_value},
                        headers=_abusech_headers(), timeout=15)
        data = r.json()
    except Exception as e:
        return {"found": False, "error": str(e)}
    if data.get("query_status") == "ok":
        out = {"found": True, "matches": data.get("data", [])}
    else:
        out = {"found": False, "query_status": data.get("query_status")}
    _cache_write(key, out)
    return out


@mcp.tool()
def lookup_c2_ip(ip: str) -> dict:
    """Check abuse.ch Feodo Tracker for known botnet C2 IPs."""
    key = _cache_key({"src": "feodo", "ip": ip})
    cached = _cache_read(key)
    if cached is not None:
        return cached
    try:
        # Feodo Tracker uses CSV/JSON exports; cheaper to do a single download
        # per case and cache than per-IP API calls.
        r = httpx.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            headers=_abusech_headers(), timeout=15)
        rows = r.json()
        match = next((row for row in rows if row.get("ip_address") == ip), None)
    except Exception as e:
        return {"found": False, "error": str(e)}
    out = {"found": match is not None, "match": match}
    _cache_write(key, out)
    return out


# ---------------------------------------------------------------------------
# OpenSourceMalware — STIX 2.1 indicator bundle (API key required)
# ---------------------------------------------------------------------------


@mcp.tool()
def osm_lookup_indicator(value: str, type_hint: str = "auto") -> dict:
    """Look up an indicator in the OpenSourceMalware STIX feed.

    Args:
        value: hash / IP / domain / URL.
        type_hint: "auto" | "sha256" | "ipv4-addr" | "domain-name" | "url".

    Requires SIFTICS_OSM_API_KEY env var (or keyring). Returns the matching
    STIX indicator object + any related relationship/threat-actor objects.
    """
    api_key = os.environ.get("SIFTICS_OSM_API_KEY")
    if not api_key:
        return {"found": False, "error": "SIFTICS_OSM_API_KEY not set"}

    key = _cache_key({"src": "osm", "v": value.lower(), "t": type_hint})
    cached = _cache_read(key)
    if cached is not None:
        return cached
    try:
        r = httpx.get(
            "https://opensourcemalware.com/api/v1/indicators/search",
            params={"value": value, "type": type_hint},
            headers={"Authorization": f"Bearer {api_key}",
                      "User-Agent": "SIFTics/0.1"},
            timeout=20)
        data = r.json()
    except Exception as e:
        return {"found": False, "error": str(e)}
    out = {"found": bool(data.get("indicators")),
           "indicators": data.get("indicators", []),
           "related": data.get("related_objects", [])}
    _cache_write(key, out)
    return out


# ---------------------------------------------------------------------------
# Aggregator — single call across all backends
# ---------------------------------------------------------------------------


@mcp.tool()
def enrich(ioc_value: str, ioc_type: str = "auto") -> dict:
    """Single-call aggregator across all enabled CTI backends.

    Returns {'value': ..., 'type': ..., 'backends': {...}} with one entry per
    backend that returned a hit. The agent should prefer this over individual
    lookups for general triage.
    """
    backends: dict[str, Any] = {}

    # Hash → MalwareBazaar
    if ioc_type in ("auto", "sha256") and len(ioc_value) == 64:
        backends["malware_bazaar"] = lookup_hash(ioc_value)

    # IP → Feodo + ThreatFox
    if ioc_type in ("auto", "ip"):
        # crude IPv4 detector
        if ioc_value.count(".") == 3:
            backends["feodo_tracker"] = lookup_c2_ip(ioc_value)
            backends["threatfox"] = lookup_ioc(ioc_value, ioc_type="ip")

    # URL → URLhaus
    if ioc_type in ("auto", "url") and ioc_value.startswith(("http://", "https://")):
        backends["urlhaus"] = lookup_url(ioc_value)
        backends["threatfox"] = lookup_ioc(ioc_value, ioc_type="url")

    # Domain → ThreatFox
    if ioc_type == "domain" or (ioc_type == "auto" and "." in ioc_value
                                  and not ioc_value.startswith("http")):
        backends["threatfox"] = lookup_ioc(ioc_value, ioc_type="domain")

    # OSM (STIX) — try regardless of type if key is set
    if os.environ.get("SIFTICS_OSM_API_KEY"):
        backends["osm"] = osm_lookup_indicator(ioc_value, type_hint=ioc_type)

    hit_count = sum(1 for v in backends.values() if v.get("found"))
    return {
        "value": ioc_value,
        "type": ioc_type,
        "backends": backends,
        "any_hit": hit_count > 0,
        "hit_count": hit_count,
    }


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="SIFTics CTI MCP server.")
    parser.add_argument("--transport", choices=("stdio", "sse"), default="stdio")
    parser.add_argument("--port", type=int, default=9103)
    args = parser.parse_args()
    if args.transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport="sse", port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
