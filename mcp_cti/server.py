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

try:
    from siftics.audit import append_event as _audit
except ImportError:
    def _audit(*a, **kw): pass  # type: ignore[misc]

# Integration keys — resolved at call time so the keyring is the canonical
# source. The raw key value never appears in audit events; only the resolution
# location is recorded ("keyring:siftics_shodan/default" vs "file:..." vs "env:").
try:
    from siftics.runtime_config import (
        load_config as _load_runtime_config,
        resolve_integration_key as _resolve_integration_key,
        MissingAPIKey as _MissingAPIKey,
    )

    def _integration_key(name: str) -> tuple[str | None, str]:
        """Return (key_value, location_label) or (None, 'not_configured')."""
        try:
            cfg = _load_runtime_config()
            ikey = getattr(cfg.integrations, name)
            return _resolve_integration_key(ikey), _key_location(ikey)
        except _MissingAPIKey:
            return None, "not_configured"
        except Exception:
            return None, "config_error"

    def _key_location(ikey) -> str:
        # Mirrors the precedence in _resolve_key without exposing the value.
        try:
            import keyring  # type: ignore
            if keyring.get_password(ikey.api_key_keyring_service,
                                     ikey.api_key_keyring_user):
                return f"keyring:{ikey.api_key_keyring_service}"
        except Exception:
            pass
        if os.environ.get(ikey.api_key_env):
            return f"env:{ikey.api_key_env}"
        if ikey.api_key_file and os.path.exists(os.path.expanduser(ikey.api_key_file)):
            return f"file:{ikey.api_key_file}"
        return "unknown"
except ImportError:
    def _integration_key(name: str) -> tuple[str | None, str]:  # type: ignore[misc]
        return None, "siftics_not_installed"


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
        out = cached
    else:
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
    try:
        _audit("cti_lookup", {
            "source_type": "deterministic",
            "backend": "malware_bazaar",
            "ioc_type": "sha256",
            "ioc_value": sha256.lower(),
            "found": out.get("found", False),
        }, actor="mcp_cti")
    except RuntimeError:
        pass
    return out


@mcp.tool()
def lookup_url(url: str) -> dict:
    """Look up a URL across abuse.ch URLhaus.

    Returns {'found': bool, 'url': {...}, 'tags': [...]} or empty.
    """
    key = _cache_key({"src": "urlhaus", "url": url})
    cached = _cache_read(key)
    if cached is not None:
        out = cached
    else:
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
    try:
        _audit("cti_lookup", {
            "source_type": "deterministic",
            "backend": "urlhaus",
            "ioc_type": "url",
            "ioc_value": url[:200],
            "found": out.get("found", False),
        }, actor="mcp_cti")
    except RuntimeError:
        pass
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
        out = cached
    else:
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
    try:
        _audit("cti_lookup", {
            "source_type": "deterministic",
            "backend": "threatfox",
            "ioc_type": ioc_type,
            "ioc_value": ioc_value[:200],
            "found": out.get("found", False),
        }, actor="mcp_cti")
    except RuntimeError:
        pass
    return out


@mcp.tool()
def lookup_c2_ip(ip: str) -> dict:
    """Check abuse.ch Feodo Tracker for known botnet C2 IPs."""
    key = _cache_key({"src": "feodo", "ip": ip})
    cached = _cache_read(key)
    if cached is not None:
        out = cached
    else:
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
    try:
        _audit("cti_lookup", {
            "source_type": "deterministic",
            "backend": "feodo_tracker",
            "ioc_type": "ip",
            "ioc_value": ip,
            "found": out.get("found", False),
        }, actor="mcp_cti")
    except RuntimeError:
        pass
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

    Key is resolved via the SIFTics keyring vault (preferred), the
    SIFTICS_OSM_API_KEY env var, or a chmod-0600 file fallback. The raw
    key never appears in audit events.
    """
    api_key, key_location = _integration_key("osm")
    if not api_key:
        return {"found": False, "error": f"OSM key {key_location}"}

    key = _cache_key({"src": "osm", "v": value.lower(), "t": type_hint})
    cached = _cache_read(key)
    if cached is not None:
        out = cached
    else:
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
    try:
        _audit("cti_lookup", {
            "source_type": "deterministic",
            "backend": "osm_stix",
            "ioc_type": type_hint,
            "ioc_value": value[:200],
            "found": out.get("found", False),
        }, actor="mcp_cti")
    except RuntimeError:
        pass
    return out


# ---------------------------------------------------------------------------
# Shodan — IP intelligence (ports, services, banners)
# ---------------------------------------------------------------------------


@mcp.tool()
def lookup_shodan_ip(ip: str) -> dict:
    """Look up an IP address in Shodan.

    Returns Shodan host record (ports, services, hostnames, organisation,
    country, ASN) for a given IPv4 address. Useful for understanding what an
    attacker IP exposes externally — distinguishes "compromised home router"
    from "C2 server with open ports" from "Tor exit node".

    Key is resolved via the SIFTics keyring vault (preferred), the
    SIFTICS_SHODAN_API_KEY env var, or a chmod-0600 file fallback.
    """
    api_key, key_location = _integration_key("shodan")
    if not api_key:
        return {"found": False, "error": f"Shodan key {key_location}"}

    key = _cache_key({"src": "shodan_host", "ip": ip})
    cached = _cache_read(key)
    if cached is not None:
        out = cached
    else:
        try:
            r = httpx.get(f"https://api.shodan.io/shodan/host/{ip}",
                           params={"key": api_key},
                           headers={"User-Agent": "SIFTics/0.1"},
                           timeout=20)
            if r.status_code == 404:
                out = {"found": False, "reason": "ip_not_indexed_by_shodan"}
            elif r.status_code == 401:
                out = {"found": False, "error": "shodan_unauthorized"}
            else:
                data = r.json()
                out = {
                    "found": True,
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "org": data.get("org"),
                    "country": data.get("country_name"),
                    "asn": data.get("asn"),
                    "tags": data.get("tags", []),
                    "vulns": list((data.get("vulns") or {}).keys()),
                    "last_update": data.get("last_update"),
                    "services": [
                        {"port": s.get("port"), "product": s.get("product"),
                         "version": s.get("version"),
                         "banner_first_200": (s.get("data") or "")[:200]}
                        for s in (data.get("data") or [])
                    ],
                }
        except Exception as e:
            return {"found": False, "error": str(e)}
        _cache_write(key, out)
    try:
        _audit("cti_lookup", {
            "source_type": "deterministic",
            "backend": "shodan",
            "ioc_type": "ip",
            "ioc_value": ip,
            "found": out.get("found", False),
            "key_location": key_location,  # never the value
        }, actor="mcp_cti")
    except RuntimeError:
        pass
    return out


# ---------------------------------------------------------------------------
# VirusTotal — file hash, URL, domain, IP reputation
# ---------------------------------------------------------------------------


@mcp.tool()
def lookup_virustotal(ioc_value: str, ioc_type: str = "auto") -> dict:
    """Look up a hash / URL / domain / IP on VirusTotal v3 API.

    Args:
        ioc_value: the indicator.
        ioc_type: "auto" | "sha256" | "md5" | "sha1" | "url" | "domain" | "ip".

    Returns AV detection ratio, family labels, first/last seen dates, and
    sandbox tags. Key resolved via SIFTics keyring vault, then env, then file.
    """
    api_key, key_location = _integration_key("virustotal")
    if not api_key:
        return {"found": False, "error": f"VirusTotal key {key_location}"}

    # Decide which v3 endpoint based on type
    v = ioc_value.strip()
    if ioc_type == "auto":
        if v.startswith(("http://", "https://")):
            ioc_type = "url"
        elif len(v) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in v):
            ioc_type = "sha256" if len(v) == 64 else ("sha1" if len(v) == 40 else "md5")
        elif v.count(".") == 3 and all(p.isdigit() for p in v.split(".")):
            ioc_type = "ip"
        else:
            ioc_type = "domain"

    if ioc_type == "url":
        import base64
        endpoint = "urls/" + base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")
    elif ioc_type in ("sha256", "sha1", "md5"):
        endpoint = f"files/{v.lower()}"
    elif ioc_type == "ip":
        endpoint = f"ip_addresses/{v}"
    elif ioc_type == "domain":
        endpoint = f"domains/{v}"
    else:
        return {"found": False, "error": f"unsupported ioc_type: {ioc_type}"}

    key = _cache_key({"src": "vt", "v": v.lower(), "t": ioc_type})
    cached = _cache_read(key)
    if cached is not None:
        out = cached
    else:
        try:
            r = httpx.get(f"https://www.virustotal.com/api/v3/{endpoint}",
                           headers={"x-apikey": api_key,
                                    "User-Agent": "SIFTics/0.1"},
                           timeout=20)
            if r.status_code == 404:
                out = {"found": False, "reason": "not_in_virustotal"}
            elif r.status_code == 401:
                out = {"found": False, "error": "virustotal_unauthorized"}
            else:
                data = r.json().get("data", {})
                attrs = data.get("attributes", {}) or {}
                stats = attrs.get("last_analysis_stats", {}) or {}
                out = {
                    "found": True,
                    "ioc_type": ioc_type,
                    "malicious_count": stats.get("malicious", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                    "harmless_count": stats.get("harmless", 0),
                    "undetected_count": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()),
                    "type_description": attrs.get("type_description"),
                    "names": (attrs.get("names") or [])[:5],
                    "popular_threat_label": (attrs.get("popular_threat_classification") or {})
                                              .get("suggested_threat_label"),
                    "tags": attrs.get("tags", []),
                    "first_submission_date": attrs.get("first_submission_date"),
                    "last_analysis_date": attrs.get("last_analysis_date"),
                    "reputation": attrs.get("reputation"),
                }
        except Exception as e:
            return {"found": False, "error": str(e)}
        _cache_write(key, out)
    try:
        _audit("cti_lookup", {
            "source_type": "deterministic",
            "backend": "virustotal",
            "ioc_type": ioc_type,
            "ioc_value": v[:200],
            "found": out.get("found", False),
            "key_location": key_location,  # never the value
        }, actor="mcp_cti")
    except RuntimeError:
        pass
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

    # Helper — only try a backend if its key is present
    def _key_ok(name: str) -> bool:
        _, loc = _integration_key(name)
        return loc.startswith(("keyring:", "env:", "file:"))

    # Hash → MalwareBazaar + VirusTotal
    if ioc_type in ("auto", "sha256") and len(ioc_value) == 64:
        backends["malware_bazaar"] = lookup_hash(ioc_value)
        if _key_ok("virustotal"):
            backends["virustotal"] = lookup_virustotal(ioc_value, ioc_type="sha256")

    # IP → Feodo + ThreatFox + Shodan + VirusTotal
    if ioc_type in ("auto", "ip"):
        if ioc_value.count(".") == 3:
            backends["feodo_tracker"] = lookup_c2_ip(ioc_value)
            backends["threatfox"] = lookup_ioc(ioc_value, ioc_type="ip")
            if _key_ok("shodan"):
                backends["shodan"] = lookup_shodan_ip(ioc_value)
            if _key_ok("virustotal"):
                backends["virustotal_ip"] = lookup_virustotal(ioc_value, ioc_type="ip")

    # URL → URLhaus + VirusTotal
    if ioc_type in ("auto", "url") and ioc_value.startswith(("http://", "https://")):
        backends["urlhaus"] = lookup_url(ioc_value)
        backends["threatfox"] = lookup_ioc(ioc_value, ioc_type="url")
        if _key_ok("virustotal"):
            backends["virustotal_url"] = lookup_virustotal(ioc_value, ioc_type="url")

    # Domain → ThreatFox + VirusTotal
    if ioc_type == "domain" or (ioc_type == "auto" and "." in ioc_value
                                  and not ioc_value.startswith("http")):
        backends["threatfox"] = lookup_ioc(ioc_value, ioc_type="domain")
        if _key_ok("virustotal"):
            backends["virustotal_domain"] = lookup_virustotal(ioc_value, ioc_type="domain")

    # OSM (STIX) — only if key configured
    if _key_ok("osm"):
        backends["osm"] = osm_lookup_indicator(ioc_value, type_hint=ioc_type)

    hit_count = sum(1 for v in backends.values() if v.get("found"))
    result = {
        "value": ioc_value,
        "type": ioc_type,
        "backends": backends,
        "any_hit": hit_count > 0,
        "hit_count": hit_count,
    }
    try:
        _audit("cti_lookup", {
            "source_type": "deterministic",
            "backend": "enrich_aggregator",
            "ioc_type": ioc_type,
            "ioc_value": ioc_value[:200],
            "backends_queried": list(backends.keys()),
            "any_hit": result["any_hit"],
            "hit_count": hit_count,
        }, actor="mcp_cti")
    except RuntimeError:
        pass
    return result


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
