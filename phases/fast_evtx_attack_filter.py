"""HOT-layer: streaming EVTX → IR-relevant event IDs only.

Speed-thesis demo. Replaces ~30 minutes of full EvtxECmd dump with a focused
scan of the ~30 event IDs that matter for incident response. Designed to emit
the first event within seconds, not after a full pass.

Usage:
    python -m phases.fast_evtx_attack_filter \
        --input /path/to/evtx-dir \
        --since 2026-05-22T13:00:00Z \
        --output /case/findings/fast_evtx.jsonl

Required: python-evtx (pyevtx-rs binding). Falls back to a graceful error if
missing — the install path lists it as a dependency.

Output: one JSON line per matched event, fields:
    timestamp, source_channel, event_id, host, user, process, parent_process,
    command_line, image, target_image, network, action, attack_technique
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Iterator
from xml.etree import ElementTree as ET

# The ~30 IR-relevant event IDs (with the source channel they live in).
# Pulled from MITRE D3FEND + SwiftOnSecurity sysmon-config + NIST 800-92.
IR_EVENT_IDS = {
    # Security log (authentication, privilege, audit)
    ("Security", 4624): {"action": "logon",                       "attack": "T1078"},
    ("Security", 4625): {"action": "logon_failed",                "attack": "T1110"},
    ("Security", 4634): {"action": "logoff",                      "attack": "T1078"},
    ("Security", 4648): {"action": "explicit_credential_logon",   "attack": "T1078"},
    ("Security", 4672): {"action": "special_privilege_logon",     "attack": "T1078"},
    ("Security", 4688): {"action": "process_created",             "attack": "T1059"},
    ("Security", 4697): {"action": "service_installed",           "attack": "T1543.003"},
    ("Security", 4720): {"action": "user_account_created",        "attack": "T1136"},
    ("Security", 4732): {"action": "user_added_to_priv_group",    "attack": "T1098"},
    ("Security", 4768): {"action": "tgt_requested",               "attack": "T1558"},
    ("Security", 4769): {"action": "service_ticket_requested",    "attack": "T1558.003"},
    ("Security", 4776): {"action": "ntlm_authentication",         "attack": "T1110"},
    ("Security", 5140): {"action": "network_share_accessed",      "attack": "T1135"},
    ("Security", 7045): {"action": "service_installed_legacy",    "attack": "T1543.003"},
    ("Security", 1102): {"action": "audit_log_cleared",           "attack": "T1070.001"},
    # System log
    ("System", 7045):   {"action": "service_installed",           "attack": "T1543.003"},
    # Sysmon operational
    ("Microsoft-Windows-Sysmon/Operational",  1): {"action": "process_create",       "attack": "T1059"},
    ("Microsoft-Windows-Sysmon/Operational",  2): {"action": "file_creation_time",   "attack": "T1070.006"},
    ("Microsoft-Windows-Sysmon/Operational",  3): {"action": "network_connect",      "attack": "T1071"},
    ("Microsoft-Windows-Sysmon/Operational",  5): {"action": "process_terminate",    "attack": ""},
    ("Microsoft-Windows-Sysmon/Operational",  7): {"action": "image_loaded",         "attack": "T1574.001"},
    ("Microsoft-Windows-Sysmon/Operational",  8): {"action": "create_remote_thread", "attack": "T1055"},
    ("Microsoft-Windows-Sysmon/Operational", 10): {"action": "process_access",       "attack": "T1003.001"},
    ("Microsoft-Windows-Sysmon/Operational", 11): {"action": "file_create",          "attack": "T1105"},
    ("Microsoft-Windows-Sysmon/Operational", 13): {"action": "registry_value_set",   "attack": "T1112"},
    ("Microsoft-Windows-Sysmon/Operational", 22): {"action": "dns_query",            "attack": "T1071.004"},
    # PowerShell operational
    ("Microsoft-Windows-PowerShell/Operational", 4103): {"action": "ps_module_log",  "attack": "T1059.001"},
    ("Microsoft-Windows-PowerShell/Operational", 4104): {"action": "ps_script_block","attack": "T1059.001"},
}

# Event Data field aliases — different EVTX channels label the same data differently.
FIELD_ALIASES = {
    "process": ("Image", "NewProcessName", "ProcessName"),
    "parent_process": ("ParentImage", "ParentProcessName"),
    "command_line": ("CommandLine",),
    "user": ("User", "SubjectUserName", "TargetUserName"),
    "image": ("Image",),
    "target_image": ("TargetImage",),
    "network": ("DestinationIp", "DestinationHostname", "SourceIp"),
}


def _ns_strip(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def _extract_event_data(elem) -> dict[str, str]:
    out: dict[str, str] = {}
    for child in elem:
        if _ns_strip(child.tag) == "Data":
            name = child.get("Name", "")
            if name:
                out[name] = (child.text or "").strip()
    return out


def _to_iso(ts: str) -> str:
    """Normalise Windows EVTX TimeCreated -> ISO-8601 UTC."""
    if not ts:
        return ""
    # Strip fractional and Z if present, then reformat
    ts = ts.replace("Z", "")
    if "." in ts:
        ts = ts.split(".", 1)[0]
    try:
        t = time.strptime(ts, "%Y-%m-%dT%H:%M:%S")
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", t)
    except ValueError:
        return ts


def _walk_evtx(path: Path) -> Iterator[dict]:
    """Yield parsed events from an .evtx file using pyevtx-rs."""
    try:
        from evtx import PyEvtxParser  # type: ignore
    except ImportError:
        print(f"[evtx] python-evtx not installed; cannot parse {path}", file=sys.stderr)
        return
    parser = PyEvtxParser(str(path))
    for record in parser.records():
        try:
            xml = record["data"]
            root = ET.fromstring(xml)
        except (KeyError, ET.ParseError):
            continue
        sys_elem = root.find("{http://schemas.microsoft.com/win/2004/08/events/event}System")
        data_elem = root.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventData")
        if sys_elem is None:
            continue
        evt: dict = {}
        for child in sys_elem:
            tag = _ns_strip(child.tag)
            if tag == "EventID":
                try:
                    evt["EventID"] = int(child.text or "0")
                except ValueError:
                    evt["EventID"] = 0
            elif tag == "Channel":
                evt["Channel"] = child.text or ""
            elif tag == "TimeCreated":
                evt["TimeCreated"] = child.get("SystemTime", "")
            elif tag == "Computer":
                evt["Computer"] = child.text or ""
        if data_elem is not None:
            evt["EventData"] = _extract_event_data(data_elem)
        else:
            evt["EventData"] = {}
        yield evt


def _filter_event(evt: dict, since_ts: str | None) -> dict | None:
    channel = evt.get("Channel", "")
    eid = evt.get("EventID", 0)
    spec = IR_EVENT_IDS.get((channel, eid))
    if spec is None:
        # Some channels carry the friendly name without the prefix — try a stripped key
        spec = IR_EVENT_IDS.get((channel.split("/")[-1], eid))
        if spec is None:
            return None
    iso_ts = _to_iso(evt.get("TimeCreated", ""))
    if since_ts and iso_ts < since_ts:
        return None
    data = evt.get("EventData", {}) or {}

    def _first(*keys: str) -> str:
        for k in keys:
            v = data.get(k)
            if v:
                return v
        return ""

    return {
        "timestamp": iso_ts,
        "source_channel": channel,
        "event_id": eid,
        "host": evt.get("Computer", ""),
        "user": _first(*FIELD_ALIASES["user"]),
        "process": _first(*FIELD_ALIASES["process"]),
        "parent_process": _first(*FIELD_ALIASES["parent_process"]),
        "command_line": _first(*FIELD_ALIASES["command_line"]),
        "image": _first(*FIELD_ALIASES["image"]),
        "target_image": _first(*FIELD_ALIASES["target_image"]),
        "network": _first(*FIELD_ALIASES["network"]),
        "action": spec["action"],
        "attack_technique": spec["attack"],
    }


def run(evtx_paths: list[Path], output: Path,
        since_ts: str | None = None) -> dict:
    output.parent.mkdir(parents=True, exist_ok=True)
    n_total, n_matched = 0, 0
    started = time.time()
    with output.open("w", encoding="utf-8") as fh:
        for p in evtx_paths:
            for evt in _walk_evtx(p):
                n_total += 1
                hit = _filter_event(evt, since_ts)
                if hit is None:
                    continue
                fh.write(json.dumps(hit, sort_keys=True, separators=(",", ":")) + "\n")
                n_matched += 1
    elapsed = time.time() - started
    return {"input_files": [str(p) for p in evtx_paths],
            "total_events": n_total, "matched_events": n_matched,
            "output": str(output), "elapsed_seconds": round(elapsed, 2)}


def main() -> int:
    p = argparse.ArgumentParser(description="HOT-layer EVTX attack filter.")
    p.add_argument("--input", type=Path, required=True,
                   help="Directory containing .evtx files, or a single .evtx file.")
    p.add_argument("--output", type=Path, required=True,
                   help="JSONL output path.")
    p.add_argument("--since", default=None,
                   help="ISO-8601 UTC; ignore events before this timestamp.")
    args = p.parse_args()

    inputs = [args.input] if args.input.is_file() else sorted(args.input.rglob("*.evtx"))
    if not inputs:
        print(f"[evtx] no .evtx files at {args.input}", file=sys.stderr)
        return 2
    result = run(inputs, args.output, since_ts=args.since)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
