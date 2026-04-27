#!/usr/bin/env python3
"""Generate audit_log.jsonl with a real sha256 hash chain.

Chain rule: this_hash = sha256(prev_hash || canonical_json(audit_id, timestamp, subagent, event_type, payload)).
"""
import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "public" / "case-stub" / "audit_log.jsonl"

PERIOD_REASONING = {
    1: "Three evidence sources delivered: DC01 disk, DC01 memory, perimeter PCAP. Triage to broad first-pass; Forensics, Memory, Network branches activated in parallel; Malware on standby until a binary is flagged.",
    2: "Triage surfaced an external RDP logon for svc-backup with no prior interactive history. Forensics located update.exe and Run-key persistence; Memory found PID 3284. Activate Malware to triage update.exe in place.",
    3: "Memory reported PID 3284 as the C2 process. Forensics' Prefetch hash for update.exe did not match the in-memory image base on first comparison. Re-task Forensics: verify whether Prefetch corresponds to the same binary as PID 3284 — hypothesis is that the attacker renamed it. Lateral movement also needs mapping.",
    4: "Cross-source corroboration is now in place for initial access, persistence, credential access, lateral movement, and C2. Quantify exfiltration and clear Documentation Unit to publish.",
}

PERIOD_OBJECTIVE = {
    1: "Inventory provided evidence and establish baseline timeline of suspicious activity.",
    2: "Determine root cause of the svc-backup logon and characterize the executable referenced by Run-key persistence.",
    3: "Resolve the apparent Prefetch vs in-memory image-base contradiction, then map lateral movement and collection.",
    4: "Quantify exfiltration, finalize IOCs, verify cross-source corroboration, and publish the final report.",
}

FINDINGS = [
    ("FND-001", 1, "triage_section_chief", "EvtxECmd", {"evtx": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "filter": "EventID:4624 AND LogonType:10"}, "2020-09-20T04:21:14Z", "Triage Branch — surface anomalous RDP logons in DC01 Security.evtx", "DC01 disk image is mounted; Security.evtx is the cheapest first-pass for external RDP logons."),
    ("FND-002", 1, "forensics_section_chief", "AmcacheParser", {"hive": "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "filter": "account:svc-backup"}, "2020-09-20T04:21:18Z", "Forensics Branch — corroborate svc-backup logon via session/account artifacts", "FND-001 needs corroboration on disk before we trust Triage's first pass."),
    ("FND-003", 1, "network_section_chief", "zeek_conn", {"pcap": "EVID-003.pcap", "filter": "id.resp_p == 3389"}, "2020-09-20T04:21:14Z", "Network Branch — confirm an inbound RDP session at the time of the Security event", "Cross-source corroboration of FND-001 from the network capture."),
    ("FND-004", 1, "memory_section_chief", "vol3_windows.pslist", {"image": "EVID-002.mem", "filter": "ppid==712"}, "2020-09-20T04:24:11Z", "Memory Branch — enumerate svchost children with anomalous image paths", "Standard initial pass on memory once we suspect post-RDP execution."),
    ("FND-005", 2, "forensics_section_chief", "MFTECmd", {"mft": "C:\\$MFT", "filter": "path:C:\\Windows\\Temp\\update.exe"}, "2020-09-20T04:24:11Z", "Forensics Branch — locate update.exe on disk and capture its hash", "Need the on-disk binary to compare against PID 3284's image."),
    ("FND-006", 2, "forensics_section_chief", "RegRipper", {"hive": "NTUSER.DAT (svc-backup)", "plugin": "run"}, "2020-09-20T04:31:09Z", "Forensics Branch — enumerate Run-key persistence under svc-backup", "Standard persistence triage once a suspect account is identified."),
    ("FND-007", 2, "forensics_section_chief", "PECmd", {"prefetch_dir": "C:\\Windows\\Prefetch\\", "filter": "RUNDLL32.EXE-*.pf"}, "2020-09-20T04:43:02Z", "Forensics Branch — look for credential-dumping artifacts on disk", "Run-key + RDP session strongly suggests follow-on credential access."),
    ("FND-008", 2, "memory_section_chief", "vol3_windows.cmdline", {"image": "EVID-002.mem", "filter": "image:rundll32.exe"}, "2020-09-20T04:42:51Z", "Memory Branch — pull command lines for any rundll32 instances", "Corroborate FND-007 from memory to confirm the dump was actually invoked."),
    ("FND-009", 3, "forensics_section_chief", "bmc-tools", {"bcache": "DESKTOP-SDN1RPT C:\\Users\\svc-backup\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\bcache24.bmc"}, "2020-09-20T06:18:51Z", "Forensics Branch — recover RDP cache bitmaps on workstation", "Following the lateral-movement hypothesis from period 2 close-out."),
    ("FND-010", 3, "forensics_section_chief", "EvtxECmd", {"evtx": "DESKTOP-SDN1RPT Security.evtx", "filter": "EventID:4624 AND LogonType:10 AND SourceWorkstation:DC01"}, "2020-09-20T06:18:42Z", "Forensics Branch — confirm Logon Type 10 on workstation sourced from DC01", "Cross-host RDP requires the destination Security log to confirm the session."),
    ("FND-011", 3, "forensics_section_chief", "SBECmd", {"shellbags": "DESKTOP-SDN1RPT NTUSER.DAT (svc-backup)"}, "2020-09-20T07:48:02Z", "Forensics Branch — characterize attacker traversal of \\\\DC01\\Sales", "Bitmap fragments suggested Sales-share access; ShellBags will quantify."),
    ("FND-012", 4, "network_section_chief", "zeek_ssl_ja3", {"pcap": "EVID-003.pcap", "filter": "ja3:72a589da586844d7f0818ce684948eea"}, "2020-09-20T04:24:48Z", "Network Branch — fingerprint outbound TLS for known C2 JA3", "Cross-source the in-memory PID 3284 with network-side beacon evidence."),
    ("FND-013", 4, "network_section_chief", "zeek_dns", {"pcap": "EVID-003.pcap", "filter": "qname:drudge-report.tk"}, "2020-09-20T04:24:46Z", "Network Branch — resolve C2 domain to IP for infrastructure overlap check", "Confirm whether C2 IP overlaps with the initial-access source."),
    ("FND-014", 4, "network_section_chief", "zeek_http", {"pcap": "EVID-003.pcap", "filter": "method:PUT AND host:drudge-report.tk"}, "2020-09-20T09:14:33Z", "Network Branch — quantify HTTPS PUT volume to attacker domain", "Final exfiltration sizing for the report."),
]

def canonical(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


def append(entries, audit_id, timestamp, subagent, event_type, payload):
    prev_hash = entries[-1]["this_hash"] if entries else "0" * 64
    body = canonical({
        "audit_id": audit_id,
        "timestamp": timestamp,
        "subagent": subagent,
        "event_type": event_type,
        "payload": payload,
    })
    this_hash = hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()
    entries.append({
        "audit_id": audit_id,
        "timestamp": timestamp,
        "subagent": subagent,
        "event_type": event_type,
        "payload": payload,
        "prev_hash": prev_hash,
        "this_hash": this_hash,
    })


def main():
    entries = []
    counter = 0

    def next_id():
        nonlocal counter
        counter += 1
        return f"AUDIT-{counter:07d}"

    period_start_ts = {1: "2020-09-20T04:18:00Z", 2: "2020-09-20T04:30:00Z", 3: "2020-09-20T05:55:00Z", 4: "2020-09-20T08:30:00Z"}

    last_ic_id = {}
    last_obj_id = {}

    for period in (1, 2, 3, 4):
        ts = period_start_ts[period]
        ic_id = next_id()
        append(entries, ic_id, ts, "ic", "ic_reasoning", {
            "period": period,
            "reasoning": PERIOD_REASONING[period],
        })
        last_ic_id[period] = ic_id

        obj_id = next_id()
        append(entries, obj_id, ts, "ic", "objective_set", {
            "period": period,
            "objective": PERIOD_OBJECTIVE[period],
            "parent_audit_id": ic_id,
        })
        last_obj_id[period] = obj_id

        bnd_id = next_id()
        append(entries, bnd_id, ts, "situation_unit", "period_boundary", {
            "period": period,
            "transition": f"period_{period}_open",
        })

        for f in FINDINGS:
            fid, fperiod, subagent, mcp, params, observed_at, message, _reason = f
            if fperiod != period:
                continue

            msg_id = next_id()
            append(entries, msg_id, observed_at, subagent, "inter_skill_message", {
                "from_subagent": "ic" if "section_chief" in subagent else subagent,
                "to_subagent": subagent,
                "message": message,
                "period": period,
                "parent_audit_id": obj_id,
            })

            exec_num = int(fid.split("-")[1])
            tool_exec_id = f"EXEC-{exec_num:04d}"

            tool_id = next_id()
            append(entries, tool_id, observed_at, subagent, "tool_invocation", {
                "tool_execution_id": tool_exec_id,
                "mcp_function": mcp,
                "parameters": params,
                "parent_audit_id": msg_id,
            })

            fnd_id = next_id()
            append(entries, fnd_id, observed_at, subagent, "finding_produced", {
                "finding_id": fid,
                "tool_execution_id": tool_exec_id,
                "parent_audit_id": tool_id,
            })

        if period == 3:
            sh_id = next_id()
            append(entries, sh_id, "2020-09-20T05:50:00Z", "situation_unit", "safety_halt", {
                "reason": "Memory PID 3284 image base does not match update.exe SHA256 from disk. Pause before reporting until the contradiction is resolved.",
                "period": 3,
            })
            sc_id = next_id()
            append(entries, sc_id, "2020-09-20T05:53:00Z", "situation_unit", "safety_clear", {
                "reason": "Forensics confirmed the attacker renamed update.exe in place after first execution; the in-memory image and the original on-disk creation event are the same binary.",
                "period": 3,
                "parent_audit_id": sh_id,
            })

    OUT.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    print(f"wrote {len(entries)} audit entries to {OUT}")


if __name__ == "__main__":
    main()
