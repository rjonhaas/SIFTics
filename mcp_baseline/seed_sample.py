"""Seed mcp_baseline/baseline.sqlite with a curated demo subset.

When `build_baseline_db.py` (the canonical builder) has not been run yet,
this gives the agent enough lookups to do meaningful demos. Real deployments
should run the canonical builder; this is the day-zero fallback.

Usage:
    python -m mcp_baseline.seed_sample
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path

from .build_baseline_db import SCHEMA, init_db, stamp_meta

# Curated minimal corpus — enough to demonstrate every lookup type SIFTics
# uses without requiring a multi-GB Rathbun clone. Sourced from publicly
# documented Microsoft binary metadata.

FILES = [
    # (path, sha256, build, edition, signer, size, version)
    (r"C:\Windows\System32\svchost.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 28832, "10.0.26200.1"),
    (r"C:\Windows\System32\svchost.exe", None,
     "22631", "Windows 11 22H2 Enterprise",
     "Microsoft Windows Publisher", 28832, "10.0.22631.1"),
    (r"C:\Windows\System32\lsass.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 87040, "10.0.26200.1"),
    (r"C:\Windows\System32\cmd.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 327680, "10.0.26200.1"),
    (r"C:\Windows\System32\powershell.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 472576, "10.0.26200.1"),
    (r"C:\Windows\System32\notepad.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 195072, "10.0.26200.1"),
    (r"C:\Windows\System32\explorer.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 4761600, "10.0.26200.1"),
    (r"C:\Windows\System32\rundll32.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 71168, "10.0.26200.1"),
    (r"C:\Windows\System32\regsvr32.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 25088, "10.0.26200.1"),
    (r"C:\Windows\System32\wmic.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 581632, "10.0.26200.1"),
    (r"C:\Windows\System32\schtasks.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 195584, "10.0.26200.1"),
    (r"C:\Windows\System32\net.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 88064, "10.0.26200.1"),
    (r"C:\Windows\System32\nbtstat.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 38912, "10.0.26200.1"),
    (r"C:\Windows\SysWOW64\svchost.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 28832, "10.0.26200.1"),
    (r"C:\Windows\explorer.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 4761600, "10.0.26200.1"),
    (r"C:\Windows\System32\winlogon.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 813056, "10.0.26200.1"),
    (r"C:\Windows\System32\csrss.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 17920, "10.0.26200.1"),
    (r"C:\Windows\System32\services.exe", None,
     "26200", "Windows 11 23H2 Enterprise",
     "Microsoft Windows Publisher", 833024, "10.0.26200.1"),
]

# Common stock Run keys — agent uses these to differentiate added persistence
RUN_KEYS = [
    # (hive, key_path, value_name, build, edition)
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "SecurityHealth",
     "26200", "Windows 11 23H2 Enterprise"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "RtkAudUService",
     "26200", "Windows 11 23H2 Enterprise"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "MicrosoftEdgeAutoLaunch",
     "26200", "Windows 11 23H2 Enterprise"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "OneDrive",
     "26200", "Windows 11 23H2 Enterprise"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "MicrosoftEdgeAutoLaunch",
     "26200", "Windows 11 23H2 Enterprise"),
]

# Stock services — known clean
SERVICES = [
    # (name, image_path, build, edition)
    ("Schedule", r"C:\Windows\System32\svchost.exe -k netsvcs",
     "26200", "Windows 11 23H2 Enterprise"),
    ("EventLog", r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted",
     "26200", "Windows 11 23H2 Enterprise"),
    ("Dnscache", r"C:\Windows\System32\svchost.exe -k NetworkService",
     "26200", "Windows 11 23H2 Enterprise"),
    ("WinDefend", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18*\MsMpEng.exe",
     "26200", "Windows 11 23H2 Enterprise"),
    ("Sense", r"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe",
     "26200", "Windows 11 23H2 Enterprise"),
    ("BITS", r"C:\Windows\System32\svchost.exe -k netsvcs",
     "26200", "Windows 11 23H2 Enterprise"),
    ("LanmanServer", r"C:\Windows\System32\svchost.exe -k netsvcs",
     "26200", "Windows 11 23H2 Enterprise"),
    ("LanmanWorkstation", r"C:\Windows\System32\svchost.exe -k NetworkService",
     "26200", "Windows 11 23H2 Enterprise"),
]

# Stock Scheduled Tasks — known clean
SCHEDULED = [
    # (task_name, action, build, edition)
    (r"\Microsoft\Windows\Defrag\ScheduledDefrag", "defrag",
     "26200", "Windows 11 23H2 Enterprise"),
    (r"\Microsoft\Windows\Maintenance\WinSAT", "winsat.exe",
     "26200", "Windows 11 23H2 Enterprise"),
    (r"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
     "MpCmdRun.exe", "26200", "Windows 11 23H2 Enterprise"),
    (r"\Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
     "MpCmdRun.exe", "26200", "Windows 11 23H2 Enterprise"),
    (r"\Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work",
     "UsoClient.exe", "26200", "Windows 11 23H2 Enterprise"),
]


def main() -> int:
    p = argparse.ArgumentParser(description="Seed a sample baseline DB for SIFTics demos.")
    p.add_argument("--output", type=Path,
                    default=Path(__file__).parent / "baseline.sqlite")
    args = p.parse_args()

    conn = init_db(args.output)
    cur = conn.cursor()
    for path, sha256, build, edition, signer, size, version in FILES:
        cur.execute(
            "INSERT INTO files(path, sha256, build, edition, signer, size, version) "
            "VALUES (?,?,?,?,?,?,?)",
            (path, sha256.lower() if sha256 else None,
             build, edition, signer, size, version),
        )
    for hive, kp, vn, build, edition in RUN_KEYS:
        cur.execute(
            "INSERT INTO registry(hive, key_path, value_name, value_data_hash, "
            "build, edition) VALUES (?,?,?,?,?,?)",
            (hive, kp, vn, None, build, edition),
        )
    for name, image, build, edition in SERVICES:
        cur.execute(
            "INSERT INTO services(name, image_path, sha256, build, edition) "
            "VALUES (?,?,?,?,?)",
            (name, image, None, build, edition),
        )
    for task_name, action, build, edition in SCHEDULED:
        cur.execute(
            "INSERT INTO scheduled(task_name, action, build, edition) "
            "VALUES (?,?,?,?)",
            (task_name, action, build, edition),
        )
    stamp_meta(
        conn,
        built_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        source="siftics seed_sample.py (curated demo subset)",
        source_files="github.com/AndrewRathbun/VanillaWindowsReference (canonical)",
        source_registry="github.com/AndrewRathbun/VanillaWindowsRegistryHives (canonical)",
        note="Run `python -m mcp_baseline.build_baseline_db` for the full corpus.",
    )
    conn.commit()
    conn.close()
    print(f"[seed] wrote demo baseline DB to {args.output}")
    print(f"[seed] {len(FILES)} files, {len(RUN_KEYS)} run keys, "
          f"{len(SERVICES)} services, {len(SCHEDULED)} scheduled tasks")
    print("[seed] for the full Rathbun corpus, run "
          "`python -m mcp_baseline.build_baseline_db`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
