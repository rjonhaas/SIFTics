from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path


def test_case_ingest_inventories_zip_extracts_small_high_value_members(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTICS_CASE_DIR", str(tmp_path))
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with zipfile.ZipFile(evidence / "bundle.zip", "w") as zf:
        zf.writestr("case001.pcap", b"\xd4\xc3\xb2\xa1fake")
        zf.writestr("notes/readme.txt", "operator notes")
        zf.writestr("disk/DC01.E01", b"EWF")

    from siftics import audit, ingest

    manifest = ingest.run_case_ingest(tmp_path, max_extract_bytes=1024)

    assert manifest["evidence_file_count"] == 1
    assert manifest["evidence"][0]["kind"] == "zip_container"
    assert manifest["evidence"][0]["zip"]["member_count"] == 3
    assert manifest["evidence"][0]["zip"]["member_type_counts"]["network_capture"] == 1
    assert manifest["evidence"][0]["zip"]["member_type_counts"]["disk_image"] == 1
    extracted = manifest["evidence"][0]["zip"]["extracted"]
    extracted_names = {Path(row["path"]).name for row in extracted}
    assert {"case001.pcap", "readme.txt"} <= extracted_names
    assert "DC01.E01" not in extracted_names
    assert (tmp_path / "evidence_manifest.json").exists()
    assert (tmp_path / "evidence_quicklook.md").exists()

    events = list(audit.iter_events())
    assert events[-1]["type"] == "case_ingest_completed"
    assert events[-1]["actor"] == "dfir-operations"
    assert events[-1]["payload"]["extracted_count"] == 2


def test_ensure_case_ingest_uses_current_manifest_without_reaudit(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTICS_CASE_DIR", str(tmp_path))
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "artifact.txt").write_text("hello", encoding="utf-8")

    from siftics import audit, ingest

    first = ingest.ensure_case_ingest(tmp_path)
    second = ingest.ensure_case_ingest(tmp_path)

    assert first["evidence"][0]["sha256"] == second["evidence"][0]["sha256"]
    events = [ev for ev in audit.iter_events() if ev["type"] == "case_ingest_completed"]
    assert len(events) == 1

    manifest = json.loads((tmp_path / "evidence_manifest.json").read_text(encoding="utf-8"))
    assert manifest["evidence"][0]["name"] == "artifact.txt"
    assert os.environ["SIFTICS_CASE_DIR"] == str(tmp_path)
