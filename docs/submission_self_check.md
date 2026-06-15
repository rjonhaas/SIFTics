# Find Evil Submission Self-Check

This file mirrors the Find Evil Stage One qualification checklist and points to
the concrete repo artifacts that satisfy each requirement.

| Check | Status | Evidence |
|---|---|---|
| Repository is public | Manual verify | `https://github.com/rjonhaas/SIFTics` |
| MIT or Apache 2.0 license | Pass | [`LICENSE`](../LICENSE) contains MIT license text |
| README with setup instructions | Pass | [`README.md`](../README.md) and [`docs/QUICKSTART.md`](QUICKSTART.md) |
| Demo video | Needs final link | [`docs/demo_video.md`](demo_video.md), [`docs/demo_video_script_v2.md`](demo_video_script_v2.md) |
| Architecture diagram | Pass | [`docs/architecture.md`](architecture.md) |
| Written project description | Pass | [`docs/hackathon_submission.md`](hackathon_submission.md), [`docs/devpost_story.md`](devpost_story.md) |
| Dataset documentation | Pass | [`docs/datasets.md`](datasets.md) |
| Accuracy report | Pass | [`docs/accuracy_report.md`](accuracy_report.md) |
| Try-it-out instructions | Pass | [`docs/QUICKSTART.md`](QUICKSTART.md) |
| Agent execution logs | Pass | [`examples/szechuan_sauce/runs/2026-06-14-szechuan_sauce_2026-06-14/forensic_audit.jsonl`](../examples/szechuan_sauce/runs/2026-06-14-szechuan_sauce_2026-06-14/forensic_audit.jsonl) |
| Three-claim trace | Pass | [`examples/szechuan_sauce/runs/2026-06-14-szechuan_sauce_2026-06-14/score_card.md`](../examples/szechuan_sauce/runs/2026-06-14-szechuan_sauce_2026-06-14/score_card.md) |
| Evidence integrity section | Pass | [`docs/accuracy_report.md`](accuracy_report.md), section 4 |
| Structured narrative output | Pass | Szechuan briefings in [`examples/szechuan_sauce/runs/2026-06-14-szechuan_sauce_2026-06-14/briefings/`](../examples/szechuan_sauce/runs/2026-06-14-szechuan_sauce_2026-06-14/briefings/) |

## Fix List

1. Add the final public demo video URL to `docs/demo_video.md` and Devpost.
2. Confirm the GitHub repository is public from an unauthenticated browser.
3. Confirm GitHub detects the MIT license in the repository About panel.
4. Before final submission, run:

```bash
python -m pytest tests/test_constraints.py tests/test_ingest.py tests/test_intel_gates.py -q
python -m compileall -q siftics siftics_ui mcp_case mcp_intel
```

## Notes for Judges

The packaged Szechuan run intentionally does not include source evidence, answer
keys, or IC private key material. It includes only case state, evidence hashes,
evidence inventory, findings, briefings, IOC drafts, pending approval request,
and the hash-chained audit log.
