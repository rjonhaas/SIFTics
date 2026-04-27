# SIFTics Story View

Static React page that renders the swarm's structured JSON outputs as a six-section investigative narrative. The deliverable surface for SIFTics — what executives, legal counsel, and downstream IR teams read after the swarm finishes.

## Sections

1. Executive Summary — CISO-readable in 15 seconds
2. Attack Narrative — MITRE-mapped phases with past-tense prose
3. Timeline — horizontal Recharts visualization, color-coded by tactic
4. Cross-Source Correlation — facts confirmed by multiple evidence sources
5. IOC List — file hashes / IPs / domains / registry / paths, each linked to its provenance
6. Audit Explorer — `trace_finding(FND-N)` rendered as a hash-chain tree

## Stack

React 18, Vite, TypeScript, Tailwind, lucide-react, Recharts. No backend, no auth, no browser storage.

## Develop

```bash
npm install
npm run dev
```

Loads stub case from `public/case-stub/` (Stolen Szechuan Sauce scenario).

## Build

```bash
npm run build
npm run serve   # python -m http.server on dist/
```

## JSON Contract

The story view reads four files from the case directory:

- `final_report.json` — Documentation Unit's final output
- `findings.json` — flat list of every finding produced
- `cop.json` — Situation Unit's Common Operating Picture
- `audit_log.jsonl` — append-only hash-chained audit log

Schema is defined in `src/types.ts`.

## Deployment

Copy the case JSON next to `dist/index.html` (or symlink `dist/case-stub/`), then serve the directory with any static server. The orchestrator's responsibility is producing the JSON; the story view's responsibility is rendering it.
