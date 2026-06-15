# Devpost Story Draft

## Inspiration

SIFTics started from a practical incident-response problem: attackers can move
through an environment faster than a tired human team can triage every artifact.
The goal was not to replace the analyst. The goal was to make the SIFT
Workstation behave like a disciplined investigation teammate that records its
work, asks for authority at the right moments, and leaves enough evidence for a
reviewer to trust or reject each claim.

## What It Does

SIFTics turns a SIFT Workstation case directory into a Common Operating Picture.
It inventories real evidence, runs typed DFIR tools through MCP servers, writes
durable findings, maintains affected-system state, drafts briefings, proposes
IOCs, and blocks high-authority actions behind Incident Commander approval.

The differentiator is the handoff from finding to action. Most DFIR agents stop
at "here is what happened." SIFTics turns evidence-backed findings into
controlled response options: IOCs, Velociraptor hunts, and containment
proposals. The agent can prepare the defensive move, but the Incident Commander
and OT safety gates decide what is allowed to execute.

The latest packaged accuracy run is DFIR Madness Stolen Szechuan Sauce:

`examples/szechuan_sauce/runs/2026-06-14-szechuan_sauce_2026-06-14/`

That run includes 18 findings, two briefings, a hash-chained audit log, evidence
hashes, a score card, and a documented correction where the agent first
misread a OneDrive transfer as exfiltration and later corrected it using
directional PCAP byte counts.

## How We Built It

The system is built around typed MCP tools rather than raw shell access. The UI
launches the agent with a case-scoped operating contract and Investigation
Section Chief role context. The case MCP server exposes evidence inventory,
findings, inquiry lines, briefings, ASR state, and completeness checks. Separate
gate and intel paths require signed approval objects before publication or
fleet-impacting action.

The web UI is a Common Operating Picture first: current incident state,
evidence ledger, authority gates, inquiry lines, and the live agent workbench
are visible from the dashboard.

## Challenges

The hardest part was keeping the agent from sounding productive while failing
to persist reviewer-visible evidence. Early runs produced useful narration but
not enough durable case state. The fix was a combination of stricter tool
contracts, deterministic evidence ingest, better dashboard feedback, and
explicit Lines of Inquiry that are driven by the evidence manifest instead of a
static questionnaire.

Another challenge was honest accuracy reporting. The Szechuan run had one real
false positive. Rather than hiding it, the report traces the original claim,
the correction, and the final ASR update.

## What We Learned

Autonomy is only useful when it produces auditable state. The UI and agent
contract now treat chat as a workspace, not the system of record. Findings,
briefings, gates, and audit events are the system of record.

We also learned that an Incident Command framing works best when it is used as
an operating model, not a costume. The agent can act as an Investigation
Section Chief, but authority gates, safety stops, and audit-chain integrity
need architectural enforcement.

## What Is Next

Next work is focused on broader benchmark coverage, richer pre-close
completeness checks, tighter memory/network artifact workflows for cases with
timestomping and staged archives, and a stronger live demo loop through
`rjonhaas/hunt_lab`: Caldera launches the OT attack, ELK alerts, Velociraptor
collects triage, SIFTics investigates, and approved response actions push IOCs,
hunts, or isolation requests back through controlled gates. The immediate
submission gap is the final public demo video link.

## Built With

Python, Flask, Tailwind CSS, MCP, SIFT Workstation, Volatility, tshark,
capinfos, Plaso-class workflows, Claude Sonnet 4.6, and hash-chained JSONL
case state.
