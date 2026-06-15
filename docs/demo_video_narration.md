# Demo Video Narration Draft

Welcome to my SANS Find Evil! hackathon demonstration for SIFTics.

SIFTics is built around the NIMS Incident Command System. ICS came out of the
1970s wildfire response world, where many agencies needed one operating model
for the same incident. FEMA later folded it into the National Incident
Management System. I first learned this framework as a corrections officer, and
the part that stuck with me was its modularity: you can run a small incident
with only a few roles, or expand quickly when the situation demands it.

That structure maps well to incident response. The agent acts as the
Investigation Section Chief. The human analyst remains the Incident Commander.
Safety, Legal, and other command functions are not just labels; they control
what the system is allowed to do.

The point of SIFTics is not only to find evil. It is to take evidence-backed
findings and prepare defensive action: publish IOCs, push Velociraptor hunts,
and propose containment. Those actions go through Authority Gates, so the agent
can prepare the response, but the Incident Commander controls execution.

For this demo I am using my hunt_lab repository. Caldera launches the OT
water-plant scenario, ELK fires the alert, Velociraptor collects triage from the
Windows pivot host and OT HMI, and SIFTics investigates the resulting case.
The Caldera debrief and ground truth stay outside the agent's case directory.

The case starts from the same kind of handoff a SOC analyst would receive:
brute-force activity against an OT HMI, a suspected Windows pivot host, and
possible water-treatment configuration tamper. That briefing orients the agent,
but it is not treated as ground truth.

On the dashboard, the Common Operating Picture is the first screen. The Agent
Workbench is where the investigation runs. The Incident State, Evidence Ledger,
Lines of Inquiry, and Authority Gates are the durable record. Chat is just the
workspace.

As the agent works, it records findings against real artifacts. For the OT case,
the claims to watch are the Windows pivot, the failed and successful SSH logins
against the HMI operator account, and the chlorine setpoint/configuration
change. Each claim needs an artifact path, tool, command, and output excerpt.

The differentiator is what happens next. Most DFIR agents stop after the
timeline or report. SIFTics turns the findings into response options. It can
draft IOCs, propose a Velociraptor hunt, and open a containment or isolation
request.

The system still refuses unsafe action. In the OT scenario, isolating a
water-treatment HMI is not the same as isolating a laptop. The Safety Officer
path can block or escalate the action because personnel and process safety are
involved. That refusal is architectural: no signable approval object is created
for the agent to bypass.

Everything is written to a hash-chained audit log. The judge can verify the
chain, inspect the findings, and follow the action proposal back to the evidence
that created it.

That is the core claim: SIFTics finds evil, prepares the fight-back move, and
keeps command authority and safety controls in the loop.
