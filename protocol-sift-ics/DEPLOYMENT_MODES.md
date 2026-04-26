# Deployment Modes

Protocol SIFT ICS supports **three inference deployment modes**. The choice is made at deployment time via `config/openclaw.json` → `inference_mode`. The swarm's architectural invariants — read-only evidence, MCP choke point, audit log, citation rule — do not change with inference mode. Only where the model weights live and how requests reach them changes.

| Mode | Endpoint | Default for | Compliance ceiling | Implementation status |
|---|---|---|---|---|
| `cloud_direct` | Anthropic API | Development, hackathon demo, individual responders | TLS in transit; standard Anthropic ToS | ✅ Wired |
| `cloud_managed` | AWS Bedrock (or Azure OpenAI / GCP Vertex) | **Most commercial DFIR firms** | HIPAA BAA via AWS BAA; FedRAMP Moderate/High in select regions; data residency is operator-selected | 🟡 Skeleton only — config shape exists, SDK integration is roadmap work |
| `local` | OpenAI-compatible endpoint serving Claude weights on-prem | Classified work, defense, healthcare cases that cannot egress | Defined entirely by operator's environment; no shared trust boundary | 🟡 Skeleton only — config shape exists, SDK integration is roadmap work |

## Why three modes (and not two)

The original design had `cloud` and `local`. That's wrong for the most important commercial adoption path. A managed DFIR firm investigating a healthcare breach typically:

- **Cannot use direct Anthropic API access**, because their client's BAA only covers their existing AWS/Azure/GCP footprint.
- **Cannot use fully on-prem inference** in most cases, because they don't have GPU capacity to run Claude-class models with acceptable latency.
- **Can use Bedrock** because it's already inside their AWS account, the BAA chain is intact (client BAA → DFIR firm BAA → AWS BAA), and the data residency story is whatever region they were already using.

`cloud_managed` is the mode that unlocks adoption for the largest segment of the target market. `cloud_direct` is for development. `local` is for the cases where neither cloud option clears compliance review.

## Mode 1 — `cloud_direct`

**What it is:** the swarm calls `https://api.anthropic.com` directly. Auth via `ANTHROPIC_API_KEY`.

**When to pick it:**
- Development and iteration
- Hackathon demo
- Individual practitioner / consultant working on data they own
- Synthetic fixtures (the accuracy harness)

**When NOT to pick it:**
- Any client engagement under a BAA
- Any data subject to FedRAMP, ITAR, EAR, CMMC, or sectoral regulations beyond the basic CFAA forensic carve-outs
- Any environment with egress controls that block external HTTPS to consumer SaaS

**Config:**
```json
{
  "inference_mode": "cloud_direct"
}
```

Environment:
```bash
export ANTHROPIC_API_KEY="sk-ant-…"
```

**Network footprint:** outbound HTTPS to `api.anthropic.com` only. No inbound. The MCP server, evidence mount, working directory, and audit log are all local.

**Cost model:** pay-per-token to Anthropic. A typical operational period across the 17 skills, with Opus on IC/Legal and Sonnet on branches, lands in the low single-digit dollars per case for small fixtures and roughly $20–$100 for multi-host real cases. The `budget_caps` block in `openclaw.json` enforces a per-incident token cap; default 8.5M tokens.

## Mode 2 — `cloud_managed`

**What it is:** the swarm calls a managed inference service inside the responder's existing cloud account. Same Claude weights, but the request never leaves the responder's cloud trust boundary.

Three concrete back ends are supported by this mode (the config shape is identical; only `type` and model IDs differ):

- **AWS Bedrock** — `type: "bedrock"`, region from `AWS_REGION`, IAM-role auth. **Most important for commercial DFIR adoption.** Bedrock has the broadest BAA coverage for healthcare clients and the broadest FedRAMP authorization for federal/SLED clients.
- **Azure OpenAI** — `type: "azure_openai"`, deployment name from config. Useful for Microsoft-shop clients with existing Azure governance.
- **GCP Vertex AI** — `type: "vertex_ai"`. Less common in DFIR but appropriate for clients already on GCP.

**When to pick it:**
- Any commercial DFIR engagement under a client BAA
- Any environment with egress controls that block direct internet access but permit AWS service endpoints
- Any FedRAMP Moderate/High workload (use a Bedrock region with the appropriate authorization)
- Multi-tenant DFIR firm where each client's evidence must stay in that client's cloud account

**When NOT to pick it:**
- Air-gapped networks
- Classified work above the FedRAMP High ceiling
- Cases where the client refuses any cloud egress, including intra-cloud

**Config (Bedrock example):**
```json
{
  "inference_mode": "cloud_managed",
  "inference_endpoints": {
    "cloud_managed": {
      "type": "bedrock",
      "region": { "env_var": "AWS_REGION" },
      "auth": { "method": "iam_role" },
      "model_ids": {
        "opus":   "anthropic.claude-opus-4-7-v1:0",
        "sonnet": "anthropic.claude-sonnet-4-6-v1:0",
        "haiku":  "anthropic.claude-haiku-4-5-v1:0"
      }
    }
  }
}
```

Environment:
```bash
export AWS_REGION="us-east-1"        # or whichever region holds your BAA / FedRAMP authorization
# IAM role attached to the EC2 / ECS / Lambda running the swarm
# OR: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY for non-IAM-role environments
```

**Network footprint:** outbound HTTPS to the Bedrock VPC endpoint (`bedrock-runtime.<region>.amazonaws.com`). Configure a VPC interface endpoint to keep traffic on the AWS backbone. No public internet egress required.

**Compliance posture:**
- **HIPAA:** Bedrock is covered under the AWS BAA. The DFIR firm signs a BAA with the client; AWS's BAA covers the firm; the chain is intact.
- **FedRAMP:** Bedrock has FedRAMP Moderate authorization in commercial regions and FedRAMP High in GovCloud (verify exact authorization status at deployment — these change). Use the FedRAMP-authorized region for in-scope workloads.
- **Data residency:** the request, the response, and the inference happen in the operator-selected region. No cross-region routing.
- **Logging:** Bedrock CloudTrail logs every model invocation. Combine with the swarm's own audit log for end-to-end traceability.

**Cost model:** AWS Bedrock pricing (per 1K input/output tokens, by model). Generally 5–15% higher per token than direct Anthropic API. Worth it when compliance is the deciding factor.

**What's NOT yet implemented:** the SDK integration. The config shape is final; the runtime that maps a logical Claude call to a Bedrock InvokeModel request is roadmap work. Until then, attempting to start the swarm with `inference_mode: "cloud_managed"` will fail at gateway init with a clear error pointing here.

## Mode 3 — `local`

**What it is:** on-prem inference. Claude weights served by a vLLM/TGI/SGLang deployment behind an OpenAI-compatible API endpoint inside the responder's network.

**When to pick it:**
- Air-gapped networks (no cloud egress permitted at all)
- Classified work above FedRAMP High
- Healthcare or defense cases where the client's contract explicitly forbids cloud inference
- Sovereign / data-residency requirements that no cloud region satisfies

**When NOT to pick it:**
- Anything where `cloud_managed` would clear compliance — local is harder to operate, harder to keep current with model updates, and quality/latency depend entirely on the local hardware
- Workloads requiring the latest model release the moment it ships (local deployments lag cloud by weeks to months)
- Bursty workloads — local capacity is sized for peak; idle GPU is wasted

**When NOT to pretend you're using it:**
- Running a smaller open-weight model locally and calling it "local Claude" is not the same thing. The swarm's prompts, citation rules, and confidence calibration were tuned against actual Claude weights. A different model can be plugged in, but expect accuracy regression — characterize it with the accuracy harness before deploying.

**Config:**
```json
{
  "inference_mode": "local",
  "inference_endpoints": {
    "local": {
      "type": "openai_compatible",
      "base_url": { "env_var": "LOCAL_INFERENCE_URL" },
      "auth": { "method": "bearer_token", "env_var": "LOCAL_INFERENCE_TOKEN" },
      "model_ids": {
        "opus":   { "env_var": "LOCAL_OPUS_MODEL" },
        "sonnet": { "env_var": "LOCAL_SONNET_MODEL" },
        "haiku":  { "env_var": "LOCAL_HAIKU_MODEL" }
      }
    }
  }
}
```

Environment:
```bash
export LOCAL_INFERENCE_URL="https://inference.internal.example.invalid/v1"
export LOCAL_INFERENCE_TOKEN="…"
export LOCAL_OPUS_MODEL="claude-opus-4-7"     # whatever the local server registers
export LOCAL_SONNET_MODEL="claude-sonnet-4-6"
export LOCAL_HAIKU_MODEL="claude-haiku-4-5"
```

**Network footprint:** the swarm and the inference endpoint share a private network. No outbound internet required for inference. Outbound may still be needed for software updates (npm, pip, SIFT package mirror).

**Hardware sizing:** entirely operator's call. Claude-class model serving requires multi-GPU systems (H100/H200/MI300 class). If you don't have that capacity, `cloud_managed` is the right answer.

**What's NOT yet implemented:** same as Bedrock — config shape is final, SDK adapter is roadmap work.

## What stays the same across all three modes

These are architectural invariants. The deployment mode selects the inference endpoint; it does not relax any of them.

- **Only `logistics/tool-broker` invokes the MCP server.** Same in all modes.
- **Evidence is mounted read-only.** Same.
- **PathGuard + ReadOnlyGuard run on every call.** Same.
- **Every finding cites a `tool_execution_id`.** Same.
- **Append-only hash-chained audit log.** Same. The audit log records the inference mode and the resolved model ID per call, so a finding's full trace includes which endpoint produced it.
- **Spoliation, injection, and accuracy harnesses pass.** Same. The harnesses do not depend on inference mode; they verify the architecture, not the weights.

## Switching modes

Switching modes is a deployment-time edit, not a runtime flag. To switch:

1. Stop the OpenClaw gateway.
2. Edit `config/openclaw.json` → `inference_mode`.
3. Set the appropriate environment variables for that mode.
4. Restart the gateway.

There is no per-call inference_mode override. There is no "fall back to local if cloud fails" behavior. Mixing modes within a single incident response would muddy the audit trail (what model produced what finding?) and undermine the citation invariant. If you need to change mode mid-engagement, that is a new operational period — close the current one, document the switch, start a new one.

## Roadmap

In rough priority order:

1. **Bedrock SDK adapter.** This is the highest-impact integration because it unlocks the largest commercial segment. Implementation requires a thin wrapper that maps Anthropic SDK calls to `bedrock-runtime:InvokeModel` (or the streaming variant) and back. Estimated 200–400 lines plus tests.
2. **Audit log enrichment.** Each MCP call already records `tool_execution_id`; extend the audit log entry to also record `inference_mode` and the resolved `model_id`. The query `trace_finding(FND-N)` should return both. ~50 lines.
3. **Mode validation at gateway init.** Refuse to start with `inference_mode: "cloud_managed"` or `"local"` until the corresponding adapter is wired, with a clear error message pointing to this document.
4. **Azure OpenAI + Vertex adapters.** Same shape as Bedrock; lower priority.
5. **Local OpenAI-compatible adapter.** vLLM/TGI/SGLang serve OpenAI-compatible APIs natively, so this is mostly a config + auth concern.

## A note on cost and audit comparability

A single finding produced under `cloud_direct` is the same finding under `cloud_managed` — the model weights are identical and the Anthropic-issued model versions are the same. Cost differs (Bedrock typically 5–15% higher per token); latency may differ (Bedrock regional edge versus Anthropic's edge); but the architecture's correctness claim does not.

`local` introduces variance. Even with identical Claude weights, serving stack differences (KV-cache quantization, batch scheduling, attention implementations) can produce small numerical differences in outputs, which can compound across a multi-skill operational period. **Run the accuracy harness against your local deployment before relying on it for client work.** If F1 drifts more than 0.05 from the cloud baseline on the same fixtures, investigate before deploying.
