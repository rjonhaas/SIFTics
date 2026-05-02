# Skill: Cloud Forensics (AWS GuardDuty / CloudTrail / S3)

## Overview
Use this skill for AWS cloud incident response on the SIFT workstation. Evidence arrives as
compressed log files (GuardDuty `.jsonl.gz`, CloudTrail `.json.gz`) copied from S3 or delivered
by the customer. All analysis is read-only against local copies — never modify originals.

---

## Evidence Layout

```
./analysis/cloud/          # parsed output, pivot files
./exports/cloud/           # extracted log JSON, decompressed files
<case_root>/               # raw evidence: *.jsonl.gz, *.json.gz, *.json
```

---

## GuardDuty Analysis

GuardDuty findings arrive as `.jsonl.gz` (one JSON object per line, gzipped).

```bash
# Decompress a single finding file
gunzip -c <findings.jsonl.gz> > ./exports/cloud/guardduty.jsonl

# Decompress all at once
find . -name "*.jsonl.gz" -exec sh -c 'gunzip -c "$1" >> ./exports/cloud/guardduty.jsonl' _ {} \;

# List all finding types and counts (triage priority)
jq -r '.type' ./exports/cloud/guardduty.jsonl | sort | uniq -c | sort -rn

# Extract high-severity findings (severity >= 7)
jq 'select(.severity >= 7)' ./exports/cloud/guardduty.jsonl | \
  jq -r '[.updatedAt, .severity, .type, .title] | @csv' > ./analysis/cloud/gd_high_severity.csv

# Pivot by affected IAM principal
jq -r '[.updatedAt, .type, .service.action.actionType,
        (.resource.accessKeyDetails.userName // "N/A"),
        (.resource.accessKeyDetails.accessKeyId // "N/A")]
       | @csv' ./exports/cloud/guardduty.jsonl > ./analysis/cloud/gd_by_principal.csv

# Extract network threat indicators (C2, port scan, crypto mining)
jq 'select(.type | test("Backdoor|CryptoCurrency|Trojan|UnauthorizedAccess"))' \
  ./exports/cloud/guardduty.jsonl | \
  jq -r '[.updatedAt, .type,
          (.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4 // "N/A"),
          (.service.action.networkConnectionAction.remotePortDetails.port // "N/A")]
         | @csv' > ./analysis/cloud/gd_network_iocs.csv
```

**Key finding types to triage first:**
| Finding Type | Meaning |
|---|---|
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` | IMDS creds used from external IP |
| `Recon:IAMUser/UserPermissions` | Attacker enumerating IAM |
| `Persistence:IAMUser/UserPermissions` | New key/policy created |
| `Exfiltration:S3/ObjectRead.Unusual` | Unusual S3 data retrieval |
| `Impact:S3/AnomalousBehavior.Delete` | S3 object deletion (ransomware, cover tracks) |
| `CredentialAccess:Kubernetes/MaliciousIPCaller` | K8s API calls from threat IP |

---

## CloudTrail Analysis

CloudTrail logs are JSON (single file or `.json.gz`). Each file contains a `Records` array.

```bash
# Decompress CloudTrail gz files
find . -name "*.json.gz" | while read f; do
  gunzip -c "$f" >> ./exports/cloud/cloudtrail_all.json.raw
done

# Flatten Records arrays into jsonl (one event per line)
python3 - <<'EOF'
import json, sys
out = open('./exports/cloud/cloudtrail.jsonl', 'w')
with open('./exports/cloud/cloudtrail_all.json.raw') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            for rec in obj.get('Records', [obj]):
                out.write(json.dumps(rec) + '\n')
        except json.JSONDecodeError:
            pass
out.close()
print(f"Wrote {sum(1 for _ in open('./exports/cloud/cloudtrail.jsonl'))} events")
EOF

# Event frequency by eventName (top 30)
jq -r '.eventName' ./exports/cloud/cloudtrail.jsonl | sort | uniq -c | sort -rn | head -30

# Extract key fields to CSV for timeline analysis
jq -r '[.eventTime, .eventName, .eventSource,
        (.userIdentity.type // "N/A"),
        (.userIdentity.userName // .userIdentity.sessionContext.sessionIssuer.userName // "N/A"),
        (.userIdentity.accessKeyId // "N/A"),
        (.sourceIPAddress // "N/A"),
        (.userAgent // "N/A")]
       | @csv' ./exports/cloud/cloudtrail.jsonl > ./analysis/cloud/ct_timeline.csv

# Filter to a specific principal
jq --arg user "TARGET_USER" \
  'select(.userIdentity.userName == $user or
          .userIdentity.sessionContext.sessionIssuer.userName == $user)' \
  ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, .eventName, .sourceIPAddress] | @csv'

# Failed/denied API calls (error codes signal recon or privilege escalation attempts)
jq 'select(.errorCode != null)' ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, .errorCode, .errorMessage, .eventName,
          (.userIdentity.userName // "N/A"), .sourceIPAddress] | @csv' \
  > ./analysis/cloud/ct_errors.csv
```

---

## AWS IMDS Credential Theft Pattern

When an EC2 instance is compromised, attackers steal IAM role credentials via the Instance
Metadata Service (IMDS). Stolen creds then appear in CloudTrail from an external IP.

```bash
# Step 1: find GetCallerIdentity calls (attacker verifying stolen creds work)
jq 'select(.eventName == "GetCallerIdentity")' ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, .sourceIPAddress, (.userIdentity.arn // "N/A"),
          (.userIdentity.accessKeyId // "N/A")] | @csv'

# Step 2: identify the IAM role that was abused (sessionIssuer shows the role)
jq 'select(.userIdentity.type == "AssumedRole")' ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, .eventName, .sourceIPAddress,
          .userIdentity.sessionContext.sessionIssuer.arn,
          (.userIdentity.accessKeyId // "N/A")] | @csv' \
  > ./analysis/cloud/ct_assumed_role.csv

# Step 3: find the access key ID used outside AWS IP ranges (= exfiltration confirmed)
# Compare .sourceIPAddress against known AWS IP ranges (169.254.x.x = internal IMDS)
jq 'select(.userIdentity.type == "AssumedRole") |
    select(.sourceIPAddress | test("^169\\.254\\.|amazonaws\\.com") | not)' \
  ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, .eventName, .sourceIPAddress,
          .userIdentity.sessionContext.sessionIssuer.arn] | @csv' \
  > ./analysis/cloud/ct_external_role_use.csv

# Step 4: correlate IMDSv2 token request in VPC flow / access logs (if available)
# IMDSv2 pattern: PUT http://169.254.169.254/latest/api/token → GET /security-credentials/<role>
```

**IMDS theft indicators:**
- `GetCallerIdentity` from an external IP using an `AssumedRole` session
- `CreateAccessKey` creating a persistent key for a role-based session (persistence)
- Role ARN matches an EC2 instance profile role
- Time delta between IMDS PUT token and first external use < 5 minutes

---

## IAM Persistence Detection

```bash
# New access keys created (persistence via long-lived key)
jq 'select(.eventName == "CreateAccessKey")' ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, (.userIdentity.userName // "N/A"), .sourceIPAddress,
          .responseElements.accessKey.accessKeyId,
          .responseElements.accessKey.userName] | @csv' \
  > ./analysis/cloud/ct_new_keys.csv

# New user creation
jq 'select(.eventName == "CreateUser")' ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, (.userIdentity.userName // "N/A"), .sourceIPAddress,
          .requestParameters.userName] | @csv'

# Policy attachment / inline policy writes (privilege escalation)
jq 'select(.eventName | test("AttachUserPolicy|AttachRolePolicy|PutUserPolicy|PutRolePolicy"))' \
  ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, .eventName, (.userIdentity.userName // "N/A"),
          .sourceIPAddress, (.requestParameters | tostring)] | @csv' \
  > ./analysis/cloud/ct_policy_changes.csv

# Console login events (check for MFA bypass or unfamiliar source IPs)
jq 'select(.eventName == "ConsoleLogin")' ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, (.userIdentity.userName // "N/A"), .sourceIPAddress,
          .additionalEventData.MFAUsed, .responseElements.ConsoleLogin] | @csv'
```

---

## S3 Exfiltration Detection

```bash
# High-volume GetObject calls (data staging / exfiltration)
jq 'select(.eventName == "GetObject")' ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, .sourceIPAddress, (.userIdentity.userName // "N/A"),
          .requestParameters.bucketName, .requestParameters.key,
          (.userAgent // "N/A")] | @csv' \
  > ./analysis/cloud/ct_s3_getobject.csv

# Filter for aws CLI / boto3 user agent (scripted exfil — not console)
jq 'select(.eventName == "GetObject") |
    select(.userAgent | test("aws-cli|boto3|python-requests|curl|wget"))' \
  ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, .userAgent, .sourceIPAddress,
          .requestParameters.bucketName, .requestParameters.key] | @csv' \
  > ./analysis/cloud/ct_s3_scripted_access.csv

# aws s3 cp user-agent signature (bulk copy pattern)
jq 'select(.eventName == "GetObject") |
    select(.userAgent | test("S3Console|aws-sdk|s3transfer"))' \
  ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, .userAgent, .sourceIPAddress,
          .requestParameters.bucketName, .requestParameters.key] | @csv'

# Objects deleted (cover tracks or ransomware)
jq 'select(.eventName | test("DeleteObject|DeleteObjects|DeleteBucket"))' \
  ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, .eventName, .sourceIPAddress,
          (.userIdentity.userName // "N/A"),
          .requestParameters.bucketName] | @csv' \
  > ./analysis/cloud/ct_s3_deletes.csv

# Bytes transferred (from bytesTransferredOut in S3 server access logs — not CloudTrail)
# If S3 server access logs are available:
awk '$12 != "-" {print $2, $3, $8, $10, $12}' s3_access.log | \
  sort -k5 -rn | head -50
```

---

## Quick Triage Checklist

```bash
# 1. What time range does the log cover?
jq -r '.eventTime' ./exports/cloud/cloudtrail.jsonl | sort | head -1
jq -r '.eventTime' ./exports/cloud/cloudtrail.jsonl | sort | tail -1

# 2. Unique source IPs (rank by frequency)
jq -r '.sourceIPAddress' ./exports/cloud/cloudtrail.jsonl | sort | uniq -c | sort -rn | head -20

# 3. Unique principals
jq -r '(.userIdentity.userName // .userIdentity.sessionContext.sessionIssuer.userName // "N/A")' \
  ./exports/cloud/cloudtrail.jsonl | sort | uniq -c | sort -rn

# 4. High-signal events (subset worth reviewing in full)
jq 'select(.eventName | test("GetCallerIdentity|CreateAccessKey|CreateUser|AttachPolicy|PutPolicy|AssumeRole|GetSecretValue|GetObject|DeleteObject|ConsoleLogin"))' \
  ./exports/cloud/cloudtrail.jsonl | \
  jq -r '[.eventTime, .eventName, (.userIdentity.userName // "N/A"), .sourceIPAddress] | @csv' \
  > ./analysis/cloud/ct_high_signal.csv

echo "High-signal event count: $(wc -l < ./analysis/cloud/ct_high_signal.csv)"
```

---

## Output Paths

| Output | Path |
|--------|------|
| Decompressed logs | `./exports/cloud/` |
| Timeline CSV | `./analysis/cloud/ct_timeline.csv` |
| High-signal events | `./analysis/cloud/ct_high_signal.csv` |
| External role use | `./analysis/cloud/ct_external_role_use.csv` |
| S3 access / exfil | `./analysis/cloud/ct_s3_getobject.csv` |
| New keys / IAM changes | `./analysis/cloud/ct_new_keys.csv`, `ct_policy_changes.csv` |
| GuardDuty findings | `./analysis/cloud/gd_high_severity.csv` |

---

## Notes

- CloudTrail timestamps are UTC ISO-8601 — always correlate against other artifacts in UTC
- `userIdentity.type == "AssumedRole"` means a role session; check `sessionIssuer.arn` for the source role
- `sourceIPAddress` of `amazonaws.com` means the API call came from an AWS service (not a human)
- GuardDuty `severity >= 7.0` = High; `4.0–6.9` = Medium; `1.0–3.9` = Low
- Management events (IAM, STS, S3 bucket ops) are in CloudTrail by default; data events (S3 GetObject) require explicit enablement
- If `GetObject` events are missing, check whether S3 data event logging was enabled on the bucket
