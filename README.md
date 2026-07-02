# CMS Security Platform — AI-Powered Multi-Agent SOC

An AWS-native multi-agent security operations platform that automates threat triage, CloudTrail forensics, and incident response using Large Language Models.

Built as a portfolio project simulating a real managed security service provider (MSSP) environment with 5 customers across isolated VPCs.

---

## Architecture

```
GuardDuty / Security Hub Finding (HIGH/CRITICAL)
    │
    └── EventBridge Rule (cms-ai-triage-rule)
            │
            └── Supervisor Agent (cms-ai-triage Lambda)
                    │
                    ├── 1. Invokes CloudTrail Agent → attack chain narrative
                    ├── 2. VirusTotal enrichment → IP reputation
                    ├── 3. AWS context → customer, instance state, SGs
                    │
                    ├── 4. Triage Agent (Bedrock/Claude Haiku)
                    │       └── Verdict: AUTO_BLOCK / HUMAN_APPROVE / DISMISS
                    │
                    ├── 5. Adversarial Agent (Bedrock/Claude Haiku)
                    │       └── Challenges triage verdict
                    │       └── Conflict → force HUMAN_APPROVE
                    │
                    └── 6. Route → Slack alert + S3 audit log
```

---

## Agents

### Supervisor Agent — `lambda/ai_triage_function.py`
Orchestrates the full triage pipeline. Invokes specialist agents, collects results, resolves conflicts, and routes to the correct response action.

### CloudTrail Anomaly Analyser — `lambda/cloudtrail_agent.py`
Reconstructs attacker behaviour from CloudTrail logs. Filters 2-hour lookback for high-risk API calls, groups by identity and time, sends to Bedrock for plain-English attack narrative with MITRE ATT&CK mapping.

High-risk API calls monitored:
- `CreateUser`, `AttachRolePolicy`, `AssumeRole` — IAM escalation
- `GetSecretValue`, `PutBucketPolicy` — credential access / exfiltration setup
- `DisableLogging`, `StopLogging` — defense evasion
- `ConsoleLogin` failures — brute force

### Triage Agent (Bedrock)
First LLM call. Analyses finding + VirusTotal + AWS context + CloudTrail narrative. Returns structured JSON verdict with severity, MITRE technique, recommended action, containment steps, and false positive likelihood.

### Adversarial Agent (Bedrock)
Second LLM call. Reviews the triage verdict as a senior analyst. If it disagrees with the recommended action, the supervisor overrides to HUMAN_APPROVE — preventing automated blocking on contested verdicts.

---

## Response Actions

| Action | Trigger | What happens |
|---|---|---|
| AUTO_BLOCK | VT malicious > 5 + active compromise | EC2 moved to quarantine SG, Slack alert with undo link |
| HUMAN_APPROVE | High severity or ambiguous finding | Slack alert with approve/dismiss links via API Gateway |
| DISMISS | Clear false positive | S3 audit log, low-priority Slack note |

---

## AI Design Decisions

- **Temperature 0** — deterministic verdicts, same input always produces same output
- **System/user prompt split** — system prompt is trusted config, user prompt is untrusted data
- **Fail-closed on Bedrock failure** — any LLM error defaults to HUMAN_APPROVE, never silent drop
- **Fail-open on CloudTrail failure** — CloudTrail unavailability doesn't block triage
- **Adversarial review** — two independent LLM calls with different roles; conflict escalates to human
- **Context compression** — CloudTrail events condensed to 4 fields before sending to LLM

---

## Stack

| Layer | Technology |
|---|---|
| Cloud | AWS (ap-south-1) |
| IaC | Terraform |
| AI/LLM | AWS Bedrock (Claude 3 Haiku) |
| Detection | AWS GuardDuty, Security Hub |
| Forensics | AWS CloudTrail |
| Enrichment | VirusTotal API |
| SIEM | Splunk Enterprise |
| Alerting | Slack (incoming webhooks + API Gateway) |
| Audit | S3 |
| CI/CD | GitHub Actions (Trivy IaC + Lambda scanning) |
| Secrets | AWS SSM Parameter Store |

---

## Customer Environment

Simulates 5 customer VPCs: `garda`, `NYUL`, `laminar`, `groundprobe`, `QDB`

Each customer has isolated VPC, EC2 instances tagged with `Customer` tag, and a dedicated quarantine security group (zero-rule) for containment.

---

## Security Controls

- IAM least privilege per Lambda execution role
- Secrets in SSM Parameter Store (not env vars)
- Trivy scanning on every PR (IaC + Lambda code)
- Audit log written to S3 before any destructive action
- Quarantine reversible via Slack undo link
- Terraform state in S3 with separate dev/prod IAM users

---

## Repo Structure

```
aws-ai-soc-platform/
├── lambda/
│   ├── ai_triage_function.py      # Supervisor + triage + adversarial agents
│   └── cloudtrail_agent.py        # CloudTrail anomaly analyser agent
├── terraform/                     # All infrastructure as code
├── environments/
│   ├── dev/
│   └── prod/
├── .github/workflows/
│   └── cms-security-scan.yml      # CI/CD pipeline
└── scripts/
    └── detect-gen.py              # MITRE → Sigma rule generator (in progress)
```

