"""
detect-gen.py — LLM-Assisted Detection Rule Generator
=======================================================
CMS Security Platform — Phase 2, Layer 2

Takes a MITRE ATT&CK technique ID, calls AWS Bedrock (Claude 3 Haiku)
to generate a Sigma detection rule, validates it, and optionally opens
a GitHub PR to deploy it via the detection-as-code pipeline.

Usage:
  # Generate and print to terminal only
  python3 scripts/detect-gen.py --technique T1110.001

  # Generate, save to /detections/, and open a GitHub PR
  python3 scripts/detect-gen.py --technique T1110.001 --push

Requirements:
  pip install boto3 pyyaml PyGithub

Environment variables (for --push mode):
  GITHUB_TOKEN       — personal access token with repo scope
  GITHUB_REPO        — e.g. prashekinng/aws-ai-soc-platform
  AWS_DEFAULT_REGION — ap-south-1 (or set in ~/.aws/config)

How it fits into the project:
  1. You run this script with a MITRE technique ID
  2. Bedrock (Claude) generates a valid Sigma YAML rule
  3. Script validates the YAML has required Sigma fields
  4. With --push: saves to /detections/, opens a GitHub PR
  5. You review and merge the PR
  6. GitHub Actions pipeline (Layer 1) converts Sigma → SPL
     and deploys to Splunk automatically on merge
"""

import argparse
import json
import os
import re
import sys
import boto3
from datetime import datetime

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml not installed. Run: pip install pyyaml")
    sys.exit(1)


# ── Configuration ─────────────────────────────────────────────────────────────

BEDROCK_MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"
AWS_REGION       = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
DETECTIONS_DIR   = os.path.join(os.path.dirname(__file__), "..", "detections")

# Required fields every valid Sigma rule must have
REQUIRED_SIGMA_FIELDS = ["title", "description", "logsource", "detection"]


# ── MITRE ATT&CK technique descriptions
# Used to give Bedrock context about what the technique actually does.
# Extend this dict as you add more techniques.
MITRE_CONTEXT = {
    "T1110":     "Brute Force — attacker attempts to gain access by systematically trying passwords",
    "T1110.001": "Brute Force: Password Guessing — trying common passwords against accounts",
    "T1110.003": "Brute Force: Password Spraying — trying one password against many accounts",
    "T1059":     "Command and Scripting Interpreter — attacker uses scripts to execute commands",
    "T1059.001": "Command and Scripting Interpreter: PowerShell — malicious use of PowerShell",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell — malicious shell commands on Linux",
    "T1098":     "Account Manipulation — attacker modifies accounts to maintain persistence",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials — adding keys to IAM users",
    "T1078":     "Valid Accounts — attacker uses legitimate credentials to access systems",
    "T1078.004": "Valid Accounts: Cloud Accounts — using stolen cloud account credentials",
    "T1552":     "Unsecured Credentials — attacker searches for credentials stored insecurely",
    "T1552.001": "Unsecured Credentials: Credentials in Files — credentials hardcoded in files",
    "T1567":     "Exfiltration Over Web Service — attacker exfiltrates data via web services",
    "T1567.002": "Exfiltration to Cloud Storage — attacker uploads stolen data to S3 or similar",
    "T1087":     "Account Discovery — attacker enumerates user accounts",
    "T1087.004": "Account Discovery: Cloud Account — enumerating IAM users and roles",
    "T1580":     "Cloud Infrastructure Discovery — attacker enumerates cloud resources",
    "T1190":     "Exploit Public-Facing Application — attacker exploits vulnerabilities in apps",
}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — BUILD THE BEDROCK PROMPT
# The prompt is the most important part. It tells Claude exactly what format
# to return, what fields are required, and what the technique is about.
# ══════════════════════════════════════════════════════════════════════════════

def build_prompt(technique_id):
    technique_context = MITRE_CONTEXT.get(
        technique_id,
        f"MITRE ATT&CK technique {technique_id}"
    )

    return f"""You are an expert detection engineer specialising in AWS and Linux security.

Generate a Sigma detection rule for MITRE ATT&CK technique {technique_id}.

Technique description: {technique_context}

Target environment:
- AWS cloud infrastructure (EC2 instances running Ubuntu/Amazon Linux)
- Log sources: AWS CloudTrail, Linux syslog, auth.log, VPC Flow Logs
- SIEM: Splunk

Requirements for the rule:
- Must be specific enough to avoid excessive false positives
- Must include realistic detection logic for the log source
- Must map clearly to the MITRE technique
- Status must be: experimental

Return ONLY valid YAML in Sigma format. No explanation, no markdown backticks, no preamble.
The YAML must contain these exact top-level keys: title, id, status, description, references, author, date, logsource, detection, falsepositives, level, tags

Example structure (do not copy this literally — generate a rule for {technique_id}):

title: Example Detection Rule
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects example suspicious activity
references:
    - https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}
author: CMS Security Platform
date: {datetime.now().strftime('%Y/%m/%d')}
logsource:
    category: authentication
    product: linux
detection:
    selection:
        type: sshd
        message|contains: 'Failed password'
    timeframe: 5m
    condition: selection | count() > 10
falsepositives:
    - Legitimate automated scripts with misconfigured credentials
level: high
tags:
    - attack.credential_access
    - attack.{technique_id.lower().replace('.', '_')}

Now generate the actual rule for technique {technique_id}. Return ONLY the YAML."""


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — CALL BEDROCK
# Sends the prompt to Claude 3 Haiku via AWS Bedrock.
# Temperature = 0 for consistent, deterministic output.
# ══════════════════════════════════════════════════════════════════════════════

def call_bedrock(prompt):
    print(f"  Calling AWS Bedrock (Claude 3 Haiku) in {AWS_REGION}...")

    try:
        client = boto3.client("bedrock-runtime", region_name=AWS_REGION)

        response = client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens":        2000,
                "temperature":       0,     # deterministic output
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            })
        )

        body = json.loads(response["body"].read())
        raw_text = body["content"][0]["text"].strip()

        # Strip markdown code fences if Claude added them despite instructions
        raw_text = re.sub(r"```yaml|```", "", raw_text).strip()

        return raw_text

    except Exception as e:
        print(f"\nERROR: Bedrock call failed: {e}")
        print("\nTroubleshooting:")
        print("  1. Check AWS credentials: aws sts get-caller-identity")
        print("  2. Confirm region is ap-south-1")
        print("  3. Bedrock model access is auto-enabled — first call may take a moment")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — VALIDATE THE SIGMA YAML
# Checks that the generated YAML is valid and has required Sigma fields.
# If validation fails, prints what's missing so you can adjust the prompt.
# ══════════════════════════════════════════════════════════════════════════════

def validate_sigma(yaml_text, technique_id):
    print("  Validating Sigma YAML...")

    try:
        rule = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        print(f"\nERROR: Generated YAML is not valid: {e}")
        print("\nRaw output from Bedrock:")
        print(yaml_text)
        return None

    if not isinstance(rule, dict):
        print("ERROR: YAML parsed but is not a dictionary — unexpected format.")
        return None

    # Check required fields
    missing = [f for f in REQUIRED_SIGMA_FIELDS if f not in rule]
    if missing:
        print(f"\nWARNING: Generated rule is missing required fields: {missing}")
        print("The rule may still be usable but should be reviewed manually.")

    # Check that tags include the MITRE technique
    tags = rule.get("tags", [])
    technique_tag = f"attack.{technique_id.lower().replace('.', '_')}"
    if not any(technique_id.lower() in tag.lower() for tag in tags):
        print(f"  WARNING: MITRE tag '{technique_tag}' not found in tags. Review manually.")

    print("  Validation passed.")
    return rule


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — SAVE TO /detections/ FOLDER
# Saves the generated rule as a .sigma file.
# Filename is derived from the rule title or technique ID.
# ══════════════════════════════════════════════════════════════════════════════

def save_rule(yaml_text, rule_dict, technique_id):
    os.makedirs(DETECTIONS_DIR, exist_ok=True)

    # Derive filename from title or technique ID
    title = rule_dict.get("title", technique_id)
    filename = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    filename = f"{filename}.sigma"
    filepath = os.path.join(DETECTIONS_DIR, filename)

    with open(filepath, "w") as f:
        f.write(f"# Auto-generated by detect-gen.py\n")
        f.write(f"# MITRE ATT&CK: {technique_id}\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Review before merging — AI-generated content should be validated.\n\n")
        f.write(yaml_text)

    print(f"  Saved to: {filepath}")
    return filepath, filename


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — OPEN GITHUB PR (optional, --push flag)
# Creates a new branch and opens a PR with the generated rule.
# Requires: pip install PyGithub
# Environment: GITHUB_TOKEN, GITHUB_REPO
# ══════════════════════════════════════════════════════════════════════════════

def open_github_pr(yaml_text, filename, technique_id, rule_dict):
    try:
        from github import Github
    except ImportError:
        print("\nERROR: PyGithub not installed. Run: pip install PyGithub")
        print("Skipping GitHub PR creation. Rule saved locally.")
        return

    token     = os.environ.get("GITHUB_TOKEN")
    repo_name = os.environ.get("GITHUB_REPO")

    if not token or not repo_name:
        print("\nERROR: GITHUB_TOKEN and GITHUB_REPO environment variables required for --push")
        print("Skipping GitHub PR creation. Rule saved locally.")
        return

    print(f"  Opening GitHub PR in {repo_name}...")

    try:
        g         = Github(token)
        repo      = g.get_repo(repo_name)
        main_sha  = repo.get_branch("main").commit.sha

        # Create a new branch for this detection rule
        branch_name = f"detection/auto-{technique_id.lower().replace('.', '-')}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=main_sha)

        # Create the file on the new branch
        file_content = (
            f"# Auto-generated by detect-gen.py\n"
            f"# MITRE ATT&CK: {technique_id}\n"
            f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"# Review before merging — AI-generated content should be validated.\n\n"
            f"{yaml_text}"
        )

        repo.create_file(
            path=f"detections/{filename}",
            message=f"feat(detection): auto-generate Sigma rule for {technique_id}",
            content=file_content,
            branch=branch_name
        )

        # Open the PR
        title = rule_dict.get("title", f"Auto-generated detection: {technique_id}")
        body  = (
            f"## Auto-generated Detection Rule\n\n"
            f"**MITRE ATT&CK Technique:** [{technique_id}](https://attack.mitre.org/techniques/{technique_id.replace('.', '/')})\n\n"
            f"**Technique:** {MITRE_CONTEXT.get(technique_id, 'See MITRE ATT&CK link above')}\n\n"
            f"**Generated by:** `detect-gen.py` using AWS Bedrock (Claude 3 Haiku)\n\n"
            f"### Review Checklist\n"
            f"- [ ] Detection logic is accurate for this technique\n"
            f"- [ ] False positive rate is acceptable\n"
            f"- [ ] Log source matches what is available in Splunk\n"
            f"- [ ] Severity level is appropriate\n\n"
            f"Once merged, GitHub Actions will automatically convert this Sigma rule to SPL and deploy to Splunk."
        )

        pr = repo.create_pull(
            title=f"[Detection] Auto-generated: {title}",
            body=body,
            head=branch_name,
            base="main"
        )

        print(f"  PR opened: {pr.html_url}")
        return pr.html_url

    except Exception as e:
        print(f"\nERROR: GitHub PR creation failed: {e}")
        print("Rule was saved locally. Open a PR manually.")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Generate Sigma detection rules from MITRE ATT&CK technique IDs using AWS Bedrock"
    )
    parser.add_argument(
        "--technique",
        required=True,
        help="MITRE ATT&CK technique ID (e.g. T1110.001, T1059, T1098.001)"
    )
    parser.add_argument(
        "--push",
        action="store_true",
        help="Save rule to /detections/ and open a GitHub PR (requires GITHUB_TOKEN and GITHUB_REPO)"
    )
    args = parser.parse_args()

    technique_id = args.technique.upper()

    print(f"\n{'='*60}")
    print(f"  detect-gen.py — CMS Security Platform Phase 2")
    print(f"  Generating Sigma rule for: {technique_id}")
    print(f"{'='*60}\n")

    # Step 1 — Build prompt
    print("Step 1/4  Building Bedrock prompt...")
    prompt = build_prompt(technique_id)

    # Step 2 — Call Bedrock
    print("Step 2/4  Calling Bedrock...")
    yaml_text = call_bedrock(prompt)

    # Step 3 — Validate
    print("Step 3/4  Validating output...")
    rule_dict = validate_sigma(yaml_text, technique_id)
    if not rule_dict:
        print("\nGeneration failed. Raw output:")
        print(yaml_text)
        sys.exit(1)

    # Always print the generated rule to terminal
    print(f"\n{'─'*60}")
    print("Generated Sigma Rule:")
    print(f"{'─'*60}")
    print(yaml_text)
    print(f"{'─'*60}\n")

    # Step 4 — Save and optionally push
    print("Step 4/4  Saving rule...")
    if args.push:
        filepath, filename = save_rule(yaml_text, rule_dict, technique_id)
        print("  Opening GitHub PR...")
        open_github_pr(yaml_text, filename, technique_id, rule_dict)
    else:
        print("  (Run with --push to save to /detections/ and open a GitHub PR)")

    print(f"\nDone. Rule generated for {technique_id}.")
    print("Interview tip: This script replicates what Microsoft Security Copilot")
    print("does internally — input a technique ID, LLM generates a detection rule,")
    print("CI/CD pipeline deploys it. Built from scratch on AWS Bedrock.\n")


if __name__ == "__main__":
    main()