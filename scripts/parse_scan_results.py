"""
parse_scan_results.py — Unified scan results parser for GitHub Actions

Usage:
  python3 scripts/parse_scan_results.py trivy-iac
  python3 scripts/parse_scan_results.py trivy-images
  python3 scripts/parse_scan_results.py prowler
"""

import json
import os
import sys
import glob
import requests

WEBHOOK    = os.environ["SLACK_WEBHOOK"]
RUN_URL    = (
    f"{os.environ.get('GITHUB_SERVER_URL', '')}"
    f"/{os.environ.get('GITHUB_REPOSITORY', '')}"
    f"/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}"
)


def post_to_slack(text):
    requests.post(WEBHOOK, json={"text": text})


# ── TRIVY IAC ─────────────────────────────────────────────────────────────────

def parse_trivy_iac():
    critical = high = medium = 0
    try:
        with open("trivy-iac-results.json") as f:
            data = json.load(f)
        for result in data.get("Results", []):
            for m in result.get("Misconfigurations", []):
                sev = m.get("Severity", "")
                if sev == "CRITICAL":   critical += 1
                elif sev == "HIGH":     high += 1
                elif sev == "MEDIUM":   medium += 1
    except Exception as e:
        print(f"Error: {e}")

    total  = critical + high + medium
    status = "✅ Clean" if total == 0 else "⚠️ Issues found"
    branch = os.environ.get("GITHUB_REF_NAME", "unknown")

    post_to_slack(
        f"*🔍 Trivy IaC Scan — {status}*\n"
        f"Branch: `{branch}`\n"
        f"🔴 Critical: {critical}  🟠 High: {high}  🟡 Medium: {medium}\n"
        f"Run: {RUN_URL}"
    )
    print(f"Posted to Slack: {status} | Critical {critical} | High {high} | Medium {medium}")


# ── TRIVY IMAGES ──────────────────────────────────────────────────────────────

def parse_trivy_images():
    total_critical = total_high = total_medium = 0
    for svc in ["auth", "incident", "policy"]:
        try:
            with open(f"trivy-{svc}-results.json") as f:
                data = json.load(f)
            for result in data.get("Results", []):
                for v in result.get("Vulnerabilities", []):
                    sev = v.get("Severity", "")
                    if sev == "CRITICAL":   total_critical += 1
                    elif sev == "HIGH":     total_high += 1
                    elif sev == "MEDIUM":   total_medium += 1
        except Exception as e:
            print(f"Error for {svc}: {e}")

    total  = total_critical + total_high + total_medium
    status = "✅ Clean" if total == 0 else "⚠️ CVEs found"

    post_to_slack(
        f"*🐳 Trivy Image Scan — {status}*\n"
        f"Images: auth-service, incident-service, policy-service\n"
        f"🔴 Critical: {total_critical}  🟠 High: {total_high}  🟡 Medium: {total_medium}\n"
        f"Run: {RUN_URL}"
    )
    print(f"Posted to Slack: {status} | Critical {total_critical} | High {total_high} | Medium {total_medium}")


# ── TRIVY LAMBDA ──────────────────────────────────────────────────────────────

def parse_trivy_lambda():
    critical = high = medium = 0
    try:
        with open("trivy-lambda-results.json") as f:
            data = json.load(f)
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                sev = v.get("Severity", "")
                if sev == "CRITICAL":   critical += 1
                elif sev == "HIGH":     high += 1
                elif sev == "MEDIUM":   medium += 1
            for m in result.get("Misconfigurations", []):
                sev = m.get("Severity", "")
                if sev == "CRITICAL":   critical += 1
                elif sev == "HIGH":     high += 1
                elif sev == "MEDIUM":   medium += 1
    except Exception as e:
        print(f"Error: {e}")

    total  = critical + high + medium
    status = "✅ Clean" if total == 0 else "⚠️ Issues found"
    branch = os.environ.get("GITHUB_REF_NAME", "unknown")

    post_to_slack(
        f"*🐍 Trivy Lambda Code Scan — {status}*\n"
        f"Branch: `{branch}`\n"
        f"🔴 Critical: {critical}  🟠 High: {high}  🟡 Medium: {medium}\n"
        f"Run: {RUN_URL}"
    )
    print(f"Posted to Slack: {status} | Critical {critical} | High {high} | Medium {medium}")


# ── PROWLER ───────────────────────────────────────────────────────────────────

def parse_prowler():
    """
    Handles both Prowler v5 (OCSF) and v3/v4 (legacy) JSON formats.

    Prowler v5 OCSF format:
      - status_code: "PASS" or "FAIL"  ← the actual check result
      - status:      "New"             ← OCSF state, NOT the pass/fail result
      - severity:    "medium" / "high" etc. (string)

    Prowler v3/v4 legacy format:
      - Status:   "PASS" or "FAIL"
      - Severity: "medium" / "high" etc.
    """
    counts = {"passed": 0, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    def tally(finding):
        # Prowler v5 OCSF uses status_code; v3/v4 uses Status/status
        result = (
            finding.get("status_code") or
            finding.get("Status") or
            finding.get("status") or
            ""
        ).upper()

        severity = finding.get("severity", finding.get("Severity", "")).lower()

        if result == "PASS":
            counts["passed"] += 1
        elif result == "FAIL":
            counts["failed"] += 1
            if severity == "critical":   counts["critical"] += 1
            elif severity == "high":     counts["high"] += 1
            elif severity == "medium":   counts["medium"] += 1
            elif severity == "low":      counts["low"] += 1

    try:
        json_files = glob.glob("./prowler-output/**/*.json", recursive=True)
        if not json_files:
            json_files = glob.glob("./prowler-output/*.json")

        for json_file in json_files:
            with open(json_file) as f:
                content = f.read().strip()
            try:
                findings = json.loads(content)
                items = findings if isinstance(findings, list) else [findings]
                for finding in items:
                    tally(finding)
            except json.JSONDecodeError:
                # NDJSON — one object per line
                for line in content.split("\n"):
                    line = line.strip()
                    if line:
                        try:
                            tally(json.loads(line))
                        except Exception:
                            pass
    except Exception as e:
        print(f"Error parsing Prowler output: {e}")

    total = counts["passed"] + counts["failed"]
    score = round(counts["passed"] / total * 100, 1) if total > 0 else 0

    post_to_slack(
        f"*📊 Weekly Prowler CIS Scan*\n"
        f"AWS Account: 247794288672 | Region: ap-south-1\n"
        f"Score: *{score}%* ({counts['passed']} pass / {counts['failed']} fail)\n"
        f"🔴 Critical: {counts['critical']}  🟠 High: {counts['high']}  "
        f"🟡 Medium: {counts['medium']}  Low: {counts['low']}\n"
        f"Run: {RUN_URL}"
    )
    print(f"Posted to Slack: Score {score}% | Pass {counts['passed']} | Fail {counts['failed']}")


# ── PULUMI PREVIEW ───────────────────────────────────────────────────────────────────

def parse_pulumi_preview():
    output  = os.environ.get("PULUMI_OUTPUT", "No output captured")
    result  = os.environ.get("PULUMI_RESULT", "unknown")
    branch  = os.environ.get("GITHUB_REF_NAME", "unknown")

    # Filter only relevant lines
    relevant = []
    for line in output.split("    "):
        line = line.strip()
        if any(keyword in line for keyword in [
            "to create", "to replace", "to update", "to delete", "unchanged",
            "+-", "+ ", "~ ", "Resources:", "Diagnostics:", "warning:", "error:"
        ]):
            relevant.append(line)

    clean_output = "\n".join(relevant) if relevant else output[:500]

    emoji = "✅" if result == "success" else "❌"

    message = {
        "text": f"{emoji} *Pulumi Preview — {result.upper()}*",
        "attachments": [{
            "color": "good" if result == "success" else "danger",
            "fields": [
                {"title": "Branch",  "value": branch,  "short": True},
                {"title": "Result",  "value": result,  "short": True},
                {"title": "Preview Output", "value": f"```{clean_output[:2000]}```", "short": False}
            ]
        }]
    }

    response = requests.post(WEBHOOK, json=message)
    print(f"Slack response: {response.status_code}")


# ── MAIN ──────────────────────────────────────────────────────────────────────

MODES = {
    "trivy-iac":    parse_trivy_iac,
    "trivy-images": parse_trivy_images,
    "prowler":      parse_prowler,
    "trivy-lambda":   parse_trivy_lambda,
    "pulumi-preview": parse_pulumi_preview,
}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in MODES:
        print(f"Usage: python3 parse_scan_results.py [{' | '.join(MODES)}]")
        sys.exit(1)
    MODES[sys.argv[1]]()
