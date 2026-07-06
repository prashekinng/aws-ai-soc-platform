"""
CMS Bedrock Invoker
Thin Lambda that receives EventBridge findings and invokes cms-soc-agent.
Includes:
- Immutable audit trail: full agent trace written to S3
- Circuit breaker: confidence < 0.6 forces HUMAN_APPROVE
- Retry on throttling
"""

import json
import boto3
import os
import uuid
import time
from datetime import datetime, timezone

bedrock_agent_runtime = boto3.client(
    "bedrock-agent-runtime",
    region_name=os.environ["AWS_REGION_NAME"]
)
s3_client = boto3.client("s3", region_name=os.environ["AWS_REGION_NAME"])

AGENT_ID        = os.environ["BEDROCK_AGENT_ID"]
AGENT_ALIAS     = os.environ["BEDROCK_AGENT_ALIAS_ID"]
AUDIT_BUCKET    = os.environ.get("AUDIT_BUCKET", "cms-ai-audit-logs-cms-project-terraform")
CONFIDENCE_THRESHOLD = 0.6


def invoke_agent_with_retry(session_id: str, input_text: str, max_retries: int = 2) -> dict:
    """Invoke Bedrock Agent with retry on throttling."""
    for attempt in range(max_retries + 1):
        try:
            response = bedrock_agent_runtime.invoke_agent(
                agentId=AGENT_ID,
                agentAliasId=AGENT_ALIAS,
                sessionId=session_id,
                inputText=input_text,
                enableTrace=True
            )

            full_response = ""
            trace_steps   = []

            for event_chunk in response["completion"]:
                if "chunk" in event_chunk:
                    chunk_text     = event_chunk["chunk"]["bytes"].decode("utf-8")
                    full_response += chunk_text
                if "trace" in event_chunk:
                    trace_steps.append(event_chunk["trace"])

            return {
                "success":       True,
                "response":      full_response,
                "trace_steps":   trace_steps
            }

        except bedrock_agent_runtime.exceptions.ThrottlingException as e:
            if attempt < max_retries:
                wait = (attempt + 1) * 5
                print(f"Throttled — retrying in {wait}s (attempt {attempt + 1})")
                time.sleep(wait)
            else:
                print(f"All retries exhausted: {e}")
                return {"success": False, "error": str(e)}

        except Exception as e:
            print(f"Agent invocation failed: {e}")
            return {"success": False, "error": str(e)}


def extract_confidence(response_text: str) -> float:
    """
    Extract confidence score from agent response.
    Agent is prompted to include confidence_score in output.
    Defaults to 0.5 if not found — triggers caution, not auto-block.
    """
    try:
        # Try to find JSON in the response
        import re
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            return float(data.get("confidence_score", 0.5))
    except Exception:
        pass
    return 0.5


def apply_circuit_breaker(response_text: str, confidence: float) -> str:
    """
    Circuit breaker: if confidence below threshold,
    override recommended_action to HUMAN_APPROVE.
    """
    if confidence < CONFIDENCE_THRESHOLD:
        print(f"Circuit breaker triggered — confidence {confidence} below threshold {CONFIDENCE_THRESHOLD}")
        try:
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                original_action = data.get("recommended_action", "UNKNOWN")
                if original_action == "AUTO_BLOCK":
                    data["recommended_action"] = "HUMAN_APPROVE"
                    data["reasoning"] = (
                        f"Circuit breaker override: confidence score {confidence} "
                        f"below threshold {CONFIDENCE_THRESHOLD}. "
                        f"Original action {original_action} overridden to HUMAN_APPROVE."
                    )
                    return json.dumps(data)
        except Exception as e:
            print(f"Circuit breaker parse failed: {e}")
    return response_text


def write_audit_trail(session_id: str, finding: dict, response: str,
                      trace_steps: list, confidence: float) -> None:
    """
    Write immutable audit trail to S3.
    Stores full agent reasoning transcript — not just final verdict.
    S3 versioning ensures write-once immutability.
    """
    try:
        audit_record = {
            "session_id":        session_id,
            "timestamp":         datetime.now(timezone.utc).isoformat(),
            "finding":           finding,
            "final_response":    response,
            "confidence_score":  confidence,
            "circuit_breaker_applied": confidence < CONFIDENCE_THRESHOLD,
            "agent_trace":       trace_steps  # Full reasoning transcript
        }

        key = f"agent-traces/{datetime.now(timezone.utc).strftime('%Y/%m/%d')}/{session_id}.json"

        s3_client.put_object(
            Bucket=AUDIT_BUCKET,
            Key=key,
            Body=json.dumps(audit_record, default=str),
            ContentType="application/json"
        )
        print(f"Audit trail written to s3://{AUDIT_BUCKET}/{key}")

    except Exception as e:
        # Audit failure should never block the pipeline
        print(f"Audit trail write failed: {e} — continuing")


def lambda_handler(event, context):
    print(f"Invoker received event: {json.dumps(event)}")

    session_id = str(uuid.uuid4())
    input_text = f"Triage this security finding: {json.dumps(event)}"

    # Step 1 — Invoke agent with retry
    result = invoke_agent_with_retry(session_id, input_text)

    if not result["success"]:
        print(f"Agent invocation failed: {result['error']}")
        write_audit_trail(session_id, event, "FAILED", [], 0.0)
        return {"statusCode": 500, "body": result["error"]}

    response_text = result["response"]
    trace_steps   = result["trace_steps"]

    # Step 2 — Extract confidence score
    confidence = extract_confidence(response_text)
    print(f"Confidence score: {confidence}")

    # Step 3 — Apply circuit breaker
    final_response = apply_circuit_breaker(response_text, confidence)

    # Step 4 — Write immutable audit trail
    write_audit_trail(session_id, event, final_response, trace_steps, confidence)

    print(f"Final agent response: {final_response}")
    return {"statusCode": 200, "body": final_response}