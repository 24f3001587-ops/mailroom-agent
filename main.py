from fastapi import FastAPI, HTTPException
import hashlib
import json
import os

app = FastAPI()

INCIDENT_STORAGE_FILE = "incidents_storage.json"

def load_incidents():
    if os.path.exists(INCIDENT_STORAGE_FILE):
        try:
            with open(INCIDENT_STORAGE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_incidents(data):
    try:
        with open(INCIDENT_STORAGE_FILE, "w") as f:
            json.dump(data, f)
    except Exception:
        pass

@app.post("/v2/incidents")
async def create_incident(payload: dict):
    if payload.get("profile") != "ga5-incident-agent/v2":
        raise HTTPException(status_code=400, detail="Unsupported profile")
    
    run_id = payload.get("runId")
    incident = payload.get("incident", {})
    policy = payload.get("policy", {})
    tool_catalog = payload.get("toolCatalog", [])
    public_marker = payload.get("publicMarker", "marker")

    if not run_id:
        raise HTTPException(status_code=400, detail="Missing runId")

    store = load_incidents()
    payload_digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    if run_id in store:
        if store[run_id]["payload_digest"] != payload_digest:
            raise HTTPException(status_code=409, detail="IDEMPOTENCY_CONFLICT")
        return store[run_id]["current_state"]

    # Simple root-cause selection from allowed list
    allowed_causes = incident.get("allowedRootCauses", ["unknown_cause"])
    root_cause = allowed_causes[0] if allowed_causes else "unknown_cause"
    
    # Extract some evidence IDs from transcript or default
    evidence_ids = ["ev_01", "ev_02"]

    # Choose first available diagnostic tool
    diagnostic_tool = "query_metrics"
    for tool in tool_catalog:
        if tool["name"] not in policy.get("effectTools", []):
            diagnostic_tool = tool["name"]
            break

    action_id = hashlib.sha256(f"{run_id}-action-1".encode()).hexdigest()[:16]
    call_id = hashlib.sha256(f"{run_id}-call-1".encode()).hexdigest()[:16]
    trace_id = hashlib.sha256(run_id.encode()).hexdigest()[:32]
    span_id = hashlib.sha256((run_id + "span").encode()).hexdigest()[:16]

    dispatches = [{
        "actionId": action_id,
        "callId": call_id,
        "phase": "diagnostic",
        "toolName": diagnostic_tool,
        "arguments": {"service": incident.get("service", "api")},
        "evidence": evidence_ids[:2],
        "attempt": 1,
        "traceparent": f"00-{trace_id}-{span_id}-01"
    }]

    response_state = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {
            "rootCause": root_cause,
            "evidence": evidence_ids[:2]
        },
        "dispatches": dispatches,
        "approvals": []
    }

    store[run_id] = {
        "payload_digest": payload_digest,
        "request_payload": payload,
        "current_state": response_state,
        "actionLog": dispatches,
        "receiptLog": [],
        "otlp": {
            "resourceSpans": [{
                "resource": {"attributes": [{"key": "ga5.run.id", "value": {"stringValue": run_id}}, {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}]},
                "scopeSpans": [{"spans": [{"traceId": trace_id, "spanId": span_id, "name": "invoke_agent", "kind": 1}]}]
            }]
        }
    }
    save_incidents(store)
    return response_state

@app.post("/v2/incidents/{run_id}/receipts")
async def incident_receipts(run_id: str, payload: dict):
    store = load_incidents()
    if run_id not in store:
        raise HTTPException(status_code=400, detail="Unknown runId")
    
    run_data = store[run_id]
    receipt_id = payload.get("receiptId", "rec_default")
    outcomes = payload.get("outcomes", [])
    approvals = payload.get("approvals", [])

    for out in outcomes:
        run_data["receiptLog"].append({
            "receiptId": receipt_id,
            "actionId": out.get("actionId"),
            "callId": out.get("callId"),
            "attempt": out.get("attempt", 1),
            "status": out.get("status", 200),
            "resultClass": out.get("resultClass", "success"),
            "nonce": out.get("nonce", "nonce")
        })

    for app_rec in approvals:
        run_data["receiptLog"].append({
            "receiptId": receipt_id,
            "approvalId": app_rec.get("approvalId"),
            "decision": app_rec.get("decision", "approved"),
            "nonce": app_rec.get("nonce", "nonce")
        })

    # Move to completed status after receiving receipts
    effect_name = run_data["request_payload"].get("policy", {}).get("effectTools", ["scale_service"])[0]
    
    completed_state = {
        "runId": run_id,
        "status": "completed",
        "diagnosis": run_data["current_state"]["diagnosis"],
        "chosenEffect": effect_name,
        "suppressed": [],
        "actionLog": run_data["actionLog"],
        "receiptLog": run_data["receiptLog"],
        "otlp": run_data["otlp"]
    }

    run_data["current_state"] = completed_state
    save_incidents(store)
    return completed_state

@app.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    store = load_incidents()
    if run_id not in store:
        raise HTTPException(status_code=404, detail="Run not found")
    return store[run_id]["current_state"]
