from fastapi import FastAPI, HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64
import hashlib
import json

app = FastAPI()

EVAL_STORAGE = {}    # evaluationId -> state
DOSSIER_CACHE = {}   # content hash -> cached proposal

def compute_input_digest(dossiers) -> str:
    sorted_json = json.dumps(dossiers, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(sorted_json.encode("utf-8")).hexdigest()

def get_dossier_content_hash(dossier) -> str:
    d_copy = dossier.copy()
    d_copy.pop("dossierId", None)
    sorted_json = json.dumps(d_copy, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(sorted_json.encode("utf-8")).hexdigest()

@app.post("/")
async def handle_mailroom(payload: dict):
    operation = payload.get("operation")
    if operation == "propose":
        return handle_propose(payload)
    elif operation == "commit":
        return handle_commit(payload)
    else:
        raise HTTPException(status_code=400, detail="Invalid operation")

def handle_propose(data: dict):
    eval_id = data.get("evaluationId")
    dossiers = data.get("dossiers", [])
    verifier = data.get("receiptVerifier")
    
    if not eval_id or not dossiers:
        raise HTTPException(status_code=400, detail="Malformed request schema")

    input_digest = compute_input_digest(dossiers)
    
    # Conflict check: same evaluationId with changed content must return 409
    if eval_id in EVAL_STORAGE:
        if EVAL_STORAGE[eval_id]["input_digest"] != input_digest:
            raise HTTPException(status_code=409, detail="IDEMPOTENCY_CONFLICT")
        return EVAL_STORAGE[eval_id]["propose_response"]

    proposals = []
    for dossier in dossiers:
        dossier_id = dossier["dossierId"]
        objective = dossier.get("objective", "").lower()
        mailbox = dossier.get("mailbox", "default")
        sources = dossier.get("sources", [])
        partition = dossier.get("partition", "stable_core")
        
        first_line_id = "line_1"
        if sources and sources[0].get("lines"):
            first_line_id = sources[0]["lines"][0]["lineId"]

        # Cache lookup for stable core
        content_hash = get_dossier_content_hash(dossier)
        if partition == "stable_core" and content_hash in DOSSIER_CACHE:
            cached_prop = DOSSIER_CACHE[content_hash].copy()
            cached_prop["dossierId"] = dossier_id
            proposals.append(cached_prop)
            continue

        # Rule-based action heuristic
        if "quarantine" in objective or "injection" in objective or "attack" in objective:
            action = "quarantine_item"
            target = {"kind": "security_queue", "id": "mailroom"}
            payload = {"artifactId": dossier_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"}
        elif "draft" in objective or "customer" in objective:
            action = "create_draft"
            target = {"kind": "draft_queue", "id": f"mailbox:{mailbox}"}
            payload = {"recipient": "customer@example.com", "referenceId": dossier_id, "status": "draft", "template": "order_status"}
        else:
            action = "no_action"
            target = None
            payload = {"reasonCode": "INFORMATIONAL", "referenceId": dossier_id}

        call_id = hashlib.sha256(f"{eval_id}-{dossier_id}".encode()).hexdigest()[:20]

        proposal = {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": action,
            "target": target,
            "payload": payload,
            "evidence": [first_line_id]
        }
        proposals.append(proposal)

        if partition == "stable_core":
            DOSSIER_CACHE[content_hash] = proposal.copy()

    response_body = {
        "profile": "ga5-mailroom-action-gate/v2",
        "evaluationId": eval_id,
        "status": "awaiting_receipts",
        "inputDigest": input_digest,
        "proposals": proposals
    }

    EVAL_STORAGE[eval_id] = {
        "input_digest": input_digest,
        "verifier": verifier,
        "proposals": {p["callId"]: p for p in proposals},
        "propose_response": response_body
    }
    return response_body

def handle_commit(data: dict):
    eval_id = data.get("evaluationId")
    input_digest = data.get("inputDigest")
    receipts = data.get("receipts", [])

    if eval_id not in EVAL_STORAGE:
        raise HTTPException(status_code=400, detail="Unknown evaluation ID")
    
    stored = EVAL_STORAGE[eval_id]
    if stored["input_digest"] != input_digest:
        raise HTTPException(status_code=409, detail="Input digest mismatch")

    verifier = stored.get("verifier")
    if not verifier or "publicKeyJwk" not in verifier:
        raise HTTPException(status_code=400, detail="Missing receipt verifier")

    pub_key_jwk = verifier["publicKeyJwk"]
    outcomes = []
    
    for r in receipts:
        call_id = r.get("callId")
        dossier_id = r.get("dossierId")
        action = r.get("action")
        accepted = r.get("accepted")
        receipt_id = r.get("receiptId")
        proposal_digest = r.get("proposalDigest")
        sig_b64 = r.get("receiptSignature")

        if not all([call_id, dossier_id, action, receipt_id, proposal_digest, sig_b64]):
            raise HTTPException(status_code=400, detail="Malformed receipt schema")

        inner_receipt = {
            "dossierId": dossier_id, 
            "callId": call_id, 
            "action": action,
            "accepted": accepted, 
            "proposalDigest": proposal_digest, 
            "receiptId": receipt_id
        }
        verification_payload = {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id, 
            "inputDigest": input_digest, 
            "receipt": inner_receipt
        }
        
        msg_bytes = json.dumps(verification_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        
        try:
            # Robust base64url padding for Ed25519 public key
            x_raw = pub_key_jwk["x"]
            x_raw += "=" * (-len(x_raw) % 4)
            x_bytes = base64.urlsafe_b64decode(x_raw)
            
            public_key = Ed25519PublicKey.from_public_bytes(x_bytes)
            sig_bytes = base64.b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
            public_key.verify(sig_bytes, msg_bytes)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid receipt signature")

        outcomes.append({
            "dossierId": dossier_id, 
            "callId": call_id, 
            "action": action,
            "proposalDigest": proposal_digest, 
            "receiptId": receipt_id,
            "status": "executed" if accepted else "rejected"
        })

    return {
        "profile": "ga5-mailroom-action-gate/v2",
        "evaluationId": eval_id,
        "status": "completed",
        "inputDigest": input_digest,
        "outcomes": outcomes
    }
