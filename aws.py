#!/usr/bin/env python3
"""
aws.py
Python-only EC2-like script that emulates:
 - IMDSv1 metadata
 - IAM fake credentials
 - Minimal S3 ListObjectsV2
 - Generic AWS-like API endpoints detection (Action=..., Authorization: AWS4-HMAC-SHA256, etc.)
 - Structured JSONL logging + simple classification into attacker phases.

Run:
    pip install -r requirements.txt
    python3 aws.py

Config via environment variables:
 - HP_PORT (default 8000)
 - HP_LOG (default ./aws_events.jsonl)
 - HP_ROLE (default MyEC2Role)
 - HP_INSTANCE_ID, HP_AMI_ID, HP_INSTANCE_TYPE
 - HP_ALERT_WEBHOOK (optional) -> POST JSON alerts to this webhook
"""

import os
import re
import json
import uuid
import base64
from datetime import datetime, timedelta
from typing import Optional
import logging
from logging.handlers import RotatingFileHandler

from fastapi import FastAPI, Request, Body
from fastapi.responses import PlainTextResponse, JSONResponse, Response
from xml.etree.ElementTree import Element, SubElement, tostring
import uvicorn
import httpx  # used only for webhook alerting (optional)

# ----------------------
# Config
# ----------------------
LOG_PATH = os.getenv("HP_LOG", "./aws_events.jsonl")
PORT = int(os.getenv("HP_PORT", "8000"))
ROLE_NAME = os.getenv("HP_ROLE", "MyEC2Role")
INSTANCE_ID = os.getenv("HP_INSTANCE_ID", "i-0834abcd1234cdef0")
AMI_ID = os.getenv("HP_AMI_ID", "ami-06b21b12345f6d789")
INSTANCE_TYPE = os.getenv("HP_INSTANCE_TYPE", "t3.micro")
ALERT_WEBHOOK = os.getenv("HP_ALERT_WEBHOOK", "")
MAX_LOG_BYTES = 10 * 1024 * 1024
BACKUP_COUNT = 5

# ----------------------
# Setup logging (rotating) — writes to JSONL for easy ingestion
# ----------------------
logger = logging.getLogger("aws")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_PATH, maxBytes=MAX_LOG_BYTES, backupCount=BACKUP_COUNT)
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)

console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(console)

app = FastAPI(title="EC2-like script", docs_url=None, redoc_url=None)


# ----------------------
# Utility helpers
# ----------------------
def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def aws_style_headers():
    """Generate faux AWS-like headers for responses."""
    return {
        "Server": "AmazonEC2",
        "x-amzn-RequestId": str(uuid.uuid4()),
        "x-amz-id-2": base64.b64encode(uuid.uuid4().bytes).decode('ascii').rstrip("=")
    }


ACCESS_KEY_PATTERN = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{8,}\b")
SIGV4_PATTERN = re.compile(r"AWS4-HMAC-SHA256")
AWS_ACTION_PATTERN = re.compile(r"Action=([A-Za-z0-9]+)")
AWS_USERAGENTS = [
    "aws-cli", "Pacu", "trufflehog", "ScoutSuite", "cloudsploit", "aws-sdk", "botocore", "boto3"
]


# ----------------------
# Classification rules
# ----------------------
def classify_request(path: str, method: str, headers: dict, query: str, body_text: Optional[str]) -> dict:
    """
    Heuristics to classify the request into an attack 'phase' and flags.
    Returns a dictionary with:
      - phase: one of verify, enumerate, write, fingerprint, persistence, info
      - indicators: list of strings describing suspicious features
    """
    indicators = []
    lowered_ua = (headers.get("user-agent") or "").lower()
    auth_hdr = headers.get("authorization", "")
    # Detect signature usage / credential check
    if SIGV4_PATTERN.search(auth_hdr) or ACCESS_KEY_PATTERN.search(auth_hdr) or any(u in lowered_ua for u in AWS_USERAGENTS):
        indicators.append("auth-attempt-or-sigv4")
    # Query param action typical for AWS SOAP/Query APIs (EC2/STS actions)
    m = AWS_ACTION_PATTERN.search(query or "")
    if m:
        action = m.group(1).lower()
        indicators.append(f"aws-action:{action}")
        # Map to phases
        if action in ("getcalleridentity", "sts:getcalleridentity"):
            phase = "verify"
        elif action in ("describeinstances", "listbuckets", "describe*","list*"):
            phase = "enumerate"
        elif action in ("assumerole", "assumerolewithwebidentity"):
            phase = "persistence"
        elif action in ("runinstances", "createrole", "createuser", "createaccesskey"):
            phase = "persistence"
        else:
            phase = "info"
        return {"phase": phase, "indicators": indicators}
    # Metadata access detection (IMDS paths)
    if path.startswith("/latest/meta-data"):
        # if they're asking for iam/security-credentials, they try to extract creds
        if path.startswith("/latest/meta-data/iam/security-credentials"):
            indicators.append("metadata-iam-request")
            return {"phase": "verify", "indicators": indicators}
        return {"phase": "enumerate", "indicators": indicators}
    # S3 indicators
    if "/?list-type=2" in query or (method.upper() in ("GET","PUT","POST") and "/." in path and (path.count("/") >= 2)):
        if method.upper() in ("PUT","POST","DELETE"):
            indicators.append("s3-write-attempt")
            return {"phase": "write", "indicators": indicators}
        indicators.append("s3-list-or-probe")
        return {"phase": "enumerate", "indicators": indicators}
    # Authorization header with SigV4 -> likely validation or API calls
    if SIGV4_PATTERN.search(auth_hdr):
        indicators.append("sigv4-auth-header")
        return {"phase": "verify", "indicators": indicators}
    # Access key pattern in headers or body -> likely credential usage
    if ACCESS_KEY_PATTERN.search(json.dumps(headers)) or (body_text and ACCESS_KEY_PATTERN.search(body_text)):
        indicators.append("access-key-pattern")
        return {"phase": "verify", "indicators": indicators}
    # Check for known AWS-oriented UA
    if any(u in lowered_ua for u in AWS_USERAGENTS):
        indicators.append("aws-tool-user-agent")
        return {"phase": "verify", "indicators": indicators}
    # Fingerprinting heuristics: many different resource paths, odd verbs, or malformed requests
    if method.upper() not in ("GET","POST","HEAD") or "curl" in lowered_ua and " -I " in (headers.get("referer") or ""):
        indicators.append("fingerprinting")
        return {"phase": "fingerprint", "indicators": indicators}
    # Default: low-level enumerations or innocuous requests
    return {"phase": "info", "indicators": indicators}


async def maybe_send_alert(alert: dict):
    """Simple async alert sender to webhook if configured."""
    if not ALERT_WEBHOOK:
        return
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(ALERT_WEBHOOK, json=alert)
    except Exception as e:
        logger.error(f"alert webhook failed: {e}")


def record_event(event: dict):
    """Write event as JSONL to log. Also print a concise console alert for higher phases."""
    logger.info(json.dumps(event, ensure_ascii=False))
    # console alert for important phases
    if event.get("classification", {}).get("phase") in ("verify", "write", "persistence"):
        short = {
            "t": event["ts"],
            "src": event["src_ip"],
            "path": event["path"],
            "phase": event["classification"]["phase"],
            "indicators": event["classification"]["indicators"]
        }
        logger.info(f"ALERT: {json.dumps(short)}")
        # fire-and-forget send alert (async)
        try:
            import asyncio
            asyncio.create_task(maybe_send_alert(short))
        except Exception:
            pass


# ----------------------
# Logging wrapper for requests
# ----------------------
async def capture_request(request: Request, body_bytes: bytes = b""):
    try:
        body_text = None
        if body_bytes:
            # Try decode if text-like
            try:
                body_text = body_bytes.decode('utf-8', errors='replace')
            except Exception:
                body_text = "<binary>"
        headers = {k.lower(): v for k, v in request.headers.items()}
        classification = classify_request(request.url.path, request.method, headers, request.url.query, body_text)
        event = {
            "ts": now_iso(),
            "src_ip": request.client.host if request.client else None,
            "method": request.method,
            "path": request.url.path,
            "query": request.url.query,
            "user_agent": headers.get("user-agent"),
            "headers": headers,
            "body": body_text if body_text and len(body_text) < 4096 else (body_text[:4096] + "...") if body_text else None,
            "classification": classification
        }
        record_event(event)
        return classification
    except Exception as e:
        logger.error(f"capture_request error: {e}")
        return {"phase": "error", "indicators": ["capture-failed"]}


# ----------------------
# FastAPI endpoints
# ----------------------

@app.get("/")
async def root(request: Request):
    await capture_request(request)
    return PlainTextResponse("Amazon EC2", headers=aws_style_headers())


# --- IMDSv1 metadata ---
@app.get("/latest/meta-data/")
async def meta_index(request: Request):
    await capture_request(request)
    body = "\n".join([
        "ami-id",
        "instance-id",
        "instance-type",
        "iam/security-credentials/",
    ]) + "\n"
    return PlainTextResponse(body, headers=aws_style_headers())


@app.get("/latest/meta-data/instance-id")
async def meta_instance_id(request: Request):
    await capture_request(request)
    return PlainTextResponse(INSTANCE_ID, headers=aws_style_headers())


@app.get("/latest/meta-data/ami-id")
async def meta_ami_id(request: Request):
    await capture_request(request)
    return PlainTextResponse(AMI_ID, headers=aws_style_headers())


@app.get("/latest/meta-data/instance-type")
async def meta_instance_type(request: Request):
    await capture_request(request)
    return PlainTextResponse(INSTANCE_TYPE, headers=aws_style_headers())


@app.get("/latest/meta-data/iam/security-credentials/")
async def meta_iam_list(request: Request):
    await capture_request(request)
    return PlainTextResponse(ROLE_NAME, headers=aws_style_headers())


@app.get("/latest/meta-data/iam/security-credentials/{role_name}")
async def meta_iam_role(request: Request, role_name: str):
    # generate plausible fake keys (not real)
    await capture_request(request)
    expiration = (datetime.utcnow() + timedelta(hours=1)).replace(microsecond=0).isoformat() + "Z"
    fake_access_key = "ASIA" + base64.b32encode(uuid.uuid4().bytes).decode().replace("=", "")[:12]
    fake_secret = base64.b64encode(uuid.uuid4().bytes * 2).decode().rstrip("=")
    fake_token = base64.b64encode(uuid.uuid4().bytes * 3).decode().rstrip("=")
    body = {
        "Code": "Success",
        "Type": "AWS-HMAC",
        "AccessKeyId": fake_access_key,
        "SecretAccessKey": fake_secret,
        "Token": fake_token,
        "Expiration": expiration
    }
    return JSONResponse(body, headers=aws_style_headers())


# --- Minimal S3 list objects v2 ---
@app.get("/{bucket}/")
async def s3_list_bucket(request: Request, bucket: str):
    await capture_request(request)
    if "list-type=2" not in request.url.query:
        # realistic AccessDenied on bad calls
        return PlainTextResponse("AccessDenied", status_code=403, headers=aws_style_headers())
    root = Element('ListBucketResult')
    SubElement(root, 'Name').text = bucket
    SubElement(root, 'KeyCount').text = "0"
    SubElement(root, 'MaxKeys').text = "1000"
    SubElement(root, 'IsTruncated').text = "false"
    xml = tostring(root, encoding='utf-8')
    headers = aws_style_headers()
    headers['Content-Type'] = 'application/xml'
    return Response(content=xml, media_type='application/xml', headers=headers)


# --- Generic AWS-like endpoint catcher ---
@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
async def catch_all(request: Request, full_path: str, body: bytes = Body(b"")):
    """
    Catch-all to log and detect attempts to call AWS APIs that are not implemented.
    It looks for common query params (Action=...), Authorization headers, and returns
    plausible error messages so automated tools continue scanning.
    """
    classification = await capture_request(request, body)
    # If they try an AWS Action, respond with a plausible XML error or JSON error depending on query
    q = request.url.query or ""
    m = AWS_ACTION_PATTERN.search(q)
    if m:
        action = m.group(1)
        # Return a safe, generic-looking XML error (AWS-style)
        root = Element('Response')
        err = SubElement(root, 'Errors')
        e = SubElement(err, 'Error')
        SubElement(e, 'Code').text = "AccessDenied"
        SubElement(e, 'Message').text = f"The action {action} is not allowed."
        SubElement(root, 'RequestId').text = str(uuid.uuid4())
        xml = tostring(root, encoding='utf-8')
        headers = aws_style_headers()
        headers['Content-Type'] = 'application/xml'
        return Response(content=xml, media_type='application/xml', headers=headers, status_code=403)
    # If Authorization header present -> indicate 'InvalidClientTokenId' style
    auth = request.headers.get("authorization", "")
    if SIGV4_PATTERN.search(auth):
        body = {
            "Error": {
                "Code": "InvalidClientTokenId",
                "Message": "The security token included in the request is invalid."
            },
            "RequestId": str(uuid.uuid4())
        }
        return JSONResponse(body, status_code=403, headers=aws_style_headers())
    # Default fallback: simple plaintext to look normal
    return PlainTextResponse("Not Found", status_code=404, headers=aws_style_headers())


# ----------------------
# Startup/Shutdown events (changed because of on_event being deprecated)
# ----------------------
# @app.on_event("startup")
# async def startup_event():
#     logger.info(f"AWS starting on port {PORT} - logs -> {LOG_PATH}")


# @app.on_event("shutdown")
# async def shutdown_event():
#     logger.info("AWS shutting down")

# ----------------------
# Startup/Shutdown events (changed because of on_event being deprecated)
# ----------------------
async def lifespan(app: FastAPI):
    # On startup:
    logger.info(f"AWS starting on port {PORT} - logs -> {LOG_PATH}")
    yield
    #On shutdown:
    logger.info("AWS shutting down")


# ----------------------
# Run server
# ----------------------
if __name__ == "__main__":
    uvicorn.run("aws:app", host="0.0.0.0", port=PORT, log_level="info")
