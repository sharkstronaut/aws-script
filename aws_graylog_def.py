#!/usr/bin/env python3
"""
aws.py — EC2-like script (Python-only) con envio de logs a Graylog (GELF).

Variables de entorno relevantes:
 - HP_PORT (por defecto 8000)
 - HP_LOG (por defecto ./aws_events.jsonl)
 - HP_ROLE, HP_INSTANCE_ID, HP_AMI_ID, HP_INSTANCE_TYPE
 - HP_ALERT_WEBHOOK (opcional, webhook HTTP)
 - GRAYLOG_HOST (IP o dominio de Graylog)
 - GRAYLOG_PORT (puerto GELF; por defecto 12201)
 - GRAYLOG_PROTOCOL ("udp" o "tcp"; por defecto "udp")
 - GRAYLOG_EXTRA_FIELDS (JSON string, p.e. '{"environment":"lab"}')

Instalar dependencias:
    pip install fastapi uvicorn httpx graypy
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
import httpx  # optional webhook
# graypy puede no estar instalado en todos los entornos; import seguro:
try:
    import graypy
    GRAYPY_AVAILABLE = True
except Exception:
    GRAYPY_AVAILABLE = False

# ----------------------
# Config
# ----------------------
LOG_PATH = os.getenv("HP_LOG", "./aws_events.jsonl")
PORT = int(os.getenv("HP_PORT", "8000"))
ROLE_NAME = os.getenv("HP_ROLE", "admin")
INSTANCE_ID = os.getenv("HP_INSTANCE_ID", "i-0834abcd1935cdef0")
AMI_ID = os.getenv("HP_AMI_ID", "ami-06b21b12345f6d789")
INSTANCE_TYPE = os.getenv("HP_INSTANCE_TYPE", "t3.micro")
ALERT_WEBHOOK = os.getenv("HP_ALERT_WEBHOOK", "")
MAX_LOG_BYTES = int(os.getenv("HP_MAX_LOG_BYTES", 10 * 1024 * 1024))
BACKUP_COUNT = int(os.getenv("HP_BACKUP_COUNT", 5))

# Graylog / GELF config
GRAYLOG_HOST = os.getenv("GRAYLOG_HOST", "")
GRAYLOG_PORT = int(os.getenv("GRAYLOG_PORT", "12201"))
GRAYLOG_PROTOCOL = os.getenv("GRAYLOG_PROTOCOL", "udp").lower()  # "udp" or "tcp"
GRAYLOG_EXTRA_FIELDS = os.getenv("GRAYLOG_EXTRA_FIELDS", "")  # JSON string for extra fields

# ----------------------
# Setup logging (rotating) — writes to JSONL for easy ingestion
# ----------------------
logger = logging.getLogger("aws")
logger.setLevel(logging.INFO)

# handler de fichero JSONL (si no lo quieres, comenta estas 3 líneas)
handler = RotatingFileHandler(LOG_PATH, maxBytes=MAX_LOG_BYTES, backupCount=BACKUP_COUNT)
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)

# consola
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(console)

# Añadir handler GELF si hay configuración y graypy instalado
gelf_handler = None
def try_setup_graylog():
    global gelf_handler
    if not GRAYLOG_HOST:
        logger.info("Graylog no configurado (GRAYLOG_HOST vacío). No se enviarán GELF events.")
        return
    if not GRAYPY_AVAILABLE:
        logger.warning("graypy no está instalado; para enviar a Graylog instale 'pip install graypy'.")
        return
    try:
        extra = {}
        if GRAYLOG_EXTRA_FIELDS:
            try:
                extra = json.loads(GRAYLOG_EXTRA_FIELDS)
            except Exception as e:
                logger.warning(f"GRAYLOG_EXTRA_FIELDS inválido JSON: {e}")
                extra = {}
        if GRAYLOG_PROTOCOL == "tcp":
            gelf_handler = graypy.GELFTCPHandler(GRAYLOG_HOST, GRAYLOG_PORT)
        else:
            # por defecto UDP
            gelf_handler = graypy.GELFUDPHandler(GRAYLOG_HOST, GRAYLOG_PORT)
        logger.addHandler(gelf_handler)
        logger.info(f"Handler GELF configurado -> {GRAYLOG_HOST}:{GRAYLOG_PORT} ({GRAYLOG_PROTOCOL})")
    except Exception as e:
        logger.exception(f"No se pudo configurar GELF handler: {e}")

try_setup_graylog()

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
    indicators = []
    lowered_ua = (headers.get("user-agent") or "").lower()
    auth_hdr = headers.get("authorization", "")
    if SIGV4_PATTERN.search(auth_hdr) or ACCESS_KEY_PATTERN.search(auth_hdr) or any(u in lowered_ua for u in AWS_USERAGENTS):
        indicators.append("auth-attempt-or-sigv4")
    m = AWS_ACTION_PATTERN.search(query or "")
    if m:
        action = m.group(1).lower()
        indicators.append(f"aws-action:{action}")
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
    if path.startswith("/latest/meta-data"):
        if path.startswith("/latest/meta-data/iam/security-credentials"):
            indicators.append("metadata-iam-request")
            return {"phase": "verify", "indicators": indicators}
        return {"phase": "enumerate", "indicators": indicators}
    if "/?list-type=2" in query or (method.upper() in ("GET","PUT","POST") and "/." in path and (path.count("/") >= 2)):
        if method.upper() in ("PUT","POST","DELETE"):
            indicators.append("s3-write-attempt")
            return {"phase": "write", "indicators": indicators}
        indicators.append("s3-list-or-probe")
        return {"phase": "enumerate", "indicators": indicators}
    if SIGV4_PATTERN.search(auth_hdr):
        indicators.append("sigv4-auth-header")
        return {"phase": "verify", "indicators": indicators}
    if ACCESS_KEY_PATTERN.search(json.dumps(headers)) or (body_text and ACCESS_KEY_PATTERN.search(body_text)):
        indicators.append("access-key-pattern")
        return {"phase": "verify", "indicators": indicators}
    if any(u in lowered_ua for u in AWS_USERAGENTS):
        indicators.append("aws-tool-user-agent")
        return {"phase": "verify", "indicators": indicators}
    if method.upper() not in ("GET","POST","HEAD") or ("curl" in lowered_ua and " -I " in (headers.get("referer") or "")):
        indicators.append("fingerprinting")
        return {"phase": "fingerprint", "indicators": indicators}
    return {"phase": "info", "indicators": indicators}

# ----------------------
# Alerting & Graylog sending
# ----------------------
async def maybe_send_alert(alert: dict):
    if not ALERT_WEBHOOK:
        return
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(ALERT_WEBHOOK, json=alert)
    except Exception as e:
        logger.error(f"alert webhook failed: {e}")

def mask_sensitive_fields(obj: dict) -> dict:
    """
    Evita enviar credenciales completas al Graylog. Reemplaza AccessKeyId/SecretAccessKey/Token por máscaras.
    """
    s = dict(obj)
    if "body" in s and s["body"]:
        body = s["body"]
        body = re.sub(r"(A?SIA[A-Z0-9]{8,})", r"\1[...masked]", body)
        body = re.sub(r"(AKIA[A-Z0-9]{8,})", r"\1[...masked]", body)
        body = re.sub(r"(?i)(secretaccesskey[\"']?\s*[:=]\s*[\"'])([^\"']{4})([^\"']+)([\"'])", r"\1\2...[masked]\4", body)
        s["body"] = body
    headers = s.get("headers") or {}
    for k in list(headers.keys()):
        if "authorization" in k:
            headers[k] = "[masked-authorization]"
    s["headers"] = headers
    return s

def send_to_graylog(event: dict):
    """
    Envía un mensaje resumen al Graylog configurado (si existe).
    """
    if not GRAYLOG_HOST or not GRAYPY_AVAILABLE:
        return
    try:
        short = {
            "short_message": f"AWS event {event.get('classification', {}).get('phase')}",
            "host": "aws",
            "level": logging.INFO,
            "hp_ts": event.get("ts"),
            "hp_src_ip": event.get("src_ip"),
            "hp_method": event.get("method"),
            "hp_path": event.get("path"),
            "hp_query": event.get("query"),
            "hp_user_agent": event.get("user_agent"),
            "hp_phase": event.get("classification", {}).get("phase"),
            "hp_indicators": ",".join(event.get("classification", {}).get("indicators", []))
        }
        if GRAYLOG_EXTRA_FIELDS:
            try:
                extra = json.loads(GRAYLOG_EXTRA_FIELDS)
                for k, v in extra.items():
                    short[f"hp_extra_{k}"] = v
            except Exception:
                pass
        masked = mask_sensitive_fields(event)
        body = masked.get("body")
        if body:
            short["hp_body_preview"] = body if len(body) < 512 else body[:512] + "..."
        logger.info(json.dumps(short, ensure_ascii=False))
    except Exception as e:
        logger.exception(f"error enviando a graylog: {e}")

def record_event(event: dict):
    """Write event as JSONL to log. Also print a concise console alert for higher phases and send to Graylog."""
    logger.info(json.dumps(event, ensure_ascii=False))
    phase = event.get("classification", {}).get("phase")
    if phase in ("verify", "write", "persistence"):
        short = {
            "t": event["ts"],
            "src": event["src_ip"],
            "path": event["path"],
            "phase": phase,
            "indicators": event["classification"]["indicators"]
        }
        logger.info(f"ALERT: {json.dumps(short)}")
        try:
            import asyncio
            asyncio.create_task(maybe_send_alert(short))
        except Exception:
            pass
    try:
        send_to_graylog(event)
    except Exception as e:
        logger.exception(f"send_to_graylog failed: {e}")

# ----------------------
# Logging wrapper for requests
# ----------------------
async def capture_request(request: Request, body_bytes: bytes = b""):
    try:
        body_text = None
        if body_bytes:
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

@app.get("/{bucket}/")
async def s3_list_bucket(request: Request, bucket: str):
    await capture_request(request)
    if "list-type=2" not in request.url.query:
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

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
async def catch_all(request: Request, full_path: str, body: bytes = Body(b"")):
    classification = await capture_request(request, body)
    q = request.url.query or ""
    m = AWS_ACTION_PATTERN.search(q)
    if m:
        action = m.group(1)
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

    return PlainTextResponse("Not Found", status_code=404, headers=aws_style_headers())


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")


