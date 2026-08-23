"""
CAPE-Policy: Web Dashboard Backend
Serves conflict data via REST API with simple token-based authentication.
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
import secrets
import subprocess

app = FastAPI(title="CAPE-Policy Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple in-memory credentials + token store (fine for a capstone demo;
# note in your paper this would be replaced by a real auth provider in
# a production deployment)
VALID_USERS = {"admin": "capepolicy2026"}
ACTIVE_TOKENS = set()


class LoginRequest(BaseModel):
    username: str
    password: str


def verify_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = authorization.replace("Bearer ", "")
    if token not in ACTIVE_TOKENS:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return token


@app.post("/api/auth/login")
def login(req: LoginRequest):
    if VALID_USERS.get(req.username) == req.password:
        token = secrets.token_hex(16)
        ACTIVE_TOKENS.add(token)
        return {"token": token, "username": req.username}
    raise HTTPException(status_code=401, detail="Invalid username or password")


@app.post("/api/auth/logout")
def logout(token: str = Depends(verify_token)):
    ACTIVE_TOKENS.discard(token)
    return {"status": "logged out"}


def load_conflicts():
    with open("data/conflict_report.json") as f:
        data = json.load(f)
    return data if isinstance(data, list) else data.get("conflicts", [])


@app.get("/api/conflicts")
def get_conflicts(token: str = Depends(verify_token)):
    conflicts = load_conflicts()
    summary = {}
    severity_summary = {"high": 0, "medium": 0, "low": 0}
    for c in conflicts:
        ctype = c["conflict_type"]
        summary[ctype] = summary.get(ctype, 0) + 1
        sev = c.get("severity", "medium")
        severity_summary[sev] = severity_summary.get(sev, 0) + 1

    return {
        "total": len(conflicts),
        "by_type": summary,
        "by_severity": severity_summary,
        "conflicts": conflicts,
    }


@app.post("/api/scan")
def trigger_scan(token: str = Depends(verify_token)):
    """Re-run the full detection engine on demand."""
    try:
        subprocess.run(
            ["python", "src/ingestion/collector.py"],
            stdout=open("data/latest_scan.json", "w"),
            check=True,
        )
        subprocess.run(["python", "src/detection/engine.py"], check=True)
        return {"status": "scan complete"}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")
