from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn
import hashlib
from scanner import ThreatScanner
from sandbox import GhostSandbox
from guardian import GuardianAlert
from database import Database

app = FastAPI(title="ShieldNetX API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = Database()
scanner = ThreatScanner()
sandbox = GhostSandbox()
guardian = GuardianAlert()

@app.on_event("startup")
async def startup():
    await db.init()
    print("🛡️ ShieldNetX backend is running!")

class ScanRequest(BaseModel):
    url: str
    message: Optional[str] = None
    user_ip: Optional[str] = "unknown"
    guardian_number: Optional[str] = None
    unknown_sender: Optional[bool] = False  # Signal 6 from Android app

@app.get("/")
async def root():
    return {"status": "ShieldNetX is running 🛡️", "version": "1.0.0"}

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/scan")
async def scan(req: ScanRequest, request: Request):
    # Get real IP
    ip = req.user_ip
    if ip == "unknown":
        ip = request.client.host

    url_hash = hashlib.sha256(req.url.encode()).hexdigest()

    # Step 1: Ghost Sandbox
    print(f"🔍 Scanning: {req.url}")
    sandbox_result = await sandbox.analyze(req.url)

    # Step 2: Full threat scoring
    result = await scanner.full_scan(
        url=req.url,
        message=req.message or "",
        ip=ip,
        sandbox_result=sandbox_result
    )

    # Step 3: Unknown sender bonus (Signal 6 from Android)
    if req.unknown_sender:
        result["threat_score"] = min(result["threat_score"] + 15, 100)
        result["signals"]["unknown_sender"] = {
            "triggered": True,
            "score": 15,
            "verdict": "Sender not in contacts — high risk"
        }

    # Step 4: Save to DB
    await db.record_scan(
        url_hash=url_hash,
        url=req.url,
        ip=ip,
        country="IN",
        city="Unknown",
        score=result["threat_score"]
    )

    # Step 5: Guardian Alert if critical
    alert_sent = False
    threshold = 70
    if result["threat_score"] >= threshold and req.guardian_number:
        threat_type = result["signals"]["ai_analysis"].get("threat_type", "Unknown")
        alert_sent = guardian.send_alert(
            guardian_number=req.guardian_number,
            threat_score=result["threat_score"],
            url=req.url,
            threat_type=threat_type
        )

    return {
        "url": req.url,
        "threat_score": result["threat_score"],
        "threat_level": result["threat_level"],
        "signals": result["signals"],
        "screenshot_b64": sandbox_result.get("screenshot_b64"),
        "guardian_alert_sent": alert_sent,
        "recommendation": result["signals"]["ai_analysis"].get("recommendation", "Stay safe."),
        "explanation": result["signals"]["ai_analysis"].get("explanation", ""),
        "tamil_explanation": result["signals"]["ai_analysis"].get("tamil_explanation", "")
    }

@app.get("/recent-scans")
async def recent_scans():
    scans = await db.get_recent_scans(20)
    return {"scans": scans}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

from virustotal import scan_url as vt_scan

@app.post("/vt-scan")
async def virustotal_scan(request: Request):
    body = await request.json()
    url = body.get("url", "")
    result = await vt_scan(url)
    return result

@app.post("/scan-message")
async def scan_message_only(request: Request):
    body = await request.json()
    message = body.get("message", "")
    
    import re
    
    SCAM_PATTERNS = [
        (r'bescom|bsnl|sbi|hdfc|icici|jio|trai|uidai|aadhaar|irctc|npci', 'Bank/Govt Impersonation'),
        (r'prize|winner|won|lottery|reward|gift|lucky|congratulation', 'Prize/Lottery Scam'),
        (r'otp|password|pin|cvv|account number|card number', 'Credential Harvesting'),
        (r'suspended|blocked|expired|deactivated|freeze|locked', 'Account Threat'),
        (r'urgent|immediately|tonight|last chance|expire|disconnect|cut', 'Urgency Manipulation'),
        (r'call\s*[\d\s\-+]{8,}|whatsapp\s*[\d\s\-+]{8,}', 'Phone-based Scam'),
        (r'kyc|verify|update|confirm|validate', 'Verification Scam'),
        (r'loan|emi|insurance|policy|investment|share|stock', 'Financial Scam'),
    ]
    
    combined = message.lower()
    flags = []
    score = 0
    
    for pattern, label in SCAM_PATTERNS:
        if re.search(pattern, combined):
            flags.append(label)
            score += 15
    
    score = min(score, 95)
    
    if score >= 75: level = "CRITICAL"
    elif score >= 50: level = "HIGH"
    elif score >= 30: level = "MEDIUM"
    elif score >= 15: level = "LOW"
    else: level = "SAFE"
    
    return {
        "scam_score": score,
        "scam_level": level,
        "flags": flags,
        "message_length": len(message),
        "has_phone": bool(re.search(r'[\d\s\-+]{10,}', message)),
        "recommendation": "Do NOT call any numbers or share any info!" if score > 50 else "Looks relatively safe"
    }
