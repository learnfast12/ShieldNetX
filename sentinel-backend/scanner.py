import re
import os
from dotenv import load_dotenv
from virustotal import scan_url as vt_scan

load_dotenv()

THREAT_PATTERNS = [
    (r'testsafebrowsing|phishing|malware|ransomware|trojan|exploit|payload', 'Malware/Phishing Domain'),
    (r'bescom|bsnl|sbi|hdfc|icici|jio|trai|uidai|aadhaar', 'Impersonation Attack'),
    (r'bit\.ly|tinyurl|t\.co|shorturl|ow\.ly', 'Shortened URL'),
    (r'free|winner|prize|lucky|claim|urgent|expire|suspend|verify|update|confirm', 'Social Engineering'),
    (r'login|signin|account|secure|banking|payment|otp', 'Credential Harvesting'),
]

URGENCY_WORDS = ['tonight', 'immediately', 'now', 'urgent', 'expire', 'suspend', 'cut', 'disconnected']

def analyze_url(url: str, message: str) -> dict:
    combined = (url + " " + message).lower()
    flags = []
    threat_type = "Unknown"
    score = 0

    for pattern, ttype in THREAT_PATTERNS:
        if re.search(pattern, combined):
            flags.append(f"Detected: {ttype}")
            threat_type = ttype
            score += 25

    urgency_count = sum(1 for w in URGENCY_WORDS if w in combined)
    if urgency_count > 0:
        flags.append(f"Urgency manipulation detected ({urgency_count} signals)")
        score += urgency_count * 10

    score = min(score, 85)

    return {
        "ai_score": score,
        "threat_type": threat_type,
        "urgency_detected": urgency_count > 0,
        "url_mismatch": any(re.search(p, url.lower()) for p, _ in THREAT_PATTERNS),
        "explanation": f"Detected {len(flags)} threat signal(s): " + (", ".join(flags) if flags else "No threats found"),
        "tamil_explanation": "இந்த இணைப்பு CRITICAL அபாயகரமானது" if score > 50 else "இந்த இணைப்பு பாதுகாப்பானது",
        "recommendation": "Do not click this link!" if score > 50 else "Looks safe",
        "flags": flags
    }


class ThreatScanner:
    async def full_scan(self, url: str, message: str, ip: str, sandbox_result: dict) -> dict:
        from database import Database
        import hashlib

        db = Database()
        await db.init()

        url_hash = hashlib.sha256(url.encode()).hexdigest()

        ai = analyze_url(url, message)
        vt = await vt_scan(url)
        vt = vt or {}
        velocity = await db.get_click_velocity(url_hash)
        geo = await db.get_geo_velocity(url_hash)
        dwell = await db.get_dwell_analysis(url_hash)

        vt_contribution = min(vt.get("malicious_engines", 0) * 15, 40)

        total = (
            ai["ai_score"] +
            vt_contribution +
            sandbox_result.get("score", 0) +
            velocity["score"] +
            geo["score"] +
            dwell["score"]
        )
        total = min(int(total), 100)

        if total >= 75: level = "CRITICAL"
        elif total >= 50: level = "HIGH"
        elif total >= 30: level = "MEDIUM"
        elif total >= 15: level = "LOW"
        else: level = "SAFE"

        return {
            "threat_score": total,
            "threat_level": level,
            "signals": {
                "ai_analysis": ai,
                "virustotal": vt,
                "sandbox": sandbox_result,
                "click_velocity": velocity,
                "geo_velocity": geo,
                "dwell_time": dwell
            }
        }
