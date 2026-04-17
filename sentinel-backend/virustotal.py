import httpx
import asyncio
import base64
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

async def scan_url(url: str) -> dict:
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        async with httpx.AsyncClient() as client:
            res = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": API_KEY},
                timeout=10
            )
            
            if res.status_code == 200:
                data = res.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())
                
                return {
                    "malicious_engines": malicious,
                    "suspicious_engines": suspicious,
                    "total_engines": total,
                    "vt_score": min(int((malicious / max(total, 1)) * 100), 100),
                    "verdict": "DANGEROUS" if malicious > 2 else "SUSPICIOUS" if malicious > 0 else "CLEAN"
                }
    except Exception as e:
        return {"error": str(e), "vt_score": 0, "verdict": "UNKNOWN"}
