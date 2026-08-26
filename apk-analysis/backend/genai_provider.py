"""
Provider-agnostic GenAI layer for ShieldNetX-APK.
Tries providers in order: Gemini (REST, free tier) -> local Ollama -> Claude (if key present) -> rule-based fallback.
"""
import os
import json
import requests

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")

GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent"

PROMPT_TEMPLATE = """You are a senior mobile malware analyst at a tier-1 bank's cybersecurity team.
Analyze the following Android APK static findings and respond ONLY with valid JSON (no markdown fences), with this exact schema:
{{
  "verdict_summary": "<3 sentence plain-English verdict>",
  "attack_techniques": ["<technique>", ...],
  "fraud_mechanisms": ["<mechanism>", ...],
  "exfiltration_targets": ["<what data / where>", ...],
  "evasion_methods": ["<technique>", ...],
  "malware_family_hypothesis": "<name or 'unknown/novel'>",
  "confidence_score": <0-100 integer>
}}

DECISION RUBRIC (apply strictly and consistently across runs on identical input):
- Do NOT use package name familiarity as evidence of legitimacy or benignity. Package names are
  trivially spoofable — a real attacker's most common technique is repackaging a well-known app
  (same package name, same visual identity) while injecting malicious permissions or code. Judge
  ONLY on the concrete permissions, dangerous combos, and keyword evidence provided below.
- The "Dangerous combos" list below is pre-computed by static analysis using known attack patterns
  (e.g. READ_SMS + INTERNET = OTP theft, BIND_ACCESSIBILITY_SERVICE = overlay/keylogger risk). If
  this list is non-empty, especially with CRITICAL entries, treat that as concrete evidence requiring
  serious weight in your verdict — do not dismiss it as "normal" functionality for any app, regardless
  of package name.
- If a well-known package name appears ALONGSIDE permissions or combos that do not match that app's
  actual publicly documented functionality (e.g. an app-store client requesting READ_SMS or
  BIND_ACCESSIBILITY_SERVICE, which legitimate app stores do not need), treat this combination as a
  potential repackaging/impersonation attack — this is MORE suspicious than an unfamiliar package name
  with the same permissions, not less.
- Only mark malware_family_hypothesis as "unknown/novel" or "benign" when the dangerous_combos list is
  empty AND there is no concrete evidence of malicious behavior in the findings.
- confidence_score reflects confidence in the VERDICT itself, based on the strength of the concrete
  evidence present, not on familiarity with the package name.

APK STATIC FINDINGS:
{findings}
"""

def _try_gemini(findings: str):
    if not GEMINI_API_KEY:
        print("[genai] No GEMINI_API_KEY set")
        return None
    try:
        resp = requests.post(
            GEMINI_ENDPOINT,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": GEMINI_API_KEY,
            },
            json={
                "contents": [{"parts": [{"text": PROMPT_TEMPLATE.format(findings=findings)}]}],
                "generationConfig": {"temperature": 0.1, "topP": 0.8, "topK": 10},
            },
            timeout=60,
        )
        if resp.status_code != 200:
            print(f"[genai] Gemini REST failed: {resp.status_code} {resp.text}")
            return None
        data = resp.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        text = text.strip("```json").strip("```").strip()
        return json.loads(text)
    except Exception as e:
        print(f"[genai] Gemini failed: {e}")
        return None

def _try_ollama(findings: str):
    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": PROMPT_TEMPLATE.format(findings=findings),
                "stream": False,
                "format": "json",
            },
            timeout=60,
        )
        r.raise_for_status()
        text = r.json().get("response", "").strip()
        return json.loads(text)
    except Exception as e:
        print(f"[genai] Ollama failed: {e}")
        return None

def _try_claude(findings: str):
    if not ANTHROPIC_API_KEY:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1000,
            messages=[{"role": "user", "content": PROMPT_TEMPLATE.format(findings=findings)}],
        )
        text = msg.content[0].text.strip().strip("```json").strip("```").strip()
        return json.loads(text)
    except Exception as e:
        print(f"[genai] Claude failed: {e}")
        return None

def _rule_based_fallback(findings: str):
    return {
        "verdict_summary": "GenAI providers unavailable — falling back to rule-based static verdict. Review static findings manually.",
        "attack_techniques": [],
        "fraud_mechanisms": [],
        "exfiltration_targets": [],
        "evasion_methods": [],
        "malware_family_hypothesis": "unknown (GenAI offline)",
        "confidence_score": 0,
    }

def get_genai_verdict(findings: str) -> dict:
    for provider_fn, name in [(_try_gemini, "gemini"), (_try_ollama, "ollama")]:
        result = provider_fn(findings)
        if result:
            result["_provider_used"] = name
            return result
    result = _rule_based_fallback(findings)
    result["_provider_used"] = "none"
    return result
