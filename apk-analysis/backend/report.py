"""
Layer 6: Auto-Report generator for ShieldNetX-APK.
Takes static findings + GenAI verdict + risk score and produces the
plain-English executive report your pitch promises: summary, attack
narrative, IOCs, MITRE ATT&CK Mobile mapping, recommended actions,
and a draft CERT-In disclosure paragraph.
"""
from datetime import datetime

# Maps our internal attack-type strings to MITRE ATT&CK Mobile technique IDs.
# Extend this as you add more dangerous-combo rules in static_analysis.py.
MITRE_MOBILE_MAP = {
    "OTP/Credential theft and exfiltration": ("T1636.003", "Protected User Data: Contact List / SMS"),
    "Overlay attack / Keylogger": ("T1417.002", "Input Capture: GUI Input Capture"),
    "Persistence mechanism": ("T1624.001", "Event Triggered Execution: Broadcast Receivers"),
    "Dropper malware / Secondary payload": ("T1476", "Deliver Malicious App via Other Means"),
    "SMS spam propagation (FluBot-style)": ("T1638", "Adversary-in-the-Middle"),
    "Spyware / RAT capability": ("T1429", "Audio Capture"),
}


def _build_iocs(static_findings: dict, sha256: str) -> dict:
    return {
        "sha256": sha256,
        "package_name": static_findings.get("package_name"),
        "cert_subjects": static_findings.get("cert_subjects", []),
        "suspicious_permissions": [
            p for combo in static_findings.get("dangerous_combos", [])
            for p in combo["permissions"]
        ],
    }


def _build_mitre_mapping(static_findings: dict) -> list:
    mapping = []
    for combo in static_findings.get("dangerous_combos", []):
        technique = MITRE_MOBILE_MAP.get(combo["attack"])
        if technique:
            mapping.append({
                "attack": combo["attack"],
                "technique_id": technique[0],
                "technique_name": technique[1],
                "risk": combo["risk"],
            })
    return mapping


def _build_narrative(static_findings: dict, genai_verdict: dict, risk: dict) -> str:
    app_name = static_findings.get("app_name", "Unknown app")
    pkg = static_findings.get("package_name", "unknown package")
    verdict_summary = genai_verdict.get("verdict_summary", "No GenAI verdict available.")
    family = genai_verdict.get("malware_family_hypothesis", "unknown")

    parts = [
        f"'{app_name}' ({pkg}) was submitted for analysis and received a risk score "
        f"of {risk['score']}/100, classified as {risk['severity']}.",
        verdict_summary,
    ]
    if family and family.lower() not in ("unknown", "unknown/novel", "unknown (genai offline)"):
        parts.append(f"Behavioral patterns are consistent with the '{family}' malware family.")
    return " ".join(parts)


def _recommended_actions(risk: dict) -> list:
    base = [risk["action"]]
    if risk["severity"] in ("CRITICAL", "HIGH"):
        base += [
            "Block APK hash and associated distribution domains at network egress",
            "Notify affected customers if app was distributed via bank-branded channels",
            "Escalate to fraud/incident response team",
        ]
    elif risk["severity"] == "MEDIUM":
        base += ["Route to analyst for manual verification before any customer-facing action"]
    else:
        base += ["No immediate action required; retain for trend monitoring"]
    return base


def _cert_in_draft(static_findings: dict, risk: dict, sha256: str) -> str:
    return (
        f"Draft CERT-In Disclosure (review before submission):\n"
        f"Incident Type: Malicious Mobile Application (Banking Fraud)\n"
        f"Application Package: {static_findings.get('package_name', 'N/A')}\n"
        f"SHA-256: {sha256}\n"
        f"Severity: {risk['severity']} (Score: {risk['score']}/100)\n"
        f"Detected: {datetime.utcnow().isoformat()}Z\n"
        f"Summary: Automated GenAI-assisted static and behavioral analysis flagged this "
        f"application as {risk['severity']} risk for banking credential/OTP theft. "
        f"Full technical report attached. Reported within CERT-In's 6-hour mandatory window."
    )


def generate_report(static_findings: dict, genai_verdict: dict, risk: dict, sha256: str) -> dict:
    return {
        "executive_summary": _build_narrative(static_findings, genai_verdict, risk),
        "risk_score": risk["score"],
        "severity": risk["severity"],
        "score_breakdown": risk["breakdown"],
        "iocs": _build_iocs(static_findings, sha256),
        "mitre_attack_mapping": _build_mitre_mapping(static_findings),
        "genai_findings": {
            "attack_techniques": genai_verdict.get("attack_techniques", []),
            "fraud_mechanisms": genai_verdict.get("fraud_mechanisms", []),
            "exfiltration_targets": genai_verdict.get("exfiltration_targets", []),
            "evasion_methods": genai_verdict.get("evasion_methods", []),
            "malware_family_hypothesis": genai_verdict.get("malware_family_hypothesis", "unknown"),
            "genai_provider_used": genai_verdict.get("_provider_used", "unknown"),
        },
        "recommended_actions": _recommended_actions(risk),
        "cert_in_disclosure_draft": _cert_in_draft(static_findings, risk, sha256),
        "generated_at": datetime.utcnow().isoformat(),
    }
