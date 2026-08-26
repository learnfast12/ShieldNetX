NEGATIVE_PHRASES = ["none", "none detected", "n/a", "not detected", "no evidence", "not applicable"]
BENIGN_MARKERS = ["benign", "legitimate", "clean", "safe"]
MIN_CONFIDENCE_FOR_GENAI_SIGNALS = 60  # below this, GenAI's own uncertainty means we shouldn't score on its findings


def _has_real_findings(items) -> bool:
    if not items:
        return False
    return any(str(i).strip().lower() not in NEGATIVE_PHRASES for i in items)


def _is_benign_leaning(genai_verdict: dict) -> bool:
    """True if GenAI's own hypothesis/summary leans toward this being legitimate software,
    rather than confirmed malicious. Used to gate scoring so we don't penalize apps GenAI
    itself just called benign."""
    family = genai_verdict.get("malware_family_hypothesis", "") or ""
    if any(m in family.lower() for m in BENIGN_MARKERS):
        return True
    summary = genai_verdict.get("verdict_summary", "") or ""
    if any(m in summary.lower() for m in ["likely benign", "appears legitimate", "no malicious"]):
        return True
    return False


def compute_risk_score(static_findings: dict, genai_verdict: dict, dynamic_findings: dict = None) -> dict:
    score = 0
    breakdown = []

    confidence = genai_verdict.get("confidence_score", 0) or 0
    benign_leaning = _is_benign_leaning(genai_verdict)
    # GenAI-derived signals only count if GenAI is both confident AND not itself leaning benign.
    # A confident "this looks fine" from GenAI should not still add exfiltration/evasion points.
    trust_genai_signals = confidence >= MIN_CONFIDENCE_FOR_GENAI_SIGNALS and not benign_leaning

    if trust_genai_signals and _has_real_findings(genai_verdict.get("exfiltration_targets")):
        score += 25
        breakdown.append({"signal": "Data exfiltration confirmed (GenAI)", "points": 25})

    critical_combos = [c for c in static_findings["dangerous_combos"] if c["risk"] == "CRITICAL"]
    if critical_combos:
        score += 20
        breakdown.append({"signal": "Dangerous permission combination", "points": 20})

    if trust_genai_signals and any("overlay" in m.lower() for m in genai_verdict.get("fraud_mechanisms", [])):
        score += 20
        breakdown.append({"signal": "UI overlay attack on banking app", "points": 20})

    if trust_genai_signals and _has_real_findings(genai_verdict.get("evasion_methods")):
        score += 10
        breakdown.append({"signal": "Code obfuscation / anti-analysis", "points": 10})

    family = genai_verdict.get("malware_family_hypothesis", "")
    has_fraud_evidence = _has_real_findings(genai_verdict.get("fraud_mechanisms")) or _has_real_findings(
        genai_verdict.get("exfiltration_targets")
    )
    if trust_genai_signals and family and not benign_leaning and has_fraud_evidence:
        score += 10
        breakdown.append({"signal": f"Known malware family match: {family}", "points": 10})

    banking_hits = static_findings.get("banking_keyword_hits", [])
    if len(banking_hits) >= 2:
        score += 15
        breakdown.append({"signal": f"Banking-target keywords present ({', '.join(banking_hits)})", "points": 15})
    elif len(banking_hits) == 1:
        score += 5
        breakdown.append({"signal": f"Single banking-related keyword found ({banking_hits[0]}) — weak signal", "points": 5})

    # Transparency: if GenAI signals were suppressed, say why — this is what keeps the
    # system explainable instead of a black box when a benign app gets a low score.
    genai_offline = genai_verdict.get("_provider_used") in (None, "none")
    if genai_offline:
        breakdown.append({"signal": "GenAI-derived signals unavailable — AI provider offline, static findings only", "points": 0})
    elif not trust_genai_signals and (confidence or benign_leaning):
        reason = "GenAI assessed this as likely benign" if benign_leaning else f"GenAI confidence below threshold ({confidence}%)"
        breakdown.append({"signal": f"GenAI-derived signals suppressed — {reason}", "points": 0})

    # Dynamic analysis signals (real observed behavior > GenAI inference)
    dynamic_findings = dynamic_findings or {}
    if dynamic_findings.get("available"):
        if dynamic_findings.get("sms_access_detected"):
            score += 15
            breakdown.append({"signal": "SMS access observed at runtime (dynamic)", "points": 15})
        if dynamic_findings.get("overlay_attempt_detected"):
            score += 15
            breakdown.append({"signal": "Overlay/keylogger window observed at runtime (dynamic)", "points": 15})
        if dynamic_findings.get("network_calls_detected") and len(dynamic_findings.get("network_events", [])) > 3:
            score += 5
            breakdown.append({"signal": "Elevated network activity observed at runtime (dynamic)", "points": 5})
    else:
        breakdown.append({"signal": f"Dynamic analysis unavailable — {dynamic_findings.get('reason', 'not run')}", "points": 0})

    score = min(score, 100)

    if score >= 76:
        severity, action = "CRITICAL", "Auto-block + incident response + customer notification"
    elif score >= 51:
        severity, action = "HIGH", "Immediate block + alert"
    elif score >= 26:
        severity, action = "MEDIUM", "Analyst review required"
    else:
        severity, action = "LOW", "Log and monitor"

    return {"score": score, "severity": severity, "action": action, "breakdown": breakdown}
