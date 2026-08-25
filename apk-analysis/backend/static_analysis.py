from androguard.misc import AnalyzeAPK
from cryptography import x509

DANGEROUS_COMBOS = [
    (("android.permission.READ_SMS", "android.permission.INTERNET"), "OTP/Credential theft and exfiltration", "CRITICAL"),
    (("android.permission.BIND_ACCESSIBILITY_SERVICE",), "Overlay attack / Keylogger", "CRITICAL"),
    (("android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.FOREGROUND_SERVICE"), "Persistence mechanism", "HIGH"),
    (("android.permission.REQUEST_INSTALL_PACKAGES",), "Dropper malware / Secondary payload", "HIGH"),
    (("android.permission.READ_CONTACTS", "android.permission.SEND_SMS"), "SMS spam propagation (FluBot-style)", "MEDIUM"),
    (("android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.INTERNET"), "Spyware / RAT capability", "HIGH"),
]

BANKING_KEYWORDS = ["UPI", "IFSC", "AADHAAR", "OTP", "PIN", "CVV", "NETBANKING"]


def _parse_cert_subjects(apk) -> list:
    """Parse raw DER certificate bytes into readable subject/issuer/validity info,
    instead of dumping raw bytes into the report."""
    parsed = []
    if not apk.is_signed_v2():
        return parsed
    for der_bytes in apk.get_certificates_der_v2():
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
            parsed.append({
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": str(cert.serial_number),
                "valid_from": cert.not_valid_before_utc.isoformat(),
                "valid_until": cert.not_valid_after_utc.isoformat(),
            })
        except Exception as e:
            parsed.append({"parse_error": str(e)})
    return parsed


def analyze_apk(filepath: str) -> dict:
    a, d, dx = AnalyzeAPK(filepath)

    permissions = set(a.get_permissions())

    matched_combos = []
    for combo, attack, risk in DANGEROUS_COMBOS:
        if all(p in permissions for p in combo):
            matched_combos.append({"permissions": list(combo), "attack": attack, "risk": risk})

    all_strings = []
    for dex in d:
        all_strings.extend(dex.get_strings())
    strings_blob = " ".join(all_strings)

    banking_hits = [kw for kw in BANKING_KEYWORDS if kw.lower() in strings_blob.lower()]

    return {
        "package_name": a.get_package(),
        "app_name": a.get_app_name(),
        "version": a.get_androidversion_name(),
        "min_sdk": a.get_min_sdk_version(),
        "target_sdk": a.get_target_sdk_version(),
        "permissions": sorted(list(permissions)),
        "dangerous_combos": matched_combos,
        "banking_keyword_hits": banking_hits,
        "is_signed": a.is_signed(),
        "cert_subjects": _parse_cert_subjects(a),
    }
