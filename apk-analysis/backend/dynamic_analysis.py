"""
Dynamic sandbox analysis for ShieldNetX-APK.
Installs the APK on a connected, rooted Android device, launches it,
attaches Frida with frida_hooks.js, and captures real runtime behavior
(SMS access, network calls, overlay attempts) for a fixed observation window.

Many malware samples ship unsigned or with malformed certs (either as an
evasion tactic or as an artifact of how the sample was assembled). Android
refuses to install unsigned APKs even via adb, so we re-sign every sample
with a throwaway local debug key before install. This does NOT alter the
app's behavior — DEX code, resources, and manifest are untouched — it only
satisfies the installer's signature requirement.

Requires: a device visible via `adb devices` with frida-server already
running as root, and the Android SDK build-tools (apksigner) available on
PATH. If no device/Frida is available, this stage degrades gracefully and
reports itself as unavailable rather than failing the whole pipeline.
"""
import subprocess
import time
import os

HOOK_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "frida_hooks.js")
KEYSTORE_PATH = os.path.join(os.path.dirname(__file__), "keystore", "debug.keystore")
KEYSTORE_PASS = "android"
OBSERVATION_SECONDS = 30


def _adb(args, timeout=30):
    result = subprocess.run(["adb"] + args, capture_output=True, text=True, timeout=timeout)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def _get_package_name(apk_path: str) -> str:
    result = subprocess.run(
        ["aapt", "dump", "badging", apk_path], capture_output=True, text=True, timeout=30
    )
    for line in result.stdout.splitlines():
        if line.startswith("package: name="):
            return line.split("name='")[1].split("'")[0]
    raise RuntimeError("Could not determine package name from APK")


def _resign_apk(apk_path: str) -> str:
    """Re-signs the APK with our local debug key. Returns path to the signed copy.
    Original file is left untouched — signing writes to a temp copy."""
    signed_path = f"/tmp/shieldnetx_signed_{os.path.basename(apk_path)}"
    result = subprocess.run(
        [
            "apksigner", "sign",
            "--ks", KEYSTORE_PATH,
            "--ks-pass", f"pass:{KEYSTORE_PASS}",
            "--key-pass", f"pass:{KEYSTORE_PASS}",
            "--out", signed_path,
            apk_path,
        ],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"apksigner failed: {result.stderr[-500:]}")
    return signed_path


def device_available() -> bool:
    out, _, _ = _adb(["devices"])
    lines = [l for l in out.splitlines()[1:] if l.strip()]
    return any("\tdevice" in l for l in lines)


def _disable_package_verifier():
    """One-time-idempotent: disables Play Protect / package verifier so
    malware samples aren't silently blocked or scanned off-device."""
    _adb(["shell", "settings", "put", "global", "verifier_verify_adb_installs", "0"])
    _adb(["shell", "settings", "put", "global", "package_verifier_enable", "0"])
    _adb(["shell", "settings", "put", "global", "package_verifier_user_consent", "-1"])


def run_dynamic_analysis(apk_path: str) -> dict:
    if not device_available():
        return {
            "available": False,
            "reason": "No authorized Android device connected — dynamic analysis skipped, static + GenAI findings only",
            "events": [],
        }

    events = []
    package_name = None
    signed_path = None

    try:
        package_name = _get_package_name(apk_path)
        _disable_package_verifier()

        signed_path = _resign_apk(apk_path)

        install_out, install_err, rc = _adb(["install", "-r", signed_path], timeout=60)
        if rc != 0:
            return {"available": False, "reason": f"Install failed: {install_err}", "events": []}

        _adb(["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"])
        time.sleep(3)

        pidof_out, _, _ = _adb(["shell", "pidof", package_name])
        if not pidof_out.strip():
            return {"available": False, "reason": f"App did not launch — no PID found for {package_name} after monkey launch", "events": []}
        target_pid = int(pidof_out.strip().split()[0])

        import frida

        device = frida.get_usb_device(timeout=10)
        session = device.attach(target_pid)

        with open(HOOK_SCRIPT_PATH) as f:
            script_src = f.read()
        script = session.create_script(script_src)

        def on_message(message, data):
            if message.get("type") == "send":
                events.append(message["payload"])

        script.on("message", on_message)
        script.load()

        time.sleep(OBSERVATION_SECONDS)

        session.detach()

    except Exception as e:
        return {
            "available": False,
            "reason": f"Dynamic analysis error: {str(e)}",
            "events": events,
        }
    finally:
        if package_name:
            _adb(["uninstall", package_name])
        if signed_path and os.path.exists(signed_path):
            os.remove(signed_path)

    sms_events = [e for e in events if e.get("type") == "sms_access"]
    network_events = [e for e in events if e.get("type") == "network_call"]
    overlay_events = [e for e in events if e.get("type") == "overlay_attempt"]

    return {
        "available": True,
        "package_name": package_name,
        "observation_seconds": OBSERVATION_SECONDS,
        "sms_access_detected": len(sms_events) > 0,
        "sms_events": sms_events,
        "network_calls_detected": len(network_events) > 0,
        "network_events": network_events,
        "overlay_attempt_detected": len(overlay_events) > 0,
        "overlay_events": overlay_events,
        "raw_event_count": len(events),
        "events": events,
    }
