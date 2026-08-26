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

Design principle: this stage is *optional infrastructure*. Any missing
external tool (adb, aapt, apksigner) or missing device/frida-server must
degrade this stage to `available: False` with a clear, specific reason —
never raise and never crash the pipeline. Static + GenAI + scoring stay
fully functional with dynamic analysis absent.
"""
import subprocess
import time
import os
import logging

logger = logging.getLogger("shieldnetx.dynamic_analysis")

HOOK_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "frida_hooks.js")
KEYSTORE_PATH = os.path.join(os.path.dirname(__file__), "keystore", "debug.keystore")
KEYSTORE_PASS = "android"
OBSERVATION_SECONDS = 30

REQUIRED_TOOLS = ("adb", "aapt", "apksigner")


class ToolUnavailableError(Exception):
    """Raised internally when a required external binary is missing or a
    subprocess call fails in a way that should abort this stage (not the
    whole pipeline). Always caught in run_dynamic_analysis."""


def _run(cmd, timeout=30, label=None):
    """Wrapper around subprocess.run that turns every failure mode
    (missing binary, timeout, unexpected OS error) into a single,
    typed exception carrying a human-readable reason — instead of letting
    FileNotFoundError / TimeoutExpired propagate raw into run_pipeline."""
    label = label or cmd[0]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise ToolUnavailableError(f"Required tool '{label}' not found on PATH")
    except subprocess.TimeoutExpired:
        raise ToolUnavailableError(f"'{label}' timed out after {timeout}s")
    except OSError as e:
        raise ToolUnavailableError(f"'{label}' failed to execute: {e}")


def _adb(args, timeout=30):
    result = _run(["adb"] + args, timeout=timeout, label="adb")
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def shutil_which(name: str):
    from shutil import which
    return which(name)


def check_required_tools():
    missing = [t for t in REQUIRED_TOOLS if shutil_which(t) is None]
    if missing:
        return f"Required tool(s) not found on PATH: {', '.join(missing)}"
    return None


def _get_package_name(apk_path: str) -> str:
    result = _run(["aapt", "dump", "badging", apk_path], timeout=30, label="aapt")
    if result.returncode != 0:
        raise ToolUnavailableError(f"aapt failed to parse APK: {result.stderr[-300:]}")
    for line in result.stdout.splitlines():
        if line.startswith("package: name="):
            return line.split("name='")[1].split("'")[0]
    raise ToolUnavailableError("Could not determine package name from APK (aapt output unrecognized)")


def _resign_apk(apk_path: str) -> str:
    if not os.path.exists(KEYSTORE_PATH):
        raise ToolUnavailableError(f"Debug keystore not found at {KEYSTORE_PATH}")

    signed_path = f"/tmp/shieldnetx_signed_{os.path.basename(apk_path)}"
    result = _run(
        [
            "apksigner", "sign",
            "--ks", KEYSTORE_PATH,
            "--ks-pass", f"pass:{KEYSTORE_PASS}",
            "--key-pass", f"pass:{KEYSTORE_PASS}",
            "--out", signed_path,
            apk_path,
        ],
        timeout=60,
        label="apksigner",
    )
    if result.returncode != 0:
        raise ToolUnavailableError(f"apksigner failed: {result.stderr[-500:]}")
    return signed_path


def device_available() -> bool:
    try:
        out, _, _ = _adb(["devices"])
    except ToolUnavailableError:
        return False
    lines = [l for l in out.splitlines()[1:] if l.strip()]
    return any("\tdevice" in l for l in lines)


def _disable_package_verifier():
    for args in (
        ["shell", "settings", "put", "global", "verifier_verify_adb_installs", "0"],
        ["shell", "settings", "put", "global", "package_verifier_enable", "0"],
        ["shell", "settings", "put", "global", "package_verifier_user_consent", "-1"],
    ):
        try:
            _adb(args)
        except ToolUnavailableError as e:
            logger.warning("Package verifier setting failed (continuing): %s", e)


def _unavailable(reason: str) -> dict:
    logger.info("Dynamic analysis unavailable: %s", reason)
    return {"available": False, "reason": reason, "events": []}


def run_dynamic_analysis(apk_path: str) -> dict:
    tool_check = check_required_tools()
    if tool_check:
        return _unavailable(tool_check)

    if not device_available():
        return _unavailable(
            "No authorized Android device connected — dynamic analysis skipped, "
            "static + GenAI findings only"
        )

    events = []
    package_name = None
    signed_path = None

    try:
        package_name = _get_package_name(apk_path)
        _disable_package_verifier()
        signed_path = _resign_apk(apk_path)

        install_out, install_err, rc = _adb(["install", "-r", signed_path], timeout=60)
        if rc != 0:
            return _unavailable(f"Install failed: {install_err}")

        _adb(["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"])
        time.sleep(3)

        pidof_out, _, _ = _adb(["shell", "pidof", package_name])
        if not pidof_out.strip():
            return _unavailable(
                f"App did not launch — no PID found for {package_name} after monkey launch"
            )
        target_pid = int(pidof_out.strip().split()[0])

        try:
            import frida
        except ImportError:
            return _unavailable("Python 'frida' package not installed — instrumentation unavailable")

        try:
            device = frida.get_usb_device(timeout=10)
            session = device.attach(target_pid)
        except Exception as e:
            return _unavailable(f"Frida could not attach to target process: {e}")

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

    except ToolUnavailableError as e:
        return _unavailable(str(e))
    except Exception as e:
        logger.exception("Unexpected error during dynamic analysis")
        return _unavailable(f"Dynamic analysis error: {e}")
    finally:
        if package_name:
            try:
                _adb(["uninstall", package_name])
            except ToolUnavailableError as e:
                logger.warning("Cleanup uninstall failed (continuing): %s", e)
        if signed_path and os.path.exists(signed_path):
            try:
                os.remove(signed_path)
            except OSError as e:
                logger.warning("Cleanup of signed APK copy failed: %s", e)

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
