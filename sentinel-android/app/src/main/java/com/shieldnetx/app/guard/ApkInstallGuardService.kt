package com.shieldnetx.app.guard

/*
 * ApkInstallGuardService
 * ------------------------------------------------------------
 * Purpose: Detect when Android's system Package Installer UI is
 * about to be shown to the user (i.e. they tapped an APK file to
 * install it — from WhatsApp, email, file manager, Bluetooth, etc.)
 * and intercept BEFORE the user can tap "Install."
 *
 * How it works:
 *  1. AccessibilityService listens for window state changes.
 *  2. When the foreground package matches Android's package
 *     installer ("com.google.android.packageinstaller" or
 *     "com.android.packageinstaller"), we know an install prompt
 *     is on screen.
 *  3. We immediately press "back" / dismiss to stop the user from
 *     proceeding, and launch our own ScanGateActivity instead.
 *  4. ScanGateActivity resolves the actual APK file URI (from the
 *     Intent that triggered the installer — captured via a second,
 *     lighter mechanism, see NOTE below) and uploads it to the
 *     backend /api/analyze endpoint.
 *  5. Based on the verdict, ScanGateActivity either lets the user
 *     proceed to the real installer, or blocks with a warning.
 *
 * IMPORTANT / KNOWN LIMITATION:
 * AccessibilityService can detect that the installer UI opened,
 * but it does NOT give you the APK's file URI directly — that
 * lives in the Intent that launched the installer, which this
 * service does not have direct access to. Two practical options:
 *
 *   (A) RECOMMENDED FOR YOUR TIMELINE: Register this app as a
 *       handler for APK mime type intents
 *       (application/vnd.android.package-archive) via an
 *       <intent-filter> in the manifest. This lets Android offer
 *       YOUR app as a chooser option alongside "Package Installer"
 *       whenever a user taps an APK anywhere (file manager,
 *       WhatsApp, email). This is far more reliable than
 *       Accessibility-based interception, doesn't require
 *       accessibility permissions, and directly gives you the
 *       APK's Uri in the Intent. The tradeoff: it relies on the
 *       user picking your app in the "Open with" chooser rather
 *       than being fully silent/automatic — but you can set your
 *       app as the DEFAULT handler after first use, so it becomes
 *       automatic after that.
 *
 *   (B) Full silent interception system-wide with zero user
 *       interaction requires Device Owner / Device Admin
 *       privileges (MDM-style enrollment) — this is realistic for
 *       enterprise-managed banking-provided phones, not a
 *       hackathon demo on your personal device, and not something
 *       to attempt this close to a deadline.
 *
 * This file implements the Accessibility-based detection AND
 * dismissal (useful as a defense-in-depth layer even under
 * approach A), but you should pair it with the manifest
 * intent-filter approach in ApkOpenInterceptorActivity.kt
 * (see companion file) to reliably get the actual file URI.
 */

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Intent
import android.util.Log
import android.view.accessibility.AccessibilityEvent

class ApkInstallGuardService : AccessibilityService() {

    companion object {
        private const val TAG = "ApkInstallGuard"

        // Known package installer package names across Android versions/OEMs.
        // OnePlus/OxygenOS and other OEM skins may use additional custom
        // installer packages — add any you discover during testing.
        private val INSTALLER_PACKAGES = setOf(
            "com.google.android.packageinstaller",
            "com.android.packageinstaller",
            "com.miui.packageinstaller",       // MIUI
            "com.oneplus.packageinstaller"      // some OnePlus builds (verify on your device)
        )
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        val info = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            notificationTimeout = 100
        }
        serviceInfo = info
        Log.i(TAG, "ApkInstallGuardService connected and listening")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        val pkg = event?.packageName?.toString() ?: return

        if (pkg in INSTALLER_PACKAGES) {
            Log.w(TAG, "Package installer UI detected ($pkg) — intercepting")

            // Step 1: block the user from proceeding by simulating BACK.
            // This is a blunt instrument — it dismisses the installer
            // screen immediately. Good enough to prevent an accidental
            // tap on "Install" while ScanGateActivity spins up.
            performGlobalAction(GLOBAL_ACTION_BACK)

            // Step 2: launch our own gate screen.
            // NOTE: this does NOT have the APK's file URI (see class
            // doc above) — ScanGateActivity here would only be able to
            // show a generic "an app install was blocked, use ShieldNetX
            // to scan it" message unless launched via the intent-filter
            // path (Approach A) which carries the real file Uri.
            val gateIntent = Intent(this, com.shieldnetx.app.guard.ApkOpenInterceptorActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra("source", "accessibility_intercept")
            }
            startActivity(gateIntent)
        }
    }

    override fun onInterrupt() {
        Log.w(TAG, "ApkInstallGuardService interrupted")
    }
}
