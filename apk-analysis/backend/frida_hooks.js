Java.perform(function () {
    // --- SMS interception (OTP theft) ---
    try {
        const ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.query.overload(
            "android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String"
        ).implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
            const uriStr = uri.toString();
            if (uriStr.indexOf("sms") !== -1 || uriStr.indexOf("mms") !== -1) {
                send({type: "sms_access", api: "ContentResolver.query", uri: uriStr});
            }
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
    } catch (e) { send({type: "hook_error", target: "ContentResolver.query", error: e.toString()}); }

    try {
        const SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.lang.String", "android.app.PendingIntent", "android.app.PendingIntent"
        ).implementation = function (destAddr, scAddr, text, sentIntent, deliveryIntent) {
            send({type: "sms_access", api: "SmsManager.sendTextMessage", destination: destAddr});
            return this.sendTextMessage(destAddr, scAddr, text, sentIntent, deliveryIntent);
        };
    } catch (e) { send({type: "hook_error", target: "SmsManager.sendTextMessage", error: e.toString()}); }

    // --- Network exfiltration ---
    try {
        const URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            send({type: "network_call", api: "URL.openConnection", url: this.toString()});
            return this.openConnection();
        };
    } catch (e) { send({type: "hook_error", target: "URL.openConnection", error: e.toString()}); }

    try {
        const OkHttpClient = Java.use("okhttp3.OkHttpClient");
        OkHttpClient.newCall.implementation = function (request) {
            try {
                send({type: "network_call", api: "OkHttp.newCall", url: request.url().toString()});
            } catch (e) {}
            return this.newCall(request);
        };
    } catch (e) { /* app may not use OkHttp - not an error */ }

    // --- Overlay / keylogger attack (banking credential theft UI) ---
    try {
        const WindowManagerImpl = Java.use("android.view.WindowManagerImpl");
        WindowManagerImpl.addView.implementation = function (view, params) {
            try {
                const type = params.type.value;
                // TYPE_APPLICATION_OVERLAY = 2038, TYPE_SYSTEM_ALERT_WINDOW = 2003
                if (type === 2038 || type === 2003) {
                    send({type: "overlay_attempt", api: "WindowManager.addView", window_type: type});
                }
            } catch (e) {}
            return this.addView(view, params);
        };
    } catch (e) { send({type: "hook_error", target: "WindowManager.addView", error: e.toString()}); }
});
