package com.shieldnetx.app;

import android.accessibilityservice.AccessibilityService;
import android.content.Intent;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import java.util.List;
import okhttp3.*;
import org.json.JSONObject;
import java.io.IOException;

public class ShieldNetXService extends AccessibilityService {
    private static final String API = "http://10.0.2.2:8001";
    private static final OkHttpClient client = new OkHttpClient();
    private String lastScannedUrl = "";

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event.getEventType() == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED ||
            event.getEventType() == AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED) {

            AccessibilityNodeInfo root = getRootInActiveWindow();
            if (root == null) return;

            // Find URL bar content
            List<AccessibilityNodeInfo> nodes = root.findAccessibilityNodeInfosByViewId("com.android.chrome:id/url_bar");
            if (nodes == null || nodes.isEmpty()) {
                nodes = root.findAccessibilityNodeInfosByViewId("org.chromium.chrome:id/url_bar");
            }

            if (nodes != null && !nodes.isEmpty()) {
                AccessibilityNodeInfo urlNode = nodes.get(0);
                if (urlNode.getText() != null) {
                    String url = urlNode.getText().toString();
                    if (!url.equals(lastScannedUrl) && url.startsWith("http")) {
                        lastScannedUrl = url;
                        scanUrl(url);
                    }
                }
            }
        }
    }

    private void scanUrl(String url) {
        new Thread(() -> {
            try {
                JSONObject body = new JSONObject();
                body.put("url", url);
                body.put("message", "");

                RequestBody requestBody = RequestBody.create(
                    body.toString(),
                    MediaType.parse("application/json")
                );

                Request request = new Request.Builder()
                    .url(API + "/scan")
                    .post(requestBody)
                    .build();

                client.newCall(request).enqueue(new Callback() {
                    @Override
                    public void onFailure(Call call, IOException e) {}

                    @Override
                    public void onResponse(Call call, Response response) throws IOException {
                        try {
                            String responseBody = response.body().string();
                            JSONObject result = new JSONObject(responseBody);
                            int score = result.getInt("threat_score");
                            String level = result.getString("threat_level");

                            if (score >= 70) {
                                Intent intent = new Intent(ShieldNetXService.this, BlockedActivity.class);
                                intent.putExtra("score", score);
                                intent.putExtra("level", level);
                                intent.putExtra("url", url);
                                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                                startActivity(intent);
                            }
                        } catch (Exception e) {}
                    }
                });
            } catch (Exception e) {}
        }).start();
    }

    @Override
    public void onInterrupt() {}
}
