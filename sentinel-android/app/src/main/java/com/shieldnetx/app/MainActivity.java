package com.shieldnetx.app;

import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.view.accessibility.AccessibilityManager;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button btnEnable = findViewById(R.id.btn_enable);
        TextView tvStatus = findViewById(R.id.tv_status);

        btnEnable.setOnClickListener(v -> {
            Intent intent = new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
            startActivity(intent);
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        TextView tvStatus = findViewById(R.id.tv_status);
        Button btnEnable = findViewById(R.id.btn_enable);
        if (isAccessibilityEnabled()) {
            tvStatus.setText("🛡️ ShieldNetX is ACTIVE\nProtecting all your links");
            tvStatus.setTextColor(0xFF00C853);
            btnEnable.setText("✓ Protection Active");
            btnEnable.setEnabled(false);
        } else {
            tvStatus.setText("⚠️ Enable Accessibility\nto activate protection");
            tvStatus.setTextColor(0xFFFF5252);
            btnEnable.setText("Enable Protection");
            btnEnable.setEnabled(true);
        }
    }

    private boolean isAccessibilityEnabled() {
        AccessibilityManager am = (AccessibilityManager) getSystemService(ACCESSIBILITY_SERVICE);
        return am != null && am.isEnabled();
    }
}
