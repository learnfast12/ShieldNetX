package com.shieldnetx.app;

import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class BlockedActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_blocked);

        int score = getIntent().getIntExtra("score", 0);
        String level = getIntent().getStringExtra("level");
        String url = getIntent().getStringExtra("url");

        TextView tvScore = findViewById(R.id.tv_score);
        TextView tvLevel = findViewById(R.id.tv_level);
        TextView tvUrl = findViewById(R.id.tv_url);
        Button btnSafe = findViewById(R.id.btn_safe);

        tvScore.setText(String.valueOf(score));
        tvLevel.setText(level != null ? level : "CRITICAL");
        tvUrl.setText(url != null ? url : "Unknown URL");

        btnSafe.setOnClickListener(v -> finish());
    }
}
