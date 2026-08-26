package com.shieldnetx.app.guard

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.Button
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.shieldnetx.app.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.asRequestBody
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream

class ApkOpenInterceptorActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "ApkOpenInterceptor"
        private const val BACKEND_BASE_URL = "http://10.59.175.87:8010"
        private const val POLL_INTERVAL_MS = 2000L
        private const val POLL_TIMEOUT_MS = 120_000L
    }

    private val client = OkHttpClient()
    private lateinit var statusText: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var proceedButton: Button
    private lateinit var blockButton: Button
    private lateinit var severityIcon: ImageView
    private lateinit var resultCard: android.widget.LinearLayout
    private lateinit var scoreText: TextView
    private lateinit var severityBadge: TextView
    private lateinit var malwareFamilyText: TextView
    private lateinit var techniquesText: TextView
    private lateinit var summaryText: TextView

    private var apkFile: File? = null
    private var pollStartTime: Long = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan_gate)

        statusText = findViewById(R.id.statusText)
        progressBar = findViewById(R.id.progressBar)
        proceedButton = findViewById(R.id.proceedButton)
        blockButton = findViewById(R.id.blockButton)
        severityIcon = findViewById(R.id.severityIcon)
        resultCard = findViewById(R.id.resultCard)
        scoreText = findViewById(R.id.scoreText)
        severityBadge = findViewById(R.id.severityBadge)
        malwareFamilyText = findViewById(R.id.malwareFamilyText)
        techniquesText = findViewById(R.id.techniquesText)
        summaryText = findViewById(R.id.summaryText)

        proceedButton.isEnabled = false
        blockButton.isEnabled = false

        val incomingUri: Uri? = intent?.data
        if (incomingUri == null) {
            statusText.text = "No file received — closing."
            finish()
            return
        }

        statusText.text = "Copying file for scan..."
        CoroutineScope(Dispatchers.IO).launch {
            val localFile = copyUriToCache(incomingUri)
            withContext(Dispatchers.Main) {
                if (localFile == null) {
                    statusText.text = "Could not read APK file. Blocking by default."
                    blockButton.isEnabled = true
                } else {
                    apkFile = localFile
                    statusText.text = "Scanning APK — please wait..."
                    uploadAndAnalyze(localFile)
                }
            }
        }

        blockButton.setOnClickListener {
            apkFile?.delete()
            statusText.text = "Blocked. File removed from scan cache."
            Handler(Looper.getMainLooper()).postDelayed({ finish() }, 1500)
        }

        proceedButton.setOnClickListener {
            apkFile?.let { launchRealInstaller(it) }
        }
    }

    private fun copyUriToCache(uri: Uri): File? {
        return try {
            val input = contentResolver.openInputStream(uri) ?: return null
            val outFile = File(cacheDir, "scan_${System.currentTimeMillis()}.apk")
            FileOutputStream(outFile).use { output ->
                input.copyTo(output)
            }
            input.close()
            outFile
        } catch (e: Exception) {
            Log.e(TAG, "Failed to copy APK from Uri", e)
            null
        }
    }

    private fun uploadAndAnalyze(file: File) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val mediaType = "application/vnd.android.package-archive".toMediaTypeOrNull()
                val body = MultipartBody.Builder()
                    .setType(MultipartBody.FORM)
                    .addFormDataPart(
                        "file", file.name,
                        file.asRequestBody(mediaType)
                    )
                    .build()

                val request = Request.Builder()
                    .url("$BACKEND_BASE_URL/api/analyze")
                    .post(body)
                    .build()

                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        withContext(Dispatchers.Main) {
                            statusText.text = "Upload failed (${response.code}). Blocking by default."
                            blockButton.isEnabled = true
                        }
                        return@launch
                    }
                    val json = JSONObject(response.body?.string() ?: "{}")
                    val jobId = json.getString("job_id")
                    Log.i(TAG, "Uploaded, job_id=$jobId")
                    pollStartTime = System.currentTimeMillis()
                    pollStatus(jobId)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Upload error", e)
                withContext(Dispatchers.Main) {
                    statusText.text = "Could not reach scan server. Blocking by default — check your network/backend URL."
                    blockButton.isEnabled = true
                }
            }
        }
    }

    private suspend fun pollStatus(jobId: String) {
        while (true) {
            if (System.currentTimeMillis() - pollStartTime > POLL_TIMEOUT_MS) {
                withContext(Dispatchers.Main) {
                    statusText.text = "Scan timed out. Blocking by default."
                    blockButton.isEnabled = true
                }
                return
            }

            try {
                val request = Request.Builder()
                    .url("$BACKEND_BASE_URL/api/status/$jobId")
                    .get()
                    .build()
                client.newCall(request).execute().use { response ->
                    val json = JSONObject(response.body?.string() ?: "{}")
                    val stage = json.optString("stage", "unknown")

                    withContext(Dispatchers.Main) {
                        statusText.text = "Scanning: $stage..."
                    }

                    when (stage) {
                        "complete" -> {
                            fetchReport(jobId)
                            return
                        }
                        "error" -> {
                            withContext(Dispatchers.Main) {
                                statusText.text = "Scan error: ${json.optString("error")}. Blocking by default."
                                blockButton.isEnabled = true
                            }
                            return
                        }
                        else -> {}
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Poll error", e)
            }

            kotlinx.coroutines.delay(POLL_INTERVAL_MS)
        }
    }

    private suspend fun fetchReport(jobId: String) {
        try {
            val request = Request.Builder()
                .url("$BACKEND_BASE_URL/api/report/$jobId")
                .get()
                .build()
            client.newCall(request).execute().use { response ->
                val json = JSONObject(response.body?.string() ?: "{}")
                val risk = json.optJSONObject("risk")
                val score = risk?.optInt("score", -1) ?: -1
                val severity = risk?.optString("severity", "UNKNOWN") ?: "UNKNOWN"

                val genai = json.optJSONObject("genai_verdict")
                val malwareFamily = genai?.optString("malware_family_hypothesis", "Unknown") ?: "Unknown"
                val summary = genai?.optString("verdict_summary", "") ?: ""
                val techniquesArray = genai?.optJSONArray("attack_techniques")
                val techniques = StringBuilder()
                if (techniquesArray != null) {
                    for (i in 0 until techniquesArray.length()) {
                        if (i > 0) techniques.append(" • ")
                        techniques.append(techniquesArray.optString(i))
                    }
                }
                val techniquesStr = if (techniques.isEmpty()) "None detected" else techniques.toString()

                withContext(Dispatchers.Main) {
                    showVerdict(score, severity, malwareFamily, techniquesStr, summary)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Report fetch error", e)
            withContext(Dispatchers.Main) {
                statusText.text = "Could not fetch scan report. Blocking by default."
                blockButton.isEnabled = true
            }
        }
    }

    private fun showVerdict(
        score: Int,
        severity: String,
        malwareFamily: String,
        techniques: String,
        summary: String
    ) {
        progressBar.visibility = android.view.View.GONE
        resultCard.visibility = android.view.View.VISIBLE

        val isDangerous = severity == "CRITICAL" || severity == "HIGH"

        val severityColorRes = when (severity) {
            "CRITICAL" -> R.color.severity_critical
            "HIGH" -> R.color.severity_high
            "MEDIUM" -> R.color.severity_medium
            else -> R.color.severity_low
        }
        val severityColor = androidx.core.content.ContextCompat.getColor(this, severityColorRes)

        severityIcon.setImageResource(
            if (isDangerous) R.drawable.ic_shield_warning else R.drawable.ic_shield_check
        )
        severityIcon.setColorFilter(severityColor)

        statusText.text = if (isDangerous) {
            "Installation Blocked"
        } else {
            "Scan Complete — No Critical Threats"
        }

        scoreText.text = score.toString()
        scoreText.setTextColor(severityColor)
        severityBadge.text = severity
        severityBadge.setBackgroundColor(severityColor)
        malwareFamilyText.text = malwareFamily
        techniquesText.text = techniques
        summaryText.text = summary

        blockButton.isEnabled = true
        proceedButton.isEnabled = !isDangerous
        proceedButton.alpha = if (isDangerous) 0.4f else 1.0f
    }

    private fun launchRealInstaller(file: File) {
        try {
            val installIntent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(
                    androidx.core.content.FileProvider.getUriForFile(
                        this@ApkOpenInterceptorActivity,
                        "$packageName.fileprovider",
                        file
                    ),
                    "application/vnd.android.package-archive"
                )
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(installIntent)
            finish()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to launch installer", e)
            statusText.text = "Could not launch installer: ${e.message}"
        }
    }
}
