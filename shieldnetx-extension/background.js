const API = "http://localhost:8000";
const SANDBOX_API = "http://localhost:8001";

const WHITELIST = [
  "localhost:3000", "localhost:9001", "localhost:7000",
  "localhost:5500", "localhost:8001", "localhost:8000",
  "chrome://", "chrome-extension://", "about:"
];

const INSTANT_BLOCK = [
  "localhost:8080",
  "testsafebrowsing.appspot.com",
  "phishing", "malware"
];

// Cache to avoid scanning same URL twice
const scanCache = {};

// Default protection state on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["protectionEnabled"], (data) => {
    if (data.protectionEnabled === undefined) {
      chrome.storage.local.set({ protectionEnabled: true });
    }
  });
});

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;

  // Protection toggle check — bail out entirely if disabled
  const { protectionEnabled } = await chrome.storage.local.get(["protectionEnabled"]);
  if (protectionEnabled === false) return;
  const url = details.url;

  // Whitelist check
  if (WHITELIST.some(w => url.includes(w))) return;
  if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("about:")) return;

  // Instant block known threats — no API call needed
  const isInstantThreat = INSTANT_BLOCK.some(u => url.includes(u));
  if (isInstantThreat) {
    chrome.storage.local.set({ score: 95, level: "CRITICAL", lastUrl: url });
    const blockedUrl = chrome.runtime.getURL(`blocked.html?score=95&level=CRITICAL&url=${encodeURIComponent(url)}`);
    chrome.tabs.update(details.tabId, { url: blockedUrl });
    return;
  }

  // Check cache
  if (scanCache[url]) {
    const cached = scanCache[url];
    if (cached.threat_score >= 50) {
      const blockedUrl = chrome.runtime.getURL(`blocked.html?score=${cached.threat_score}&level=${cached.threat_level}&url=${encodeURIComponent(url)}`);
      chrome.tabs.update(details.tabId, { url: blockedUrl });
    }
    return;
  }

  // API scan
  try {
    const response = await fetch(`${API}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url, message: "" })
    });
    const result = await response.json();

    // Cache result
    scanCache[url] = result;

    chrome.storage.local.set({
      score: result.threat_score,
      level: result.threat_level,
      lastUrl: url
    });

    if (result.threat_score >= 50) {
      const blockedUrl = chrome.runtime.getURL(`blocked.html?score=${result.threat_score}&level=${result.threat_level}&url=${encodeURIComponent(url)}`);
      chrome.tabs.update(details.tabId, { url: blockedUrl });
    }
  } catch(e) {
    console.log("ShieldNetX scan error:", e);
  }
});

// ===== APK Download Interception =====
const APK_BACKEND = "http://localhost:8010";
const apkPollCache = {};

chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  if (!item.filename.toLowerCase().endsWith(".apk")) {
    suggest();
    return;
  }
  console.log("[ShieldNetX] APK download detected:", item.filename, item.url);
  // Let it save to disk first (we need bytes on disk to read + delete if needed)
  suggest();
});

chrome.downloads.onChanged.addListener(async (delta) => {
  if (delta.state && delta.state.current === "complete") {
    chrome.downloads.search({ id: delta.id }, async (items) => {
      const item = items[0];
      if (!item || !item.filename.toLowerCase().endsWith(".apk")) return;

      console.log("[ShieldNetX] APK finished downloading, scanning:", item.filename);
      await scanDownloadedApk(item);
    });
  }
});

async function scanDownloadedApk(item) {
  try {
    // Fetch the file bytes back via the file:// URL isn't accessible from extension;
    // instead re-fetch from the original source URL to get bytes for upload.
    const fileResp = await fetch(item.finalUrl || item.url);
    const blob = await fileResp.blob();

    const formData = new FormData();
    formData.append("file", blob, item.filename.split(/[\\/]/).pop());

    const uploadResp = await fetch(`${APK_BACKEND}/api/analyze`, {
      method: "POST",
      body: formData
    });
    if (!uploadResp.ok) {
      console.error("[ShieldNetX] APK upload failed:", uploadResp.status);
      return;
    }
    const { job_id } = await uploadResp.json();
    console.log("[ShieldNetX] APK scan job started:", job_id);

    pollApkJob(job_id, item.id, item.filename);
  } catch (e) {
    console.error("[ShieldNetX] APK scan error:", e);
  }
}

async function pollApkJob(jobId, downloadId, filename, attempt = 0) {
  if (attempt > 60) {
    console.error("[ShieldNetX] APK scan timed out for", filename);
    return;
  }
  try {
    const statusResp = await fetch(`${APK_BACKEND}/api/status/${jobId}`);
    const status = await statusResp.json();

    if (status.stage === "complete") {
      const reportResp = await fetch(`${APK_BACKEND}/api/report/${jobId}`);
      const report = await reportResp.json();
      const severity = report?.risk?.severity || "UNKNOWN";
      console.log("[ShieldNetX] APK verdict:", severity, filename);

      if (severity === "CRITICAL" || severity === "HIGH") {
        chrome.downloads.removeFile(downloadId, () => {
          chrome.downloads.erase({ id: downloadId });
          console.warn("[ShieldNetX] Malicious APK deleted:", filename, severity);
          chrome.notifications?.create({
            type: "basic",
            iconUrl: "icons/icon128.png",
            title: "ShieldNetX — APK Blocked",
            message: `${filename} was flagged ${severity} and deleted.`
          });
        });
      }
      return;
    }
    if (status.stage === "error") {
      console.error("[ShieldNetX] APK scan error:", status.error);
      return;
    }
    setTimeout(() => pollApkJob(jobId, downloadId, filename, attempt + 1), 2000);
  } catch (e) {
    console.error("[ShieldNetX] Poll error:", e);
  }
}
