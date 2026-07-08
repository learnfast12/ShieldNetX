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

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
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
