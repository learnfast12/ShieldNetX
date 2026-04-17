const API = "http://localhost:8001";
const BLOCKED_URLS = ["localhost:9000"];

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("about:")) return;
  if (url.includes("localhost:3000") || url.includes("localhost:8001") || url.includes("localhost:7000")) return;

  const isKnownThreat = BLOCKED_URLS.some(u => url.includes(u));
  
  if (isKnownThreat) {
    chrome.storage.local.set({ 
      score: 91,
      level: "CRITICAL",
      lastUrl: url
    });
    const blockedUrl = chrome.runtime.getURL(`blocked.html?score=91&level=CRITICAL&url=${encodeURIComponent(url)}`);
    chrome.tabs.update(details.tabId, { url: blockedUrl });
    return;
  }

  try {
    const response = await fetch(`${API}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url, message: "" })
    });
    const result = await response.json();
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
    console.log("ShieldNetX error:", e);
  }
});
