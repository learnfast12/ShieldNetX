const API = 'http://localhost:8002';
const colors = { CRITICAL: "#ff2d2d", HIGH: "#ff6b00", MEDIUM: "#ffd000", LOW: "#00c2ff", SAFE: "#00ff88" };
let currentURL = '';

function show(score, level, url, signals) {
  const color = colors[level] || "#00ff88";
  const signalsHTML = signals && signals.length
    ? signals.map(s => `<div class="signal-item"><div class="dot" style="background:${color}"></div>${s}</div>`).join('')
    : '<div class="signal-item">No suspicious signals detected</div>';

  document.getElementById("scanContent").innerHTML = `
    <div class="score-row">
      <div class="score-big" style="color:${color}">${score}</div>
      <div class="level" style="background:${color}22;color:${color};border:1px solid ${color}44">${level}</div>
    </div>
    <div class="url-text">${url || ""}</div>
    <div class="signals">${signalsHTML}</div>
  `;
  document.getElementById('sandboxBtn').disabled = false;
}

async function analyzeURL() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) return;
  currentURL = url;

  document.getElementById('analyzeBtn').disabled = true;
  document.getElementById('sandboxBtn').disabled = true;
  document.getElementById('scanContent').innerHTML = '<div class="loading">⟳ Scanning target...</div>';

  try {
    const res = await fetch(`${API}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    if (data.success) {
      show(data.risk.score, data.risk.level, url, data.risk.signals);
    } else {
      document.getElementById('scanContent').innerHTML = `<div class="no-scan" style="color:#ff3366">Error: ${data.error}</div>`;
    }
  } catch(e) {
    document.getElementById('scanContent').innerHTML = '<div class="no-scan" style="color:#ff3366">Backend not reachable.<br>Is sandbox running on port 8001?</div>';
  }
  document.getElementById('analyzeBtn').disabled = false;
}

function openSandbox() {
  if (!currentURL) return;
  const sandboxURL = `http://localhost:5500/index.html?url=${encodeURIComponent(currentURL)}`;
  chrome.tabs.create({ url: sandboxURL });
}

document.addEventListener('DOMContentLoaded', () => {
  // Check backend status
  const badge = document.getElementById('statusBadge');
  fetch('http://localhost:8002/docs')
    .then(() => {
      badge.textContent = '● ACTIVE';
      badge.style.color = '#00ff88';
      badge.style.borderColor = '#00ff88';
      badge.style.background = '#00ff8822';
    })
    .catch(() => {
      badge.textContent = '● OFFLINE';
      badge.style.color = '#ff3366';
      badge.style.borderColor = '#ff3366';
      badge.style.background = '#ff336622';
    });

  document.getElementById('analyzeBtn').addEventListener('click', analyzeURL);
  document.getElementById('sandboxBtn').addEventListener('click', openSandbox);
  document.getElementById('urlInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') analyzeURL();
  });

  chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
    const tab = tabs[0];
    if (tab && tab.url && tab.url.includes("blocked.html")) {
      const params = new URL(tab.url).searchParams;
      const score = params.get("score");
      const level = params.get("level");
      const url = decodeURIComponent(params.get("url") || "");
      if (score && level) { show(score, level, url, []); currentURL = url; return; }
    }
    chrome.storage.local.get(["score", "level", "lastUrl"], (data) => {
      if (data.score) { show(data.score, data.level, data.lastUrl, []); currentURL = data.lastUrl; }
    });
  });
});
