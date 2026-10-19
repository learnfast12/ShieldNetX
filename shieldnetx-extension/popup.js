const API = 'http://localhost:8000';
const SEV = { CRITICAL: "#ff3b5c", HIGH: "#ff8a1f", MEDIUM: "#ffd23f", LOW: "#3aa7ff", SAFE: "#2dffa8" };
const RING_R = 34;
const RING_C = 2 * Math.PI * RING_R;
let currentURL = '';

const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Backend returns signals as an object; blocked-page fallback passes nothing.
function normalizeSignals(signals) {
  if (!signals) return [];
  if (Array.isArray(signals)) {
    return signals.map(t => ({ name: 'SIGNAL', text: String(t), score: '', hot: true }));
  }
  const rows = [];
  const add = (name, text, score, hot) => rows.push({ name, text, score, hot });

  const ai = signals.ai_analysis;
  if (ai) {
    const flags = (ai.flags || []).join(' · ');
    add('AI HEURISTICS', flags || 'No threat patterns found', `+${ai.ai_score || 0}`, (ai.ai_score || 0) > 0);
  }
  const vt = signals.virustotal;
  if (vt) {
    const n = vt.malicious_engines || 0;
    add('VIRUSTOTAL', vt.verdict || 'UNKNOWN', n ? `${n} eng` : '0 eng', n > 0);
  }
  const sb = signals.sandbox;
  if (sb) add('GHOST SANDBOX', sb.verdict || 'Clean', `+${sb.score || 0}`, (sb.score || 0) > 0);
  const cv = signals.click_velocity;
  if (cv) add('CLICK VELOCITY', cv.verdict || 'Normal', `+${cv.score || 0}`, (cv.score || 0) > 0);
  const gv = signals.geo_velocity;
  if (gv) add('GEO SPREAD', gv.verdict || 'Normal', `+${gv.score || 0}`, (gv.score || 0) > 0);
  const dw = signals.dwell_time;
  if (dw) add('DWELL TIME', dw.verdict || 'Normal', `+${dw.score || 0}`, (dw.score || 0) > 0);
  const us = signals.unknown_sender;
  if (us && us.triggered) add('SENDER', us.verdict || 'Unknown sender', `+${us.score || 0}`, true);
  return rows;
}

function show(score, level, url, signals) {
  const sev = SEV[level] || SEV.SAFE;
  const n = Math.max(0, Math.min(100, Number(score) || 0));
  const rows = normalizeSignals(signals);

  const signalsHTML = rows.length
    ? rows.map(r => `
        <div class="signal-item${r.hot ? ' hot' : ''}">
          <div class="sig-name">${esc(r.name)}</div>
          <div class="sig-text" title="${esc(r.text)}">${esc(r.text)}</div>
          <div class="sig-score">${esc(r.score)}</div>
        </div>`).join('')
    : '<div class="signal-item"><div class="sig-name">INFO</div><div class="sig-text">Run a scan for the full signal breakdown</div><div class="sig-score"></div></div>';

  const box = $('scanContent');
  box.style.setProperty('--sev', sev);
  box.innerHTML = `
    <div class="score-row">
      <div class="gauge">
        <svg viewBox="0 0 80 80">
          <circle class="track" cx="40" cy="40" r="${RING_R}"></circle>
          <circle class="fg" id="gaugeFg" cx="40" cy="40" r="${RING_R}"
            stroke-dasharray="${RING_C}" stroke-dashoffset="${RING_C}"></circle>
        </svg>
        <div class="score-big">${n}</div>
      </div>
      <div class="score-meta">
        <div class="level">${esc(level || 'UNKNOWN')}</div>
        <div class="score-cap">THREAT SCORE / 100</div>
      </div>
    </div>
    <div class="url-text" title="${esc(url)}">${esc(url || '')}</div>
    <div class="signals">${signalsHTML}</div>
  `;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    const fg = $('gaugeFg');
    if (fg) fg.style.strokeDashoffset = RING_C * (1 - n / 100);
  }));
  $('sandboxBtn').disabled = false;
}

async function analyzeURL() {
  const url = $('urlInput').value.trim();
  if (!url) return;
  currentURL = url;

  $('analyzeBtn').disabled = true;
  $('sandboxBtn').disabled = true;
  $('scanContent').innerHTML = '<div class="loading">SCANNING TARGET<div class="bar"></div></div>';

  try {
    const res = await fetch(`${API}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (!res.ok) {
      $('scanContent').innerHTML = `<div class="no-scan" style="color:#ff3b5c">Scan error: ${esc(res.status)} ${esc(res.statusText)}</div>`;
    } else {
      const data = await res.json();
      show(data.threat_score, data.threat_level, url, data.signals);
    }
  } catch (e) {
    $('scanContent').innerHTML = '<div class="no-scan" style="color:#ff3b5c">Backend not reachable.<br>Is the sentinel backend running on port 8000?</div>';
  }
  $('analyzeBtn').disabled = false;
}

function openSandbox() {
  if (!currentURL) return;
  const sandboxURL = `http://localhost:5500/index.html?url=${encodeURIComponent(currentURL)}`;
  chrome.tabs.create({ url: sandboxURL });
}

function setBadge(state, text) {
  const badge = $('statusBadge');
  badge.dataset.state = state;
  badge.textContent = text;
}

function updateBadge(protectionEnabled) {
  if (protectionEnabled === false) { setBadge('offline', 'OFFLINE'); return; }
  setBadge('checking', 'CHECKING');
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 4000);
  fetch(`${API}/health`, { signal: ctl.signal })
    .then((r) => { if (!r.ok) throw new Error('bad status'); setBadge('active', 'ACTIVE'); })
    .catch(() => setBadge('down', 'BACKEND DOWN'))
    .finally(() => clearTimeout(timer));
}

document.addEventListener('DOMContentLoaded', () => {
  chrome.storage.local.get(["protectionEnabled"], (data) => {
    updateBadge(data.protectionEnabled !== false);
  });

  $('analyzeBtn').addEventListener('click', analyzeURL);
  $('sandboxBtn').addEventListener('click', openSandbox);

  const toggle = $('protectionToggle');
  chrome.storage.local.get(["protectionEnabled"], (data) => {
    toggle.checked = data.protectionEnabled !== false;
  });
  toggle.addEventListener('change', () => {
    chrome.storage.local.set({ protectionEnabled: toggle.checked });
    updateBadge(toggle.checked);

    // If protection just got turned OFF, un-block any currently blocked tabs
    if (!toggle.checked) {
      chrome.tabs.query({}, (tabs) => {
        tabs.forEach((tab) => {
          if (tab.url && tab.url.includes('blocked.html')) {
            const params = new URL(tab.url).searchParams;
            const originalUrl = decodeURIComponent(params.get('url') || '');
            if (originalUrl) {
              chrome.tabs.update(tab.id, { url: originalUrl });
            }
          }
        });
      });
    }
  });
  $('urlInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') analyzeURL();
  });

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
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
