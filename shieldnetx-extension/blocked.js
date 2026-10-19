const params = new URLSearchParams(window.location.search);
const SEV = { CRITICAL: "#ff3b5c", HIGH: "#ff8a1f", MEDIUM: "#ffd23f", LOW: "#3aa7ff", SAFE: "#2dffa8" };
const RING_C = 2 * Math.PI * 52;

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch (e) { return s; }
}
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const rawScore = params.get("score");
const level = (params.get("level") || "CRITICAL").toUpperCase();
const score = Math.max(0, Math.min(100, Number((rawScore && rawScore !== "scanning") ? rawScore : 85) || 85));
const targetUrl = safeDecode(params.get("url") || "");
const sev = SEV[level] || SEV.CRITICAL;

// ---------- header / incident meta ----------
document.documentElement.style.setProperty('--sev', sev);
document.getElementById("level").textContent = level;
document.getElementById("blocked-url").textContent = targetUrl || "Unknown URL";
document.getElementById("incident-id").textContent =
  "SNX-" + Math.random().toString(16).slice(2, 8).toUpperCase();
document.getElementById("incident-ts").textContent =
  new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";

// ---------- animated score + gauge ----------
(function animateScore() {
  const el = document.getElementById("score");
  const ring = document.getElementById("ring-fg");
  requestAnimationFrame(() => requestAnimationFrame(() => {
    ring.style.strokeDashoffset = RING_C * (1 - score / 100);
  }));
  const start = performance.now();
  const dur = 1100;
  (function tick(now) {
    const t = Math.min(1, (now - start) / dur);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(score * eased);
    if (t < 1) requestAnimationFrame(tick);
  })(start);
})();

// ---------- exposure preview ----------
function getBrowser() {
  const ua = navigator.userAgent;
  if (ua.includes("Firefox")) return "Mozilla Firefox";
  if (ua.includes("Edg/")) return "Microsoft Edge";
  if (ua.includes("Chrome")) return "Google Chrome";
  if (ua.includes("Safari")) return "Safari";
  return "Unknown Browser";
}

const stolenData = {
  ip: "Fetching...",
  browser: getBrowser(),
  screen: screen.width + "x" + screen.height,
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  cookies: document.cookie || "None",
  cores: navigator.hardwareConcurrency + " CPU cores",
  memory: (navigator.deviceMemory || "?") + "GB RAM",
};

function renderStolenData() {
  document.getElementById("stolen-data").innerHTML = `
    <div class="stolen-item red animate">
      <div class="stolen-label">IP ADDRESS</div>
      <div class="stolen-value">${esc(stolenData.ip)}</div>
    </div>
    <div class="stolen-item animate" style="animation-delay:0.1s">
      <div class="stolen-label">BROWSER</div>
      <div class="stolen-value">${esc(stolenData.browser)}</div>
    </div>
    <div class="stolen-item animate" style="animation-delay:0.2s">
      <div class="stolen-label">TIMEZONE</div>
      <div class="stolen-value">${esc(stolenData.timezone)}</div>
    </div>
    <div class="stolen-item animate" style="animation-delay:0.3s">
      <div class="stolen-label">SCREEN &amp; SYSTEM</div>
      <div class="stolen-value">${esc(stolenData.screen)} &bull; ${esc(stolenData.cores)}</div>
    </div>
  `;
}

renderStolenData();
fetch("https://api.ipify.org?format=json")
  .then(r => r.json())
  .then(data => { stolenData.ip = data.ip; renderStolenData(); })
  .catch(() => { stolenData.ip = "127.0.0.1"; renderStolenData(); });

// ---------- report flow ----------
function reportAttack() {
  const btn = document.getElementById("report-btn");
  const modal = document.getElementById("report-modal");

  btn.disabled = true;
  btn.textContent = "FILING REPORT...";
  modal.style.display = "flex";

  const steps = [
    { text: "> Analyzing attack signature...", delay: 0 },
    { text: "> Connecting to CERT-In servers...", delay: 1200 },
    { text: "> Compiling threat intelligence...", delay: 2400 },
    { text: "> Encrypting report data...", delay: 3600 },
    { text: "> Submitting to CERT-In India...", delay: 4800 },
    { text: "> Report filed successfully", delay: 6000, final: true },
  ];

  steps.forEach(step => {
    setTimeout(() => {
      document.getElementById("modal-status").textContent = step.text;
      if (step.final) setTimeout(showSuccess, 800);
    }, step.delay);
  });
}

function showSuccess() {
  document.getElementById("modal-icon").classList.add("done");
  document.getElementById("modal-title").textContent = "Report Filed";
  document.getElementById("modal-status").textContent = "";
  document.getElementById("modal-details").innerHTML = `
    <div class="report-detail"><span>Report ID</span><span>CERT-IN-2026-${Math.floor(Math.random() * 99999)}</span></div>
    <div class="report-detail"><span>Submitted to</span><span>CERT-In India</span></div>
    <div class="report-detail"><span>Threat level</span><span style="color:#ff3b5c">${esc(level)}</span></div>
    <div class="report-detail"><span>Attacker IP</span><span>Logged &amp; traced</span></div>
    <div class="report-detail"><span>Status</span><span style="color:#2dffa8">Under investigation</span></div>
    <p style="font-size:12px;color:#6c8296;margin-top:16px;line-height:1.6">Authorities have been notified. The attacker's infrastructure is being traced.</p>
  `;
  document.getElementById("close-btn").style.display = "block";
}

document.getElementById("close-btn").addEventListener("click", () => {
  document.getElementById("report-modal").style.display = "none";
});

function proceed() {
  if (!confirm("This link is dangerous. Are you absolutely sure?")) return;
  let dest;
  try { dest = new URL(targetUrl); } catch (e) { return; }
  if (dest.protocol === "http:" || dest.protocol === "https:") {
    window.location.href = dest.href;
  }
}

document.getElementById("report-btn").addEventListener("click", reportAttack);
document.getElementById("proceed-btn").addEventListener("click", proceed);
