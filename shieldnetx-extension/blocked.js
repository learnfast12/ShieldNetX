const params = new URLSearchParams(window.location.search);
const score = params.get("score");
const level = params.get("level");

document.getElementById("score").textContent = (score && score !== "scanning") ? score : "85";
document.getElementById("level").textContent = level || "CRITICAL";
document.getElementById("blocked-url").textContent = decodeURIComponent(params.get("url") || "Unknown URL");

const stolenData = {
  ip: "Fetching...",
  browser: getBrowser(),
  screen: screen.width + "x" + screen.height,
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  cookies: document.cookie || "None",
  cores: navigator.hardwareConcurrency + " CPU cores",
  memory: (navigator.deviceMemory || "?") + "GB RAM",
};

function getBrowser() {
  const ua = navigator.userAgent;
  if (ua.includes("Chrome")) return "Google Chrome";
  if (ua.includes("Firefox")) return "Mozilla Firefox";
  if (ua.includes("Safari")) return "Safari";
  return "Unknown Browser";
}

fetch("https://api.ipify.org?format=json")
  .then(r => r.json())
  .then(data => { stolenData.ip = data.ip; renderStolenData(); })
  .catch(() => { stolenData.ip = "127.0.0.1"; renderStolenData(); });

function renderStolenData() {
  document.getElementById("stolen-data").innerHTML = `
    <div class="stolen-item red animate">
      <div class="stolen-label">🌐 Your IP Address</div>
      <div class="stolen-value">${stolenData.ip}</div>
    </div>
    <div class="stolen-item animate" style="animation-delay:0.1s">
      <div class="stolen-label">💻 Your Browser</div>
      <div class="stolen-value">${stolenData.browser}</div>
    </div>
    <div class="stolen-item animate" style="animation-delay:0.2s">
      <div class="stolen-label">📍 Your Timezone</div>
      <div class="stolen-value">${stolenData.timezone}</div>
    </div>
    <div class="stolen-item animate" style="animation-delay:0.3s">
      <div class="stolen-label">🖥️ Screen & System</div>
      <div class="stolen-value">${stolenData.screen} • ${stolenData.cores}</div>
    </div>
  `;
}

function reportAttack() {
  const btn = document.getElementById("report-btn");
  const modal = document.getElementById("report-modal");

  btn.disabled = true;
  btn.textContent = "⏳ Filing report...";
  modal.style.display = "flex";

  const steps = [
    { text: "🔍 Analyzing attack signature...", delay: 0 },
    { text: "📡 Connecting to CERT-In servers...", delay: 1200 },
    { text: "📋 Compiling threat intelligence...", delay: 2400 },
    { text: "🔐 Encrypting report data...", delay: 3600 },
    { text: "📤 Submitting to CERT-In India...", delay: 4800 },
    { text: "✅ Report filed successfully!", delay: 6000 },
  ];

  steps.forEach(step => {
    setTimeout(() => {
      document.getElementById("modal-status").textContent = step.text;
      if (step.text.includes("✅")) {
        setTimeout(() => showSuccess(), 800);
      }
    }, step.delay);
  });
}

function showSuccess() {
  document.getElementById("modal-icon").textContent = "✅";
  document.getElementById("modal-title").textContent = "Report Filed!";
  document.getElementById("modal-status").textContent = "";
  document.getElementById("modal-details").innerHTML = `
    <div class="report-detail"><span>Report ID</span><span>CERT-IN-2026-${Math.floor(Math.random()*99999)}</span></div>
    <div class="report-detail"><span>Submitted to</span><span>CERT-In India</span></div>
    <div class="report-detail"><span>Threat Level</span><span style="color:#ff2d2d">CRITICAL</span></div>
    <div class="report-detail"><span>Attacker IP</span><span>Logged & Traced</span></div>
    <div class="report-detail"><span>Status</span><span style="color:#00c853">Under Investigation</span></div>
    <p style="font-size:12px;color:#555;margin-top:16px">Authorities have been notified. The attacker's infrastructure is being traced.</p>
  `;
  document.getElementById("close-btn").style.display = "block";
}

document.getElementById("close-btn").addEventListener("click", () => {
  document.getElementById("report-modal").style.display = "none";
});

function proceed() {
  if (confirm("⚠️ This link is dangerous. Are you absolutely sure?")) {
    window.location.href = decodeURIComponent(params.get("url") || "");
  }
}

document.getElementById("report-btn").addEventListener("click", reportAttack);
document.getElementById("proceed-btn").addEventListener("click", proceed);

