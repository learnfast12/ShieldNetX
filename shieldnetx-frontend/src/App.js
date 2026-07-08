import { useState, useEffect } from "react";
import axios from "axios";

const API = "";

const STATS = [
  { value: "1,247", label: "URLs Scanned", color: "#ff8800" },
  { value: "983", label: "Threats Blocked", color: "#ff2d2d" },
  { value: "298,450", label: "Indians Protected", color: "#00c853" },
  { value: "95", label: "Engines Active", color: "#7F77DD" },
];

export default function App() {
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [recentScans, setRecentScans] = useState([]);

  useEffect(() => { fetchRecent(); }, []);

  const fetchRecent = async () => {
    try {
      const res = await axios.get(`${API}/recent-scans`);
      setRecentScans((res.data.scans || []).filter(s => s.url && s.url !== "string"));
    } catch (e) {}
  };

  const scan = async () => {
    if (!url) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await axios.post(`${API}/scan`, { url, message });
      setResult(res.data);
      fetchRecent();
    } catch (e) { alert("Backend not running!"); }
    setLoading(false);
  };

  const getColor = (score) => {
    if (score >= 75) return "#ff2d2d";
    if (score >= 50) return "#ff8800";
    if (score >= 30) return "#ffcc00";
    return "#00c853";
  };

  const signals = result?.signals ? [
    { name: "AI Analysis", score: result.signals.ai_analysis?.ai_score || 0, max: 100, icon: "🧠", desc: result.signals.ai_analysis?.explanation || "" },
    { name: "Ghost Sandbox", score: result.signals.sandbox?.score || 0, max: 25, icon: "👻", desc: result.signals.sandbox?.verdict || "" },
    { name: "Click Velocity", score: result.signals.click_velocity?.score || 0, max: 20, icon: "⚡", desc: result.signals.click_velocity?.verdict || "" },
    { name: "Geo Velocity", score: result.signals.geo_velocity?.score || 0, max: 15, icon: "🌍", desc: result.signals.geo_velocity?.verdict || "" },
    { name: "Dwell Time", score: result.signals.dwell_time?.score || 0, max: 10, icon: "⏱️", desc: result.signals.dwell_time?.verdict || "" },
  ] : [];

  return (
    <div style={{ background: "linear-gradient(135deg, #0a0a1a, #0d0d2a)", minHeight: "100vh", color: "#fff", fontFamily: "Segoe UI, sans-serif" }}>

      {/* Header */}
      <div style={{ textAlign: "center", padding: "40px 24px 20px" }}>
        <div style={{ fontSize: "52px", marginBottom: "12px" }}>🛡️</div>
        <h1 style={{ fontSize: "32px", margin: "0 0 6px", color: "#7F77DD", fontWeight: "900", letterSpacing: "2px" }}>ShieldNetX</h1>
        <p style={{ color: "#888", margin: 0, fontSize: "14px" }}>Cyber Threat Intelligence Platform</p>
      </div>

      {/* Stats */}
      <div style={{ display: "flex", justifyContent: "center", gap: "12px", padding: "0 24px 32px", flexWrap: "wrap" }}>
        {STATS.map((s, i) => (
          <div key={i} style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "12px", padding: "16px 24px", textAlign: "center", minWidth: "120px" }}>
            <div style={{ fontSize: "22px", fontWeight: "900", color: s.color }}>{s.value}</div>
            <div style={{ fontSize: "11px", color: "#666", marginTop: "4px" }}>{s.label}</div>
          </div>
        ))}
      </div>

      <div style={{ maxWidth: "800px", margin: "0 auto", padding: "0 24px 40px" }}>

        {/* Scan box */}
        <div style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(127,119,221,0.3)", borderRadius: "16px", padding: "24px", marginBottom: "24px" }}>
          <h2 style={{ margin: "0 0 16px", fontSize: "15px", color: "#aaa", display: "flex", alignItems: "center", gap: "8px" }}>🔍 Scan a Link</h2>
          <input
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="Paste URL here..."
            style={{ width: "100%", padding: "12px 16px", borderRadius: "8px", border: "1px solid rgba(127,119,221,0.3)", background: "rgba(0,0,0,0.3)", color: "#fff", fontSize: "14px", marginBottom: "12px", boxSizing: "border-box", outline: "none" }}
          />
          <textarea
            value={message}
            onChange={e => setMessage(e.target.value)}
            placeholder="Paste the full WhatsApp/SMS message here (optional but improves accuracy)..."
            rows={3}
            style={{ width: "100%", padding: "12px 16px", borderRadius: "8px", border: "1px solid rgba(127,119,221,0.3)", background: "rgba(0,0,0,0.3)", color: "#fff", fontSize: "14px", marginBottom: "16px", boxSizing: "border-box", resize: "none", outline: "none", fontFamily: "Segoe UI, sans-serif" }}
          />
          <button
            onClick={scan}
            disabled={loading}
            style={{ width: "100%", padding: "14px", borderRadius: "10px", border: "none", background: loading ? "#333" : "linear-gradient(135deg, #7F77DD, #534AB7)", color: "#fff", fontSize: "15px", fontWeight: "700", cursor: loading ? "not-allowed" : "pointer" }}>
            {loading ? "⏳ Scanning..." : "🔍 Scan Now"}
          </button>
        </div>

        {/* Results */}
        {result && (
          <div style={{ marginBottom: "24px" }}>
            <div style={{ background: "rgba(255,255,255,0.05)", border: `2px solid ${getColor(result.threat_score)}`, borderRadius: "16px", padding: "24px", marginBottom: "16px", textAlign: "center" }}>
              <div style={{ fontSize: "72px", fontWeight: "900", color: getColor(result.threat_score) }}>{result.threat_score}</div>
              <div style={{ color: "#888", marginBottom: "12px", fontSize: "13px" }}>THREAT SCORE OUT OF 100</div>
              <div style={{ display: "inline-block", background: getColor(result.threat_score), padding: "6px 24px", borderRadius: "20px", fontWeight: "800", letterSpacing: "2px", fontSize: "13px" }}>{result.threat_level}</div>
              <p style={{ color: "#ccc", marginTop: "16px", fontSize: "14px" }}>{result.explanation}</p>
              {result.tamil_explanation && <p style={{ color: "#aaa", fontSize: "13px" }}>{result.tamil_explanation}</p>}
            </div>

            <div style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(127,119,221,0.3)", borderRadius: "16px", padding: "24px", marginBottom: "16px" }}>
              <h2 style={{ margin: "0 0 16px", fontSize: "15px", color: "#aaa" }}>📊 Signal Breakdown</h2>
              {signals.map((sig, i) => (
                <div key={i} style={{ marginBottom: "16px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px", fontSize: "14px" }}>
                    <span>{sig.icon} {sig.name}</span>
                    <span style={{ color: getColor((sig.score / sig.max) * 100) }}>{sig.score}/{sig.max}</span>
                  </div>
                  <div style={{ background: "rgba(0,0,0,0.3)", borderRadius: "4px", height: "8px" }}>
                    <div style={{ width: `${Math.min((sig.score / sig.max) * 100, 100)}%`, background: getColor((sig.score / sig.max) * 100), height: "8px", borderRadius: "4px", transition: "width 0.5s" }} />
                  </div>
                  <div style={{ fontSize: "12px", color: "#666", marginTop: "4px" }}>{sig.desc}</div>
                </div>
              ))}
            </div>

            {result.screenshot_b64 && (
              <div style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(127,119,221,0.3)", borderRadius: "16px", padding: "24px", marginBottom: "16px" }}>
                <h2 style={{ margin: "0 0 8px", fontSize: "15px", color: "#aaa" }}>📸 Ghost Sandbox Screenshot</h2>
                <p style={{ color: "#666", fontSize: "13px", marginBottom: "12px" }}>Captured safely without you visiting it</p>
                <img src={`data:image/png;base64,${result.screenshot_b64}`} alt="Sandbox" style={{ width: "100%", borderRadius: "8px", border: "1px solid #ff2d2d" }} />
              </div>
            )}
          </div>
        )}

        {/* Recent Scans */}
        <div style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(127,119,221,0.3)", borderRadius: "16px", padding: "24px" }}>
          <h2 style={{ margin: "0 0 16px", fontSize: "15px", color: "#aaa" }}>🕵️ Recent Scans</h2>
          {recentScans.length === 0 ? (
            <p style={{ color: "#555", textAlign: "center", fontSize: "13px" }}>No scans yet</p>
          ) : (
            recentScans.map((scan, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 0", borderBottom: "1px solid rgba(255,255,255,0.05)", fontSize: "13px" }}>
                <span style={{ color: "#ff8888", maxWidth: "55%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{scan.url}</span>
                <span style={{ color: getColor(scan.score), fontWeight: "bold" }}>{scan.score}/100</span>
                <span style={{ color: "#555", fontSize: "12px" }}>{scan.scanned_at?.slice(11, 16)}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
