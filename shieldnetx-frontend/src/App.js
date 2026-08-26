import { useState, useEffect, Suspense, lazy } from 'react';
import axios from 'axios';
import Navbar from './components/Navbar';
import StatsStrip from './components/StatsStrip';
import ScanResult from './components/ScanResult';
import RecentScans from './components/RecentScans';
import ScanTheater from './components/ScanTheater';

const ParticleField = lazy(() => import('./three/ParticleField'));
const HeroShield = lazy(() => import('./three/HeroShield'));
const ThreatGlobeSection = lazy(() => import('./three/ThreatGlobe'));

const API = '';

const BADGES = [
  { text: '⚡ Zero-day detection', color: '#3E7BFA' },
  { text: '🧠 GenAI analysis', color: '#8B5CF6' },
  { text: '👻 Ghost sandbox', color: '#EC4899' },
  { text: '🌍 Geo-velocity', color: '#2DD4A0' },
];

function modeFromState(loading, result) {
  if (loading) return 'scanning';
  if (result) {
    if (result.threat_score >= 75) return 'threat';
    if (result.threat_score >= 30) return 'warn';
    return 'safe';
  }
  return 'idle';
}

export default function App() {
  const [url, setUrl] = useState('');
  const [message, setMessage] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [recentScans, setRecentScans] = useState([]);
  const [showTheater, setShowTheater] = useState(false);

  useEffect(() => {
    fetchRecent();
  }, []);

  useEffect(() => {
    if (loading) {
      setShowTheater(true);
      return undefined;
    }
    if (showTheater) {
      const t = setTimeout(() => setShowTheater(false), 2000);
      return () => clearTimeout(t);
    }
    return undefined;
  }, [loading]);

  const fetchRecent = async () => {
    try {
      const res = await axios.get(`${API}/recent-scans`);
      setRecentScans((res.data.scans || []).filter((s) => s.url && s.url !== 'string'));
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
    } catch (e) {
      alert('Backend not running!');
    }
    setLoading(false);
  };

  const mode = modeFromState(loading, result);

  return (
    <div id="top">
      <Suspense fallback={null}>
        <ParticleField />
      </Suspense>

      <Navbar />

      <header className="hero">
        <div className="hero-copy">
          <h1>
            Scan any link <span className="grad-text">before it scams you.</span>
          </h1>
          <p className="hero-sub">
            ShieldNetX analyzes six real-time behavioral signals to catch phishing pages on first
            appearance — no blocklists, no waiting, no zero-day gap.
          </p>

          <div className="badges">
            {BADGES.map((b) => (
              <span
                key={b.text}
                className="badge"
                style={{ color: b.color, borderColor: `${b.color}55`, background: `${b.color}12` }}
              >
                {b.text}
              </span>
            ))}
          </div>

          <div className="glass scanbox" id="scan">
            <div className="scan-row">
              <input
                className="scan-input"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Paste suspicious URL here..."
                onKeyDown={(e) => e.key === 'Enter' && scan()}
              />
              <button className="btn-scan" onClick={scan} disabled={loading}>
                {loading ? '⏳ Scanning…' : '🔍 Scan Now'}
              </button>
            </div>
            <textarea
              className="scan-input"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Paste the full WhatsApp/SMS message here (optional — improves accuracy)…"
              rows={3}
            />
            {showTheater && (
              <ScanTheater active={loading} failed={!loading && !result} />
            )}
          </div>
        </div>

        <Suspense fallback={null}>
          <HeroShield mode={mode} />
        </Suspense>
      </header>

      <StatsStrip />

      <Suspense fallback={null}>
        <ThreatGlobeSection />
      </Suspense>

      {result && <ScanResult result={result} />}

      <RecentScans scans={recentScans} />

      <footer className="footer">
        ShieldNetX · Cyber Threat Intelligence Platform — deception caught at the link, funds traced at the graph.
      </footer>
    </div>
  );
}
