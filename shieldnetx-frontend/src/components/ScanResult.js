import { lazy, Suspense, useEffect, useState } from 'react';
import TiltCard from './TiltCard';
import useReveal from './useReveal';

const SignalConstellation = lazy(() => import('../three/SignalConstellation'));

export const scoreColor = (score) => {
  if (score >= 75) return '#ff3b5c';
  if (score >= 50) return '#ff8a3d';
  if (score >= 30) return '#ffc53d';
  return '#2dd4a0';
};

const SIG_GRADIENTS = {
  '#ff3b5c': 'linear-gradient(90deg,#ff3b5c,#ff8a3d)',
  '#ff8a3d': 'linear-gradient(90deg,#ff8a3d,#ffc53d)',
  '#ffc53d': 'linear-gradient(90deg,#ffc53d,#ec4899)',
  '#2dd4a0': 'linear-gradient(90deg,#2dd4a0,#3e7bfa)',
};

function ScoreGauge({ score }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 60);
    return () => clearTimeout(t);
  }, []);

  const r = 62;
  const C = 2 * Math.PI * r;
  const offset = mounted ? C - (Math.min(score, 100) / 100) * C : C;
  const c = scoreColor(score);

  return (
    <div className="gauge-ring">
      <svg width="148" height="148" viewBox="0 0 148 148">
        <circle cx="74" cy="74" r={r} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="10" />
        <circle
          cx="74" cy="74" r={r} fill="none"
          stroke={c} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={C}
          strokeDashoffset={offset}
          style={{
            transition: 'stroke-dashoffset 1.3s cubic-bezier(.22,1,.36,1)',
            filter: `drop-shadow(0 0 9px ${c})`,
          }}
        />
      </svg>
      <div className="gauge-center">
        <div className="gauge-score" style={{ color: c }}>{score}</div>
        <div className="gauge-max">/ 100</div>
      </div>
    </div>
  );
}

function SignalBar({ name, icon, desc, score, max }) {
  const pct = Math.min((score / max) * 100, 100);
  const [w, setW] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setW(pct), 80);
    return () => clearTimeout(t);
  }, [pct]);

  const c = scoreColor(pct);
  return (
    <div className="sig-row">
      <div className="sig-top">
        <span>{icon} {name}</span>
        <span style={{ color: c }}>{score}/{max}</span>
      </div>
      <div className="sig-track">
        <div
          className="sig-fill"
          style={{ width: `${w}%`, backgroundImage: SIG_GRADIENTS[c] || `linear-gradient(90deg,${c},${c})` }}
        />
      </div>
      {desc && <div className="sig-desc">{desc}</div>}
    </div>
  );
}

export default function ScanResult({ result }) {
  const revealRef = useReveal();
  const c = scoreColor(result.threat_score);
  const signals = result.signals ? [
    { name: 'AI Analysis', score: result.signals.ai_analysis?.ai_score || 0, max: 100, icon: '🧠', desc: result.signals.ai_analysis?.explanation || '' },
    { name: 'Ghost Sandbox', score: result.signals.sandbox?.score || 0, max: 25, icon: '👻', desc: result.signals.sandbox?.verdict || '' },
    { name: 'Click Velocity', score: result.signals.click_velocity?.score || 0, max: 20, icon: '⚡', desc: result.signals.click_velocity?.verdict || '' },
    { name: 'Geo Velocity', score: result.signals.geo_velocity?.score || 0, max: 15, icon: '🌍', desc: result.signals.geo_velocity?.verdict || '' },
    { name: 'Dwell Time', score: result.signals.dwell_time?.score || 0, max: 10, icon: '⏱️', desc: result.signals.dwell_time?.verdict || '' },
  ] : [];

  return (
    <section className="section reveal" id="scan-result" ref={revealRef}>
      <TiltCard max={2.5}>
        <div className="verdict-head">
          <ScoreGauge score={result.threat_score} />
          <div>
            <span
              className="level-pill"
              style={{
                background: `${c}1f`,
                border: `1px solid ${c}66`,
                color: c,
                boxShadow: `0 0 22px ${c}33`,
              }}
            >
              {result.threat_level || 'ANALYZED'}
            </span>
            <p className="explain">{result.explanation}</p>
            {result.tamil_explanation && <p className="tamil">{result.tamil_explanation}</p>}
          </div>
        </div>
      </TiltCard>

      {signals.length > 0 && (
        <TiltCard max={2.5}>
          <h3 className="section-title">🛰 Signal Constellation</h3>
          <p style={{ color: '#8a97ad', fontSize: 13, margin: '-6px 0 10px' }}>
            Live behavioral signature — drag to rotate
          </p>
          <div className="const-wrap">
            <Suspense fallback={<div className="const-loading mono">initializing constellation…</div>}>
              <SignalConstellation signals={signals} />
            </Suspense>
          </div>
        </TiltCard>
      )}

      {signals.length > 0 && (
        <TiltCard max={2.5}>
          <h3 className="section-title">📊 Signal Breakdown</h3>
          <div style={{ padding: '4px 6px 12px' }}>
            {signals.map((s) => (
              <SignalBar key={s.name} {...s} />
            ))}
          </div>
        </TiltCard>
      )}

      {result.screenshot_b64 && (
        <TiltCard max={2.5}>
          <h3 className="section-title">📸 Ghost Sandbox Screenshot</h3>
          <p style={{ color: '#8a97ad', fontSize: 13, margin: '-6px 0 16px' }}>
            Captured safely — without you ever visiting the page
          </p>
          <div className="shot-frame">
            <img src={`data:image/png;base64,${result.screenshot_b64}`} alt="Sandbox capture" />
          </div>
        </TiltCard>
      )}
    </section>
  );
}
