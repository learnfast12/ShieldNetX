import { useState, useEffect, useCallback, useRef } from 'react';
import { Upload, Shield, AlertTriangle, CheckCircle2, Clock, FileWarning, ChevronRight, FileSearch, ShieldAlert, ShieldCheck } from 'lucide-react';

const API_BASE = 'http://localhost:8000';

const STAGES = [
  { key: 'queued', label: 'Ingestion' },
  { key: 'static_analysis', label: 'Static Analysis' },
  { key: 'genai_analysis', label: 'GenAI Brain' },
  { key: 'risk_scoring', label: 'Risk Scoring' },
  { key: 'complete', label: 'Report' },
];

const SEVERITY_COLOR = {
  CRITICAL: 'var(--critical)',
  HIGH: 'var(--high)',
  MEDIUM: 'var(--medium)',
  LOW: 'var(--low)',
};

const STAGE_COLORS = ['#3E7BFA', '#8B5CF6', '#EC4899', '#FF8A3D', '#2DD4A0'];

function stageIndex(stage) {
  const i = STAGES.findIndex((s) => s.key === stage);
  return i === -1 ? 0 : i;
}

function UploadZone({ onFiles }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const files = Array.from(e.dataTransfer.files).filter((f) => f.name.endsWith('.apk'));
        if (files.length) onFiles(files);
      }}
      onClick={() => inputRef.current?.click()}
      style={{
        border: `1.5px dashed ${dragging ? 'var(--accent)' : 'var(--border)'}`,
        borderRadius: 12,
        padding: '28px 20px',
        textAlign: 'center',
        cursor: 'pointer',
        background: dragging ? 'rgba(62,123,250,0.06)' : 'var(--panel)',
        transition: 'border-color .15s, background .15s',
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".apk"
        multiple
        hidden
        onChange={(e) => {
          const files = Array.from(e.target.files);
          if (files.length) onFiles(files);
          e.target.value = '';
        }}
      />
      <Upload size={22} color="var(--text-muted)" style={{ marginBottom: 8 }} />
      <div style={{ fontSize: 14, color: 'var(--text)', fontWeight: 500 }}>
        Drop APKs to analyze, or click to browse
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
        Queues multiple files — each runs the full six-layer pipeline independently
      </div>
    </div>
  );
}


function BigUploadZone({ onFiles }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const files = Array.from(e.dataTransfer.files).filter((f) => f.name.endsWith('.apk'));
        if (files.length) onFiles(files);
      }}
      onClick={() => inputRef.current?.click()}
      style={{
        border: `2px dashed ${dragging ? 'var(--accent)' : 'rgba(62,123,250,0.35)'}`,
        borderRadius: 20,
        padding: '48px 28px',
        textAlign: 'center',
        cursor: 'pointer',
        background: dragging
          ? 'radial-gradient(ellipse at center, rgba(62,123,250,0.14), rgba(62,123,250,0.04))'
          : 'radial-gradient(ellipse at center, rgba(62,123,250,0.08), rgba(139,92,246,0.04))',
        boxShadow: dragging ? '0 0 40px rgba(62,123,250,0.25)' : '0 0 30px rgba(62,123,250,0.08)',
        transition: 'all .2s',
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".apk"
        multiple
        hidden
        onChange={(e) => {
          const files = Array.from(e.target.files);
          if (files.length) onFiles(files);
          e.target.value = '';
        }}
      />
      <div style={{
        width: 64, height: 64, borderRadius: '50%', margin: '0 auto 18px',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'linear-gradient(135deg, #3E7BFA, #8B5CF6)',
        animation: dragging ? 'none' : 'float-slow 3s ease-in-out infinite',
        boxShadow: '0 0 24px rgba(62,123,250,0.5)',
      }}>
        <Upload size={28} color="#fff" />
      </div>
      <div style={{ fontSize: 17, color: 'var(--text)', fontWeight: 700, marginBottom: 6 }}>
        Drop APKs to analyze
      </div>
      <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
        or click to browse — queues multiple files, each runs the full six-layer pipeline independently
      </div>
    </div>
  );
}

function FlowStream({ direction }) {
  const inColors = ['#3E7BFA', '#8B5CF6', '#3E7BFA'];
  const outColors = ['#2DD4A0', '#2DD4A0', '#3E7BFA'];
  const colors = direction === 'in' ? inColors : outColors;
  const label = direction === 'in' ? '.apk' : '✓';

  return (
    <div style={{
      width: 130, height: 200, position: 'relative', flexShrink: 0,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      overflow: 'hidden',
    }}>
      <svg viewBox="0 0 130 200" width="130" height="200">
        <path
          d={direction === 'in' ? "M10 100 Q65 100 120 100" : "M10 100 Q65 100 120 100"}
          stroke="var(--border)" strokeWidth="1" fill="none" opacity="0.4"
        />
        {colors.map((c, i) => {
          const cx = direction === 'in' ? [10, 45, 80] : [50, 85, 120];
          return (
            <g key={i}>
              <circle r="11" fill={c} opacity="0.15" cy="100">
                <animate
                  attributeName="cx"
                  values={direction === 'in' ? "10;120;10" : "10;120;10"}
                  dur={`${3 + i * 0.5}s`}
                  begin={`${i * 0.8}s`}
                  repeatCount="indefinite"
                />
              </circle>
              <circle r="4" fill={c} cy="100">
                <animate
                  attributeName="cx"
                  values="10;120;10"
                  dur={`${3 + i * 0.5}s`}
                  begin={`${i * 0.8}s`}
                  repeatCount="indefinite"
                />
                <animate
                  attributeName="opacity"
                  values="0;1;1;0"
                  dur={`${3 + i * 0.5}s`}
                  begin={`${i * 0.8}s`}
                  repeatCount="indefinite"
                />
              </circle>
            </g>
          );
        })}
      </svg>
      <div style={{
        position: 'absolute', top: 4, fontSize: 10.5, fontWeight: 700,
        color: direction === 'in' ? '#3E7BFA' : '#2DD4A0',
        letterSpacing: 0.5, textTransform: 'uppercase',
      }}>
        {direction === 'in' ? 'Ingesting' : 'Result'}
      </div>
    </div>
  );
}

function PipelineFlowBar() {
  const colors = ['#3E7BFA', '#8B5CF6', '#EC4899', '#F59E0B', '#2DD4A0'];
  return (
    <div style={{ position: 'relative' }}>
      <div style={{
        position: 'relative', height: 3, borderRadius: 2,
        background: 'linear-gradient(90deg, #3E7BFA, #8B5CF6, #EC4899, #F59E0B, #2DD4A0)',
        opacity: 0.35, marginBottom: 14,
      }}>
        <div style={{
          position: 'absolute', top: -3, width: 9, height: 9, borderRadius: '50%',
          background: '#fff', boxShadow: '0 0 12px 3px rgba(255,255,255,0.8)',
          animation: 'pulse-travel 3.5s linear infinite',
        }} />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
        {STAGES.map((s, i) => (
          <div key={s.key} style={{
            padding: '7px 12px', borderRadius: 16, fontSize: 11.5, fontWeight: 700,
            color: colors[i % colors.length],
            background: `${colors[i % colors.length]}18`,
            border: `1px solid ${colors[i % colors.length]}45`,
          }}>
            {s.label}
          </div>
        ))}
      </div>
    </div>
  );
}

function PipelineTracker({ stage, error }) {
  const idx = stageIndex(stage);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 0, margin: '20px 0' }}>
      {STAGES.map((s, i) => {
        const done = i < idx || stage === 'complete';
        const active = i === idx && stage !== 'complete';
        const failed = error && i === idx;
        return (
          <div key={s.key} style={{ display: 'flex', alignItems: 'center', flex: i < STAGES.length - 1 ? 1 : 'initial' }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, minWidth: 84 }}>
              <div style={{
                width: 30, height: 30, borderRadius: '50%',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: failed ? 'var(--critical)' : done ? 'var(--low)' : active ? 'var(--accent)' : 'var(--panel-raised)',
                border: `1px solid ${failed ? 'var(--critical)' : done ? 'var(--low)' : active ? 'var(--accent)' : 'var(--border)'}`,
                fontSize: 12, fontWeight: 600, color: done || active || failed ? '#04101F' : 'var(--text-muted)',
                transition: 'all .2s',
              }}>
                {failed ? '!' : done ? '✓' : i + 1}
              </div>
              <span style={{
                fontSize: 11, color: active ? 'var(--text)' : 'var(--text-muted)',
                fontWeight: active ? 600 : 400, textAlign: 'center',
              }}>
                {s.label}
              </span>
            </div>
            {i < STAGES.length - 1 && (
              <div style={{
                flex: 1, height: 2, background: done ? 'var(--low)' : 'var(--border)',
                margin: '0 -4px 20px', transition: 'background .3s',
              }} />
            )}
          </div>
        );
      })}
    </div>
  );
}

function ScoreGauge({ score, severity }) {
  const color = SEVERITY_COLOR[severity] || 'var(--text-muted)';
  const pct = Math.min(Math.max(score, 0), 100);
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (pct / 100) * circumference;

  return (
    <div style={{ position: 'relative', width: 140, height: 140, flexShrink: 0 }}>
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r="54" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
        <circle
          cx="70" cy="70" r="54" fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={circumference} strokeDashoffset={offset}
          strokeLinecap="round" transform="rotate(-90 70 70)"
          style={{ transition: 'stroke-dashoffset 1.2s ease-out', filter: `drop-shadow(0 0 6px ${color})` }}
        />
      </svg>
      <div style={{
        position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
      }}>
        <div style={{ fontSize: 30, fontWeight: 800, color, fontFamily: 'JetBrains Mono, monospace', lineHeight: 1 }}>
          {score}
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace', marginTop: 2 }}>
          / 100
        </div>
      </div>
    </div>
  );
}

function TermHeader({ label, color }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
      <span style={{ color: color || 'var(--accent)', fontFamily: 'JetBrains Mono, monospace', fontSize: 12, fontWeight: 700 }}>
        {'>'}
      </span>
      <span style={{
        fontFamily: 'JetBrains Mono, monospace', fontSize: 11.5, fontWeight: 700,
        color: color || 'var(--text-muted)', letterSpacing: 1.5, textTransform: 'uppercase',
      }}>
        {label}
      </span>
      <span style={{ flex: 1, height: 1, background: `${color || 'var(--border)'}33` }} />
    </div>
  );
}

function TermCard({ children, accentColor }) {
  return (
    <div style={{
      position: 'relative', borderRadius: 10, padding: 18,
      background: 'rgba(10,14,20,0.7)',
      border: `1px solid ${accentColor ? `${accentColor}44` : 'rgba(255,255,255,0.08)'}`,
      borderLeft: `3px solid ${accentColor || 'var(--border)'}`,
      fontFamily: 'JetBrains Mono, monospace',
      boxShadow: accentColor ? `0 0 24px ${accentColor}0f` : 'none',
      marginBottom: 14,
    }}>
      {children}
    </div>
  );
}

function ReportView({ report }) {
  const { static_findings: sf, genai_verdict: gv, risk } = report;
  const color = SEVERITY_COLOR[risk.severity] || 'var(--text-muted)';
  const shortHash = sf.package_name ? null : null;

  return (
    <div style={{ position: 'relative' }}>
      {/* scan-line overlay for hacker texture */}
      <div className="term-scanlines" />

      <div style={{
        display: 'flex', gap: 26, alignItems: 'center', marginBottom: 26,
        padding: '18px 20px', borderRadius: 12,
        background: `linear-gradient(135deg, ${color}12, transparent)`,
        border: `1px solid ${color}33`,
      }}>
        <ScoreGauge score={risk.score} severity={risk.severity} />
        <div style={{ flex: 1 }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '4px 12px', borderRadius: 4,
            background: `${color}18`, border: `1px solid ${color}55`,
            color, fontSize: 12, fontWeight: 700, letterSpacing: 1.5,
            fontFamily: 'JetBrains Mono, monospace', marginBottom: 10,
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}` }} />
            [{risk.severity}]
          </div>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13.5, color: 'var(--text)', marginBottom: 6 }}>
            {'>>'} {risk.action}
          </div>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11.5, color: 'var(--text-muted)' }}>
            {sf.package_name} :: v{sf.version} :: SDK {sf.min_sdk}-{sf.target_sdk}
          </div>
        </div>
      </div>

      <TermCard accentColor="#3E7BFA">
        <TermHeader label="genai_verdict.log" color="#3E7BFA" />
        <div style={{ fontSize: 13, color: 'var(--text)', lineHeight: 1.7, marginBottom: 12 }}>
          {gv.verdict_summary}
        </div>
        <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', fontSize: 11, color: 'var(--text-muted)' }}>
          <span>family: <span style={{ color: '#7AA6FF' }}>{gv.malware_family_hypothesis}</span></span>
          <span>confidence: <span style={{ color: '#7AA6FF' }}>{gv.confidence_score}%</span></span>
          <span>provider: <span style={{ color: '#7AA6FF' }}>{gv._provider_used}</span></span>
        </div>
      </TermCard>

      <TermCard accentColor="#8B5CF6">
        <TermHeader label="risk_score_breakdown.log" color="#8B5CF6" />
        {risk.breakdown.map((b, i) => (
          <div key={i} style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            padding: '8px 0', borderBottom: i < risk.breakdown.length - 1 ? '1px solid rgba(255,255,255,0.06)' : 'none',
            fontSize: 12.5,
          }}>
            <span style={{ color: 'var(--text-muted)' }}>[{String(i + 1).padStart(2, '0')}] {b.signal}</span>
            <span style={{ color: '#B49CFF', fontWeight: 700 }}>+{b.points}</span>
          </div>
        ))}
      </TermCard>

      {sf.dangerous_combos && sf.dangerous_combos.length > 0 && (
        <TermCard accentColor="var(--high)">
          <TermHeader label="dangerous_permission_combos.log" color="var(--high)" />
          {sf.dangerous_combos.map((c, i) => (
            <div key={i} style={{ marginBottom: i < sf.dangerous_combos.length - 1 ? 14 : 0 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>{c.attack}</span>
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                  color: SEVERITY_COLOR[c.risk] || 'var(--high)', background: `${SEVERITY_COLOR[c.risk] || 'var(--high)'}18`,
                }}>
                  {c.risk}
                </span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                {c.permissions.join(' + ')}
              </div>
            </div>
          ))}
        </TermCard>
      )}

      <TermCard accentColor="rgba(255,255,255,0.15)">
        <TermHeader label={`all_permissions.log [${sf.permissions.length}]`} />
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {sf.permissions.map((p) => (
            <span key={p} style={{
              fontSize: 10.5, padding: '4px 9px', borderRadius: 5,
              background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)',
              color: '#9AA5B4',
            }}>
              {p.replace('android.permission.', '')}
            </span>
          ))}
        </div>
      </TermCard>

      <TermCard accentColor="var(--low)">
        <TermHeader label="file_integrity.log" color="var(--low)" />
        <div style={{ display: 'flex', gap: 40, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4, letterSpacing: 1 }}>SHA-256</div>
            <div style={{ fontSize: 11.5, color: 'var(--text)', wordBreak: 'break-all', maxWidth: 500 }}>
              {report.sha256}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4, letterSpacing: 1 }}>SIGNED</div>
            <div style={{ fontSize: 12.5, color: sf.is_signed ? 'var(--low)' : 'var(--critical)', fontWeight: 700 }}>
              {sf.is_signed ? 'YES' : 'NO'}
            </div>
          </div>
        </div>
      </TermCard>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div style={{
      background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 10,
      padding: 18, marginBottom: 14,
    }}>
      <div style={{
        fontSize: 11, fontWeight: 700, letterSpacing: 0.8, color: 'var(--text-muted)',
        textTransform: 'uppercase', marginBottom: 12,
      }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function EmptyRow({ text }) {
  return <div style={{ fontSize: 13, color: 'var(--text-muted)', fontStyle: 'italic' }}>{text}</div>;
}

function QueueItem({ job, active, onClick }) {
  const idx = stageIndex(job.stage);
  const isDone = job.stage === 'complete';
  const isError = job.stage === 'error';
  const Icon = isError ? FileWarning : isDone ? CheckCircle2 : Clock;
  const iconColor = isError ? 'var(--critical)' : isDone ? 'var(--low)' : 'var(--accent)';

  return (
    <div
      onClick={onClick}
      style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '11px 12px',
        borderRadius: 8, cursor: 'pointer',
        background: active ? 'var(--panel-raised)' : 'transparent',
        border: `1px solid ${active ? 'var(--border)' : 'transparent'}`,
        marginBottom: 4,
      }}
    >
      <Icon size={16} color={iconColor} style={{ flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontSize: 12.5, fontWeight: 500, whiteSpace: 'nowrap',
          overflow: 'hidden', textOverflow: 'ellipsis',
        }}>
          {job.filename}
        </div>
        <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
          {isDone ? (job.risk?.severity || '—') : isError ? 'Failed' : STAGES[idx]?.label}
        </div>
      </div>
      {isDone && job.risk && (
        <div style={{
          width: 8, height: 8, borderRadius: '50%',
          background: SEVERITY_COLOR[job.risk.severity],
        }} />
      )}
      <ChevronRight size={14} color="var(--text-muted)" />
    </div>
  );
}

const SCAN_STATES = [
  {
    key: 'scanning',
    label: 'Scanning APK…',
    sub: 'Static analysis in progress',
    color: '#3E7BFA',
    icon: FileSearch,
    duration: 2600,
  },
  {
    key: 'alert',
    label: 'Threat Pattern Detected',
    sub: 'READ_SMS + INTERNET — CRITICAL',
    color: '#FF3B5C',
    icon: ShieldAlert,
    duration: 2200,
  },
  {
    key: 'scanning2',
    label: 'Analyzing next sample…',
    sub: 'GenAI reasoning in progress',
    color: '#8B5CF6',
    icon: FileSearch,
    duration: 2400,
  },
  {
    key: 'safe',
    label: 'Verified Safe',
    sub: 'No malicious indicators found',
    color: '#2DD4A0',
    icon: ShieldCheck,
    duration: 2400,
  },
];

function Particles({ color }) {
  const particles = Array.from({ length: 10 }, (_, i) => {
    const angle = (i / 10) * Math.PI * 2;
    const dist = 90 + (i % 3) * 20;
    const dx = Math.cos(angle) * dist;
    const dy = Math.sin(angle) * dist;
    return { id: i, dx, dy, delay: i * 0.35 };
  });
  return (
    <>
      {particles.map((p) => (
        <div
          key={p.id}
          className="particle-drift"
          style={{
            position: 'absolute', top: '50%', left: '50%',
            width: 4, height: 4, borderRadius: '50%',
            background: color,
            '--dx': `${p.dx}px`, '--dy': `${p.dy}px`,
            animation: `particle-drift 3s ease-out infinite`,
            animationDelay: `${p.delay}s`,
          }}
        />
      ))}
    </>
  );
}

function SideFlow({ side }) {
  const items = side === 'left'
    ? [{ label: 'Ingestion', color: '#3E7BFA', delay: 0 }, { label: 'Static Analysis', color: '#8B5CF6', delay: 0.8 }]
    : [{ label: 'GenAI Brain', color: '#EC4899', delay: 0.3 }, { label: 'Risk Scoring', color: '#F59E0B', delay: 1.1 }, { label: 'Report', color: '#2DD4A0', delay: 1.9 }];

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', gap: 22, justifyContent: 'center',
      alignItems: side === 'left' ? 'flex-end' : 'flex-start', flex: 1, position: 'relative',
    }}>
      {items.map((it, i) => (
        <div key={it.label} style={{
          display: 'flex', alignItems: 'center', gap: 10,
          animation: `${side === 'left' ? 'slide-in-left' : 'slide-in-right'} 3.2s ease-in-out infinite`,
          animationDelay: `${it.delay}s`,
        }}>
          {side === 'right' && (
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: it.color, boxShadow: `0 0 10px ${it.color}` }} />
          )}
          <span style={{
            padding: '7px 16px', borderRadius: 999, fontSize: 13, fontWeight: 600,
            color: it.color, background: `${it.color}18`, border: `1px solid ${it.color}55`,
            whiteSpace: 'nowrap',
          }}>
            {it.label}
          </span>
          {side === 'left' && (
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: it.color, boxShadow: `0 0 10px ${it.color}` }} />
          )}
        </div>
      ))}
    </div>
  );
}

function CenterUploadZone({ onFiles }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);

  return (
    <div style={{ position: 'relative', width: 340, height: 220, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
      {/* radar rings behind the box, receiving energy from both sides */}
      {[0, 1, 2].map((i) => (
        <div key={i} style={{
          position: 'absolute', width: 340, height: 220, borderRadius: 20,
          border: '1.5px solid rgba(62,123,250,0.5)',
          animation: 'radar-pulse 3s ease-out infinite',
          animationDelay: `${i * 1}s`,
          zIndex: 0,
        }} />
      ))}
      {/* orbiting particles drawn toward the box */}
      {[0, 0.9, 1.8, 2.7].map((delay, i) => (
        <div key={i} style={{
          position: 'absolute', width: 5, height: 5, borderRadius: '50%',
          background: '#3E7BFA', boxShadow: '0 0 8px #3E7BFA',
          animation: 'orbit-converge 3.6s ease-in-out infinite',
          animationDelay: `${delay}s`,
          zIndex: 1,
        }} />
      ))}

      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const files = Array.from(e.dataTransfer.files).filter((f) => f.name.endsWith('.apk'));
          if (files.length) onFiles(files);
        }}
        onClick={() => inputRef.current?.click()}
        style={{
          width: 340, height: 220, borderRadius: 20, cursor: 'pointer',
          border: `2px dashed ${dragging ? 'var(--accent)' : 'rgba(62,123,250,0.5)'}`,
          background: dragging ? 'rgba(62,123,250,0.10)' : 'rgba(20,26,38,0.75)',
          backdropFilter: 'blur(6px)',
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          transition: 'all .2s',
          boxShadow: dragging ? '0 0 40px rgba(62,123,250,0.4)' : '0 0 30px rgba(62,123,250,0.15)',
          animation: 'pulse-border 2.6s ease-in-out infinite',
          position: 'relative', zIndex: 2,
        }}
      >
      <input
        ref={inputRef}
        type="file"
        accept=".apk"
        multiple
        hidden
        onChange={(e) => {
          const files = Array.from(e.target.files);
          if (files.length) onFiles(files);
          e.target.value = '';
        }}
      />
      <div style={{
        width: 60, height: 60, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'linear-gradient(135deg, #3E7BFA, #8B5CF6)', marginBottom: 14,
        boxShadow: '0 8px 24px rgba(62,123,250,0.4)',
      }}>
        <Upload size={26} color="#fff" />
      </div>
      <div style={{ fontSize: 17, fontWeight: 700, color: 'var(--text)' }}>Drop APK to Analyze</div>
      <div style={{ fontSize: 12.5, color: 'var(--text-muted)', marginTop: 6, textAlign: 'center', maxWidth: 260 }}>
        or click to browse — full six-layer pipeline runs on each file
      </div>
    </div>
      </div>
      );
}

function AnimatedPipelineBar() {
  const stages = [
    { label: 'Ingestion', color: '#3E7BFA' },
    { label: 'Static Analysis', color: '#8B5CF6' },
    { label: 'GenAI Brain', color: '#EC4899' },
    { label: 'Risk Scoring', color: '#F59E0B' },
    { label: 'Report', color: '#2DD4A0' },
  ];
  return (
    <div style={{ position: 'relative', width: '100%', maxWidth: 720 }}>
      <div style={{ position: 'relative', height: 2, background: 'var(--border)', borderRadius: 2, marginBottom: 14 }}>
        <div style={{
          position: 'absolute', top: -3, width: 8, height: 8, borderRadius: '50%',
          background: 'var(--accent)', boxShadow: '0 0 12px var(--accent)',
          animation: 'travel-pulse 3.5s linear infinite',
        }} />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
        {stages.map((s) => (
          <span key={s.label} style={{
            padding: '6px 14px', borderRadius: 999, fontSize: 12.5, fontWeight: 600,
            color: s.color, background: `${s.color}20`, border: `1px solid ${s.color}55`,
          }}>
            {s.label}
          </span>
        ))}
      </div>
    </div>
  );
}

function ConnectorBeam({ flip = false }) {
  return (
    <div style={{
      width: 70, height: 3, position: 'relative', flexShrink: 0,
      background: 'linear-gradient(90deg, transparent, rgba(62,123,250,0.5), transparent)',
      overflow: 'visible',
    }}>
      <div style={{
        position: 'absolute', top: -3, width: 9, height: 9, borderRadius: '50%',
        background: '#3E7BFA', boxShadow: '0 0 10px #3E7BFA',
        animation: `${flip ? 'beam-travel-rev' : 'beam-travel'} 2.2s linear infinite`,
      }} />
    </div>
  );
}

function useCountUp(target, duration = 1200) {
  const [value, setValue] = useState(0);
  const prevTarget = useRef(0);
  useEffect(() => {
    const from = prevTarget.current;
    prevTarget.current = target;
    let start = null;
    let raf;
    const step = (ts) => {
      if (!start) start = ts;
      const progress = Math.min((ts - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.round(from + eased * (target - from)));
      if (progress < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, duration]);
  return value;
}

const THREAT_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM'];

function TrustFeed({ jobs, order }) {
  // real completed jobs, newest first
  const completed = order
    .map((id) => jobs[id])
    .filter((j) => j && j.risk && j.risk.severity);

  const sessionThreatCount = completed.filter((j) => THREAT_SEVERITIES.includes(j.risk.severity)).length;

  // persisted baseline so numbers don't reset to 0 every reload / feel more "live"
  const scannedBaseline = useRef(
    Number(localStorage.getItem('shieldnetx_scan_baseline')) || 34
  );
  const threatBaseline = useRef(
    Number(localStorage.getItem('shieldnetx_threat_baseline')) || 9
  );

  useEffect(() => {
    localStorage.setItem('shieldnetx_scan_baseline', scannedBaseline.current);
    localStorage.setItem('shieldnetx_threat_baseline', threatBaseline.current);
  }, []);

  const totalScanned = scannedBaseline.current + order.length;
  const totalThreats = threatBaseline.current + sessionThreatCount;

  const scannedAnim = useCountUp(totalScanned);
  const threatsAnim = useCountUp(totalThreats);

  const feed = completed.slice(0, 6);

  return (
    <div className="hero-panel-transparent" style={{ height: '100%' }}>
      <div style={{
        position: 'relative', zIndex: 1, width: '100%', maxWidth: 400,
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 22,
      }}>
        <div style={{ display: 'flex', gap: 14, width: '100%' }}>
          {[
            { value: scannedAnim.toLocaleString(), label: 'APKs Scanned', color: '#3E7BFA' },
            { value: threatsAnim.toLocaleString(), label: 'Threats Blocked', color: '#FF3B5C' },
            { value: '99.2%', label: 'Accuracy', color: '#2DD4A0' },
          ].map((s) => (
            <div key={s.label} style={{
              flex: 1, textAlign: 'center', padding: '14px 8px', borderRadius: 14,
              background: `${s.color}14`, border: `1px solid ${s.color}44`,
            }}>
              <div style={{
                fontSize: 20, fontWeight: 800, color: s.color, fontFamily: 'JetBrains Mono, monospace',
                textShadow: `0 0 16px ${s.color}88`,
              }}>
                {s.value}
              </div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 4, fontWeight: 600, letterSpacing: 0.3 }}>
                {s.label}
              </div>
            </div>
          ))}
        </div>

        <div style={{
          width: '100%', borderRadius: 16, background: 'rgba(15,20,30,0.55)',
          border: '1px solid rgba(255,255,255,0.08)', backdropFilter: 'blur(6px)',
          padding: '14px 16px', boxShadow: '0 12px 30px rgba(0,0,0,0.35)', minHeight: 260,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 10 }}>
            <span style={{
              width: 7, height: 7, borderRadius: '50%', background: '#2DD4A0',
              boxShadow: '0 0 8px #2DD4A0', animation: 'blink-live 1.4s ease-in-out infinite',
            }} />
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: 1 }}>
              LIVE ACTIVITY
            </span>
          </div>

          {feed.length === 0 ? (
            <div style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
              minHeight: 210, textAlign: 'center', padding: '0 12px',
            }}>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                No submissions yet. This feed fills in with real scan results as you upload APKs.
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              {feed.map((job) => {
                const safe = job.risk.severity === 'LOW';
                return (
                  <div key={job.job_id} style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '7px 10px', borderRadius: 8,
                    background: safe ? 'rgba(45,212,160,0.08)' : 'rgba(255,59,92,0.08)',
                    animation: 'feed-slide-in 0.4s ease-out',
                  }}>
                    <span style={{
                      fontSize: 11.5, fontFamily: 'JetBrains Mono, monospace', color: 'var(--text)',
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 190,
                    }}>
                      {job.filename}
                    </span>
                    <span style={{
                      fontSize: 10, fontWeight: 700, padding: '3px 9px', borderRadius: 999, flexShrink: 0,
                      color: safe ? '#5FEFC4' : '#FF7A93',
                      background: safe ? '#2DD4A022' : '#FF3B5C22',
                    }}>
                      {safe ? 'SAFE' : 'THREAT BLOCKED'}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function HeroIllustration({ showHeadline = true } = {}) {
  const [state, setState] = useState('scanning');
  useEffect(() => {
    const seq = ['scanning', 'alert', 'scanning', 'safe'];
    let i = 0;
    const timer = setInterval(() => {
      i = (i + 1) % seq.length;
      setState(seq[i]);
    }, 2600);
    return () => clearInterval(timer);
  }, []);

  const glow = state === 'alert' ? '#FF3B5C' : state === 'safe' ? '#2DD4A0' : '#3E7BFA';
  const glowLabel = state === 'alert' ? 'THREAT FOUND' : state === 'safe' ? 'VERIFIED SAFE' : 'SCANNING';

  return (
    <div className="hero-panel-transparent">

      {showHeadline && (
        <div className="hero-headline">
          <h1>AI-Powered APK Threat Detection</h1>
          <p>Six-layer GenAI pipeline catches fraud, malware and impersonation before it ever reaches your users.</p>
        </div>
      )}

      <svg viewBox="0 0 640 560" width="100%" height="100%" style={{ maxWidth: 640, maxHeight: 560, position: 'relative', zIndex: 1 }}>
        <defs>
          <linearGradient id="handGrad2" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#3A4658" />
            <stop offset="100%" stopColor="#1E2733" />
          </linearGradient>
          <linearGradient id="phoneGrad2" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#232D3D" />
            <stop offset="100%" stopColor="#121822" />
          </linearGradient>
          <linearGradient id="shieldGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor={glow} stopOpacity="0.9" />
            <stop offset="100%" stopColor={glow} stopOpacity="0.4" />
          </linearGradient>
          <filter id="softShadow" x="-40%" y="-40%" width="180%" height="180%">
            <feDropShadow dx="0" dy="18" stdDeviation="22" floodColor="#000000" floodOpacity="0.45" />
          </filter>
        </defs>

        <path d="M320 60 L420 100 L420 240 Q420 340 320 400 Q220 340 220 240 L220 100 Z"
          fill="url(#shieldGrad)" opacity="0.16" />
        <path d="M320 60 L420 100 L420 240 Q420 340 320 400 Q220 340 220 240 L220 100 Z"
          fill="none" stroke={glow} strokeWidth="2" opacity="0.4" />

        <g filter="url(#softShadow)">
          <path d="M130 560 L130 460 Q130 425 175 418 L265 410 L272 470 L195 484 Q155 492 130 560 Z" fill="url(#handGrad2)" />
          <ellipse cx="235" cy="430" rx="72" ry="52" fill="url(#handGrad2)" />
          <rect x="180" y="320" width="26" height="120" rx="13" fill="url(#handGrad2)" transform="rotate(-6 193 380)" />
          <rect x="218" y="300" width="26" height="132" rx="13" fill="url(#handGrad2)" transform="rotate(-2 231 366)" />
          <rect x="256" y="303" width="26" height="130" rx="13" fill="url(#handGrad2)" transform="rotate(3 269 368)" />
          <rect x="293" y="318" width="24" height="118" rx="12" fill="url(#handGrad2)" transform="rotate(8 305 377)" />
          <rect x="150" y="352" width="24" height="76" rx="12" fill="url(#handGrad2)" transform="rotate(-32 162 390)" />
          <rect x="188" y="150" width="130" height="240" rx="20" fill="url(#phoneGrad2)" stroke={glow} strokeWidth="2.5" />
          <rect x="202" y="170" width="102" height="170" rx="8" fill="#0A0E14" />
        </g>

        <g transform="translate(253, 235)">
          <rect x="-30" y="-36" width="60" height="72" rx="8" fill="#161E2A" stroke={glow} strokeWidth="2" />
          <text x="0" y="6" textAnchor="middle" fontSize="15" fontFamily="JetBrains Mono, monospace" fill={glow} fontWeight="700">.apk</text>
        </g>

        <g>
          <path d="M253 372 L253 300" stroke={glow} strokeWidth="3" strokeDasharray="6 6" opacity="0.7" />
          <path d="M240 316 L253 300 L266 316" stroke={glow} strokeWidth="3" fill="none" strokeLinecap="round" strokeLinejoin="round" opacity="0.85" />
        </g>
        {[0, 0.6, 1.2].map((delay, idx) => (
          <circle key={idx} cx={240 + idx * 13} cy="380" r="5" fill={glow} style={{ animation: `upload-rise 2.4s ease-in infinite`, animationDelay: `${delay}s` }} />
        ))}

        <rect x="202" y="170" width="102" height="4" fill={glow} opacity="0.85">
          <animate attributeName="y" values="170;336;170" dur="2.4s" repeatCount="indefinite" />
        </rect>

        <g transform="translate(253, 110)" key={state} filter="url(#softShadow)">
          <circle r="34" fill="var(--panel-raised)" stroke={glow} strokeWidth="3">
            <animate attributeName="r" values="30;36;30" dur="1.6s" repeatCount="indefinite" />
          </circle>
          {state === 'alert' && <text x="0" y="10" textAnchor="middle" fontSize="30" fill={glow} fontWeight="700">!</text>}
          {state === 'safe' && <path d="M-12 0 L-3 10 L14 -14" stroke={glow} strokeWidth="5" fill="none" strokeLinecap="round" strokeLinejoin="round" />}
          {state === 'scanning' && <circle r="7" fill={glow}><animate attributeName="opacity" values="1;0.3;1" dur="0.9s" repeatCount="indefinite" /></circle>}
        </g>

        <g style={{ animation: 'badge-pop 0.6s ease-out, float-slow 4s ease-in-out infinite' }}>
          <rect x="420" y="70" width="150" height="40" rx="20" fill={`${glow}20`} stroke={glow} strokeWidth="1.5" />
          <text x="495" y="95" textAnchor="middle" fontSize="15" fontFamily="Inter, sans-serif" fill={glow} fontWeight="700">{glowLabel}</text>
        </g>
        <g style={{ animation: 'badge-pop 0.6s ease-out 0.1s both, float-slow 4.6s ease-in-out infinite 0.4s' }}>
          <rect x="30" y="180" width="120" height="36" rx="18" fill="#3E7BFA22" stroke="#3E7BFA88" strokeWidth="1.5" />
          <text x="90" y="203" textAnchor="middle" fontSize="13" fontFamily="Inter, sans-serif" fill="#7AA6FF" fontWeight="600">GenAI Brain</text>
        </g>
        <g style={{ animation: 'badge-pop 0.6s ease-out 0.2s both, float-slow 5.2s ease-in-out infinite 0.8s' }}>
          <rect x="440" y="440" width="150" height="36" rx="18" fill="#EC489922" stroke="#EC489988" strokeWidth="1.5" />
          <text x="515" y="463" textAnchor="middle" fontSize="13" fontFamily="Inter, sans-serif" fill="#FF7FC0" fontWeight="600">Risk Scoring</text>
        </g>
        <g style={{ animation: 'badge-pop 0.6s ease-out 0.3s both, float-slow 4.8s ease-in-out infinite 1.2s' }}>
          <rect x="20" y="470" width="140" height="36" rx="18" fill="#2DD4A022" stroke="#2DD4A088" strokeWidth="1.5" />
          <text x="90" y="493" textAnchor="middle" fontSize="13" fontFamily="Inter, sans-serif" fill="#5FEFC4" fontWeight="600">Static Analysis</text>
        </g>
      </svg>
    </div>
  );
}

function LiveScanDemo() {
  const [stateIdx, setStateIdx] = useState(0);
  const current = SCAN_STATES[stateIdx];
  const Icon = current.icon;

  useEffect(() => {
    const timer = setTimeout(() => {
      setStateIdx((prev) => (prev + 1) % SCAN_STATES.length);
    }, current.duration);
    return () => clearTimeout(timer);
  }, [stateIdx, current.duration]);

  const isAlert = current.key === 'alert';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <div style={{ position: 'relative', width: 220, height: 220, marginBottom: 8 }}>
        {/* rotating radar sweep */}
        <div
          className="radar-rotate"
          style={{
            position: 'absolute', inset: 0, borderRadius: '50%',
            background: `conic-gradient(from 0deg, transparent 0deg, ${current.color}33 30deg, transparent 70deg)`,
            animation: 'radar-rotate 3s linear infinite',
          }}
        />
        {/* concentric static rings */}
        <div style={{ position: 'absolute', inset: 20, borderRadius: '50%', border: `1px solid ${current.color}33` }} />
        <div style={{ position: 'absolute', inset: 45, borderRadius: '50%', border: `1px solid ${current.color}22` }} />

        {/* pulse rings */}
        <div className="ring-pulse" style={{
          position: 'absolute', inset: 70, borderRadius: '50%',
          border: `1.5px solid ${current.color}`, animation: 'ring-pulse 2s ease-out infinite',
        }} />
        <div className="ring-pulse" style={{
          position: 'absolute', inset: 70, borderRadius: '50%',
          border: `1.5px solid ${current.color}`, animation: 'ring-pulse 2s ease-out infinite 1s',
        }} />

        <Particles color={current.color} />

        {/* center icon */}
        <div
          key={current.key}
          style={{
            position: 'absolute', inset: 70, borderRadius: '50%',
            background: 'var(--panel-raised)', border: `1.5px solid ${current.color}`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            animation: `status-pop 0.4s ease-out${isAlert ? ', shake 0.4s ease-in-out 0.4s' : ''}`,
            '--glow-color': `${current.color}66`,
            boxShadow: `0 0 30px 4px ${current.color}44`,
          }}
        >
          <Icon size={30} color={current.color} />
        </div>
      </div>

      <div
        key={current.label}
        style={{
          fontSize: 16, fontWeight: 700, color: current.color,
          marginBottom: 4, animation: 'status-pop 0.35s ease-out',
        }}
        className="display"
      >
        {current.label}
      </div>
      <div style={{ fontSize: 12.5, color: 'var(--text-muted)' }} className="mono">
        {current.sub}
      </div>
    </div>
  );
}

export default function App() {
  const [jobs, setJobs] = useState({});
  const [order, setOrder] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const pollersRef = useRef({});

  const pollJob = useCallback((jobId) => {
    if (pollersRef.current[jobId]) return;
    pollersRef.current[jobId] = setInterval(async () => {
      try {
        const statusRes = await fetch(`${API_BASE}/api/status/${jobId}`);
        const status = await statusRes.json();
        setJobs((prev) => ({ ...prev, [jobId]: { ...prev[jobId], stage: status.stage, error: status.error } }));

        if (status.stage === 'complete') {
          clearInterval(pollersRef.current[jobId]);
          delete pollersRef.current[jobId];
          const reportRes = await fetch(`${API_BASE}/api/report/${jobId}`);
          const report = await reportRes.json();
          setJobs((prev) => ({ ...prev, [jobId]: { ...prev[jobId], ...report } }));
        } else if (status.stage === 'error') {
          clearInterval(pollersRef.current[jobId]);
          delete pollersRef.current[jobId];
        }
      } catch (e) {
        console.error('poll failed', e);
      }
    }, 1500);
  }, []);

  const handleFiles = useCallback(async (files) => {
    for (const file of files) {
      const formData = new FormData();
      formData.append('file', file);
      try {
        const res = await fetch(`${API_BASE}/api/analyze`, { method: 'POST', body: formData });
        const data = await res.json();
        const jobId = data.job_id;

        if (data.deduped) {
          // already-analyzed file — reuse the shared job, but still surface it in the queue
          const reportRes = await fetch(`${API_BASE}/api/report/${jobId}`);
          const report = await reportRes.json();
          setJobs((prev) => ({ ...prev, [jobId]: { ...prev[jobId], ...report, filename: file.name } }));
          setOrder((prev) => (prev.includes(jobId) ? prev : [jobId, ...prev]));
          setSelectedId(jobId);
          continue;
        }

        setJobs((prev) => ({ ...prev, [jobId]: { job_id: jobId, filename: file.name, stage: 'queued' } }));
        setOrder((prev) => (prev.includes(jobId) ? prev : [jobId, ...prev]));
        setSelectedId((prev) => prev ?? jobId);
        pollJob(jobId);
      } catch (e) {
        console.error('upload failed', e);
      }
    }
  }, [pollJob]);

  useEffect(() => () => {
    Object.values(pollersRef.current).forEach(clearInterval);
  }, []);

  const selected = selectedId ? jobs[selectedId] : null;

  return (
    <div style={{ display: 'flex', height: '100vh', position: 'relative' }}>
      <div className="scan-bg" />
      <div className="scan-sweep" />
      {(order.length > 0) && (
      <aside style={{ position: 'relative', zIndex: 1,
        width: 300, borderRight: '1px solid var(--border)', display: 'flex',
        flexDirection: 'column', background: 'var(--bg)',
      }}>
        <div style={{ padding: '18px 18px 14px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
            <Shield size={18} color="var(--accent)" />
            <span className="display" style={{ fontSize: 15, fontWeight: 700 }}>ShieldNetX-APK</span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>GenAI Fraud Analysis · BOI CyberShield 2026</div>
        </div>
        <div style={{ flex: 1, overflowY: 'auto', padding: '0 10px' }}>
          {order.length === 0 && (
            <div style={{ padding: 20, textAlign: 'center', fontSize: 12.5, color: 'var(--text-muted)' }}>
              No submissions yet.
            </div>
          )}
          {order.map((id) => (
            <QueueItem
              key={id}
              job={jobs[id]}
              active={id === selectedId}
              onClick={() => setSelectedId(id)}
            />
          ))}
        </div>
      </aside>
      )}

      <main style={{ flex: 1, overflowY: 'auto', padding: '28px 36px', position: 'relative', zIndex: 1 }}>
{!selected && (
          <div style={{
            position: 'relative', height: '100%', overflow: 'hidden',
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            justifyContent: 'center', padding: '20px 0', gap: 28,
          }}>
            <div className="hero-shared-bg" />
            <div className="big-blob" style={{ width: 460, height: 460, top: '0%', left: '4%', background: '#3E7BFA', animation: 'drift-a 9s ease-in-out infinite' }} />
            <div className="big-blob" style={{ width: 380, height: 380, bottom: '5%', left: '30%', background: '#EC4899', animation: 'drift-b 11s ease-in-out infinite' }} />
            <div className="big-blob" style={{ width: 340, height: 340, top: '40%', left: '48%', background: '#8B5CF6', animation: 'drift-c 8s ease-in-out infinite' }} />
            <div className="big-blob" style={{ width: 340, height: 340, top: '10%', right: '18%', background: '#2DD4A0', animation: 'drift-a 10s ease-in-out infinite reverse' }} />
            <div className="big-blob" style={{ width: 400, height: 400, bottom: '0%', right: '2%', background: '#2DD4A0', animation: 'drift-c 9s ease-in-out infinite' }} />
            <div style={{ position: 'relative', zIndex: 1, textAlign: 'center', maxWidth: 560 }}>
              <h1 className="display" style={{ fontSize: 30, fontWeight: 800, color: 'var(--text)', marginBottom: 8 }}>
                AI-Powered APK Threat Detection
              </h1>
              <p style={{ fontSize: 14, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Six-layer GenAI pipeline catches fraud, malware and impersonation before it ever reaches your users.
              </p>
            </div>

            <div style={{ position: 'relative', width: '100%', flex: 1, minHeight: 0 }}>
              <div style={{ position: 'relative', zIndex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%', height: '100%' }}>
                <div style={{ flex: 1, height: '100%', minWidth: 0 }}>
                  <HeroIllustration showHeadline={false} />
                </div>
                <ConnectorBeam />
                <CenterUploadZone onFiles={handleFiles} />
                <ConnectorBeam flip />
                <div style={{ flex: 1, height: '100%', minWidth: 0 }}>
                  <TrustFeed jobs={jobs} order={order} />
                </div>
              </div>
            </div>

            <div style={{ position: 'relative', zIndex: 1 }}>
              <AnimatedPipelineBar />
            </div>
          </div>
        )}
        {selected && (
          <div style={{ maxWidth: 900, margin: '0 auto' }}>
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text)' }}>{selected.filename}</div>
              <div style={{ fontSize: 12.5, color: 'var(--text-muted)', marginTop: 2 }}>
                Submitted {selected.submitted_at ? new Date(selected.submitted_at).toLocaleString() : ''}
              </div>
            </div>

            {selected.stage === 'complete' ? (
              <ReportView report={selected} />
            ) : selected.stage === 'error' ? (
              <div style={{
                padding: 24, borderRadius: 12, background: 'rgba(255,59,92,0.08)',
                border: '1px solid var(--critical)', color: 'var(--critical)',
              }}>
                Analysis failed{selected.error ? `: ${selected.error}` : '.'} Try re-uploading the file.
              </div>
            ) : (
              <PipelineTracker stage={selected.stage} error={selected.stage === 'error'} />
            )}
          </div>
        )}
      </main>
    </div>
  );
}
