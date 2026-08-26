import TiltCard from './TiltCard';
import useReveal from './useReveal';
import { scoreColor } from './ScanResult';

export default function RecentScans({ scans }) {
  const ref = useReveal();
  return (
    <section className="section reveal" id="recent" ref={ref}>
      <h3 className="section-title">🕵️ Recent Scans</h3>
      <TiltCard max={2}>
        {scans.length === 0 ? (
          <div className="empty-hint">No scans yet — be the first to test a suspicious link.</div>
        ) : (
          <div className="recent-list" style={{ padding: 8 }}>
            {scans.map((s, i) => (
              <div className="recent-row" key={i}>
                <span
                  className="sev-dot"
                  style={{ background: scoreColor(s.score), boxShadow: `0 0 8px ${scoreColor(s.score)}` }}
                />
                <span className="recent-url">{s.url}</span>
                <span className="recent-score" style={{ color: scoreColor(s.score) }}>{s.score}/100</span>
                <span className="recent-time">{s.scanned_at?.slice(11, 16)}</span>
              </div>
            ))}
          </div>
        )}
      </TiltCard>
    </section>
  );
}
