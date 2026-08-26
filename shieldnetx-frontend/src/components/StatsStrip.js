import useCountUp from './useCountUp';
import useReveal from './useReveal';
import TiltCard from './TiltCard';

const STATS = [
  { icon: '🛡️', value: 1247, label: 'URLs Scanned', color: '#FF8A3D' },
  { icon: '🚫', value: 983, label: 'Threats Blocked', color: '#FF3B5C' },
  { icon: '🇮🇳', value: 298450, label: 'Indians Protected', color: '#2DD4A0' },
  { icon: '⚙️', value: 95, label: 'Engines Active', color: '#8B5CF6' },
];

function Stat({ icon, value, label, color }) {
  const n = useCountUp(value);
  return (
    <TiltCard className="stat-card" max={5}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-value" style={{ '--sc': color }} data-color={color}>
        {n.toLocaleString()}
      </div>
      <div className="stat-label">{label}</div>
    </TiltCard>
  );
}

export default function StatsStrip() {
  const ref = useReveal();
  return (
    <section className="stats-strip reveal" id="stats" ref={ref}>
      {STATS.map((s) => (
        <Stat key={s.label} {...s} />
      ))}
    </section>
  );
}
