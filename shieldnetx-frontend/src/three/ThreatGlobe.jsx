import { useEffect, useMemo, useRef, useState } from 'react';
import axios from 'axios';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Line as DreiLine } from '@react-three/drei';
import * as THREE from 'three';

const COUNTRY_COORDS = {
  india: [21, 78],
  'united states': [38, -97],
  usa: [38, -97],
  'united kingdom': [54, -2],
  uk: [54, -2],
  russia: [61, 90],
  china: [35, 105],
  brazil: [-10, -52],
  germany: [51, 10],
  nigeria: [9, 8],
  pakistan: [30, 69],
  indonesia: [-2, 118],
  netherlands: [52.1, 5.3],
  vietnam: [16, 106],
  singapore: [1.35, 103.8],
  uae: [24, 54],
  canada: [56, -106],
  australia: [-25, 133],
  france: [46, 2],
  japan: [36, 138],
  'south korea': [36, 128],
  bangladesh: [23.7, 90.4],
  'sri lanka': [7.9, 80.8],
  'south africa': [-29, 24],
};

const SEED_SCANS = [
  { url: 'sbi-net-banking.co.in', country: 'india', score: 91 },
  { url: 'hdfc-secure-alert.top', country: 'india', score: 84 },
  { url: 'paytm-kyc-update.xyz', country: 'india', score: 66 },
  { url: 'amazon-refund-claim.club', country: 'singapore', score: 47 },
  { url: 'telegram-premium-gift.ru', country: 'russia', score: 93 },
];

function severityColor(score) {
  if (score >= 75) return '#ff3b5c';
  if (score >= 50) return '#ff8a3d';
  if (score >= 30) return '#ffc53d';
  return '#2dd4a0';
}

function hashCode(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  return Math.abs(h);
}

function scanPosition(scan, i) {
  const key = (scan.country || '').toLowerCase().trim();
  const base = COUNTRY_COORDS[key] || COUNTRY_COORDS.india;
  const h1 = (hashCode(scan.url || String(i)) % 1000) / 1000 - 0.5;
  const h2 = (hashCode((scan.url || '') + i) % 1000) / 1000 - 0.5;
  const lat = base[0] + h1 * 16;
  const lon = base[1] + h2 * 16;
  return { lat, lon };
}

function latLonToVec3(lat, lon, r) {
  const phi = ((90 - lat) * Math.PI) / 180;
  const theta = ((lon + 180) * Math.PI) / 180;
  return new THREE.Vector3(
    -r * Math.sin(phi) * Math.cos(theta),
    r * Math.cos(phi),
    r * Math.sin(phi) * Math.sin(theta)
  );
}

function makeGlowTexture(inner = 0.12) {
  const s = 128;
  const c = document.createElement('canvas');
  c.width = c.height = s;
  const g = c.getContext('2d');
  const grad = g.createRadialGradient(s / 2, s / 2, s * inner, s / 2, s / 2, s / 2);
  grad.addColorStop(0, 'rgba(255,255,255,1)');
  grad.addColorStop(0.35, 'rgba(255,255,255,0.45)');
  grad.addColorStop(1, 'rgba(255,255,255,0)');
  g.fillStyle = grad;
  g.fillRect(0, 0, s, s);
  return new THREE.CanvasTexture(c);
}

function makeRingTexture() {
  const s = 128;
  const c = document.createElement('canvas');
  c.width = c.height = s;
  const g = c.getContext('2d');
  g.strokeStyle = 'rgba(255,255,255,1)';
  g.lineWidth = 5;
  g.beginPath();
  g.arc(s / 2, s / 2, s / 2 - 6, 0, Math.PI * 2);
  g.stroke();
  return new THREE.CanvasTexture(c);
}

const R = 2;

let _glowTex = null;
let _ringTex = null;
function getGlowTex() {
  if (!_glowTex) _glowTex = makeGlowTexture(0);
  return _glowTex;
}
function getRingTex() {
  if (!_ringTex) _ringTex = makeRingTexture();
  return _ringTex;
}

function GlobeMesh() {
  const glowTex = useMemo(makeGlowTexture, []);
  return (
    <group>
      <mesh>
        <sphereGeometry args={[R * 0.985, 48, 48]} />
        <meshBasicMaterial color="#080d18" transparent opacity={0.96} />
      </mesh>
      <mesh>
        <sphereGeometry args={[R, 36, 26]} />
        <meshBasicMaterial color="#4a6cf0" wireframe transparent opacity={0.14} />
      </mesh>
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[R * 1.28, 0.004, 6, 110]} />
        <meshBasicMaterial color="#EC4899" transparent opacity={0.35} blending={THREE.AdditiveBlending} depthWrite={false} />
      </mesh>
      <sprite scale={[6.6, 6.6, 1]}>
        <spriteMaterial map={glowTex} color="#4a6cf0" transparent opacity={0.32} blending={THREE.AdditiveBlending} depthWrite={false} />
      </sprite>
    </group>
  );
}

function Ping({ pos, color, phase }) {
  const ring = useRef();
  const dot = useRef();
  useFrame((st) => {
    const t = ((st.clock.elapsedTime * 0.55 + phase) % 1 + 1) % 1;
    if (ring.current) {
      const s = 0.14 + t * 0.62;
      ring.current.scale.set(s, s, 1);
      ring.current.material.opacity = (1 - t) * 0.9;
    }
    if (dot.current) {
      const blink = 0.65 + Math.sin(st.clock.elapsedTime * 4 + phase * 20) * 0.35;
      dot.current.scale.setScalar(0.075);
      dot.current.material.opacity = blink;
    }
  });
  const normal = pos.clone().normalize();
  const quat = new THREE.Quaternion().setFromUnitVectors(new THREE.Vector3(0, 0, 1), normal);
  return (
    <group position={pos.clone().multiplyScalar(1.01)} quaternion={quat}>
      <sprite ref={dot}>
        <spriteMaterial map={getGlowTex()} color={color} transparent blending={THREE.AdditiveBlending} depthWrite={false} />
      </sprite>
      <sprite ref={ring}>
        <spriteMaterial map={getRingTex()} color={color} transparent blending={THREE.AdditiveBlending} depthWrite={false} opacity={0.8} />
      </sprite>
    </group>
  );
}

function Arc({ a, b, color }) {
  const dotRef = useRef();
  const curve = useMemo(() => {
    const mid = a.clone().add(b).multiplyScalar(0.5).normalize().multiplyScalar(R * (1.25 + a.distanceTo(b) * 0.09));
    return new THREE.QuadraticBezierCurve3(a.clone().multiplyScalar(1.005), mid, b.clone().multiplyScalar(1.005));
  }, [a, b]);
  const points = useMemo(() => curve.getPoints(40), [curve]);

  useFrame((st) => {
    if (!dotRef.current) return;
    const t = (st.clock.elapsedTime * 0.22 + (a.x + b.z) * 0.13) % 1;
    dotRef.current.position.copy(curve.getPoint(t < 0 ? t + 1 : t));
  });

  return (
    <group>
      <DreiLine points={points} color={color} lineWidth={0.7} transparent opacity={0.34} />
      <mesh ref={dotRef}>
        <sphereGeometry args={[0.02, 10, 10]} />
        <meshBasicMaterial color={color} transparent opacity={0.95} />
      </mesh>
    </group>
  );
}

function GlobeContent({ scans }) {
  const pings = useMemo(
    () =>
      scans.slice(0, 18).map((s, i) => {
        const { lat, lon } = scanPosition(s, i);
        return {
          pos: latLonToVec3(lat, lon, R),
          color: severityColor(s.score ?? s.threat_score ?? 50),
          phase: (i * 0.37) % 1,
        };
      }),
    [scans]
  );

  const arcs = useMemo(() => {
    const list = [];
    for (let i = 1; i < Math.min(pings.length, 11); i++) {
      list.push({ a: pings[i].pos, b: pings[i - 1].pos, color: pings[i].color });
    }
    return list;
  }, [pings]);

  return (
    <>
      <ambientLight intensity={1} />
      <GlobeMesh />
      {arcs.map((arc, i) => (
        <Arc key={`a${i}`} {...arc} />
      ))}
      {pings.map((p, i) => (
        <Ping key={`p${i}`} pos={p.pos} color={p.color} phase={p.phase} />
      ))}
      <OrbitControls
        enableZoom={false}
        enablePan={false}
        autoRotate
        autoRotateSpeed={1.1}
        minPolarAngle={Math.PI * 0.22}
        maxPolarAngle={Math.PI * 0.78}
      />
    </>
  );
}

export default function ThreatGlobeSection() {
  const [scans, setScans] = useState(SEED_SCANS);

  useEffect(() => {
    let alive = true;
    const load = () => {
      axios
        .get('/recent-scans')
        .then((res) => {
          const rows = (res.data.scans || []).filter((s) => s.url && s.url !== 'string');
          if (alive && rows.length) setScans(rows);
        })
        .catch(() => {});
    };
    load();
    const id = setInterval(load, 12000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const threats = scans.filter((s) => (s.score ?? s.threat_score ?? 0) >= 50).length;

  return (
    <section className="globe-section reveal" id="threat-radar">
      <h3 className="section-title">🌍 Live Threat Radar</h3>
      <div className="glass globe-stage">
        <Canvas camera={{ position: [0, 0.6, 5.4], fov: 42 }} dpr={[1, 2]} gl={{ antialias: true, alpha: true }}>
          <GlobeContent scans={scans} />
        </Canvas>
        <div className="globe-hud mono">
          <div className="hud-row">
            <span className="hud-key">SIGNALS</span>
            <span className="hud-val">{scans.length}</span>
          </div>
          <div className="hud-row">
            <span className="hud-key">HOSTILE</span>
            <span className="hud-val" style={{ color: '#ff3b5c' }}>{threats}</span>
          </div>
          <div className="hud-row">
            <span className="hud-key">STATUS</span>
            <span className="hud-val" style={{ color: '#2dd4a0' }}>TRACKING</span>
          </div>
        </div>
        <div className="globe-legend mono">
          <span><i style={{ background: '#ff3b5c' }} />CRITICAL</span>
          <span><i style={{ background: '#ff8a3d' }} />HIGH</span>
          <span><i style={{ background: '#ffc53d' }} />MEDIUM</span>
          <span><i style={{ background: '#2dd4a0' }} />SAFE</span>
        </div>
      </div>
    </section>
  );
}
