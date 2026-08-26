import { Suspense, lazy, useEffect, useMemo, useRef, useState } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Html, PresentationControls } from '@react-three/drei';
import * as THREE from 'three';

export const scoreColor = (score) => {
  if (score >= 75) return '#ff3b5c';
  if (score >= 50) return '#ff8a3d';
  if (score >= 30) return '#ffc53d';
  return '#2dd4a0';
};

function Constellation({ signals }) {
  const N = Math.max(signals.length, 3);
  const ready = useRef(false);
  const cur = useRef(new Array(N).fill(0));
  const group = useRef();

  useEffect(() => {
    const t = setTimeout(() => {
      ready.current = true;
    }, 350);
    return () => clearTimeout(t);
  }, []);

  const targets = useMemo(
    () => signals.map((s) => Math.min(Math.max(s.score / s.max, 0), 1)),
    [signals]
  );

  const { fanGeom, loopGeom, spokeGeom } = useMemo(() => {
    const mk = (n) => {
      const g = new THREE.BufferGeometry();
      g.setAttribute('position', new THREE.BufferAttribute(new Float32Array(n * 3), 3));
      return g;
    };
    const fan = mk(N + 1);
    const idx = [];
    for (let i = 1; i <= N; i++) idx.push(0, i, i === N ? 1 : i + 1);
    fan.setIndex(idx);
    const loop = mk(N);
    const spokes = mk(N * 2);
    return { fanGeom: fan, loopGeom: loop, spokeGeom: spokes };
  }, [N]);

  const dirs = useMemo(
    () =>
      Array.from({ length: N }, (_, i) => {
        const a = -Math.PI / 2 + (i * 2 * Math.PI) / N;
        return new THREE.Vector2(Math.cos(a), Math.sin(a));
      }),
    [N]
  );

  const nodeRefs = useRef([]);
  const coreRef = useRef();
  const avgRisk = useMemo(() => {
    if (!signals.length) return 0;
    return (signals.reduce((a, s) => a + s.score / s.max, 0) / signals.length) * 100;
  }, [signals]);

  const loopObj = useMemo(
    () =>
      new THREE.LineLoop(
        loopGeom,
        new THREE.LineBasicMaterial({ color: '#9db1ff', transparent: true, opacity: 0.85 })
      ),
    [loopGeom]
  );

  useFrame((st, delta) => {
    const k = Math.min(1, delta * 3.2);
    const pos = st.clock.elapsedTime;
    for (let i = 0; i < N; i++) {
      const target = ready.current ? targets[i] || 0 : 0;
      cur.current[i] += (target - cur.current[i]) * k;
      const wob = Math.sin(pos * 1.6 + i * 1.7) * 0.02;
      const r = 0.28 + cur.current[i] * 1.52 + wob;
      const x = dirs[i].x * r;
      const y = dirs[i].y * r;

      fanGeom.attributes.position.setXYZ(i + 1, x, y, 0);
      loopGeom.attributes.position.setXYZ(i, x, y, 0);
      spokeGeom.attributes.position.setXYZ(i * 2, 0, 0, 0);
      spokeGeom.attributes.position.setXYZ(i * 2 + 1, x, y, 0);

      const node = nodeRefs.current[i];
      if (node) {
        node.position.set(x, y, 0);
        const pulse = 1 + Math.sin(pos * 3 + i) * 0.12;
        node.scale.setScalar(pulse);
        node.material.color.set(scoreColor(cur.current[i] * 100));
      }
    }
    fanGeom.attributes.position.needsUpdate = true;
    loopGeom.attributes.position.needsUpdate = true;
    spokeGeom.attributes.position.needsUpdate = true;

    if (coreRef.current) {
      const heat = cur.current.reduce((a, b) => a + b, 0) / N;
      coreRef.current.material.color.lerpColors(
        new THREE.Color('#2dd4a0'),
        new THREE.Color('#ff3b5c'),
        heat
      );
      coreRef.current.scale.setScalar(0.14 + heat * 0.1 + Math.sin(pos * 4) * 0.008);
    }

    if (group.current) group.current.rotation.z += delta * 0.05;
  });

  const levelColor = scoreColor(avgRisk);

  return (
    <group ref={group} rotation={[0, 0, 0]}>
      <group rotation={[0.42, 0, 0]}>
        <mesh geometry={fanGeom}>
          <meshBasicMaterial color="#4a6cf0" transparent opacity={0.13} side={THREE.DoubleSide} depthWrite={false} />
        </mesh>
        <lineSegments>
          <primitive object={spokeGeom} attach="geometry" />
          <lineBasicMaterial color="#6f86ff" transparent opacity={0.35} />
        </lineSegments>

        <primitive object={loopObj} />

        {[0.62, 1.18, 1.74].map((r, i) => (
          <mesh key={i} rotation={[Math.PI / 2, 0, 0]}>
            <torusGeometry args={[r, 0.0035, 5, 72]} />
            <meshBasicMaterial color="#3E7BFA" transparent opacity={0.12} depthWrite={false} />
          </mesh>
        ))}

        <mesh ref={coreRef}>
          <sphereGeometry args={[1, 16, 16]} />
          <meshBasicMaterial color={levelColor} transparent opacity={0.95} blending={THREE.AdditiveBlending} depthWrite={false} />
        </mesh>

        {signals.map((s, i) => (
          <mesh key={s.name} ref={(el) => (nodeRefs.current[i] = el)} position={[dirs[i].x * 0.28, dirs[i].y * 0.28, 0]}>
            <sphereGeometry args={[0.06, 14, 14]} />
            <meshBasicMaterial color="#ffffff" transparent opacity={0.95} />
          </mesh>
        ))}

        {signals.map((s, i) => (
          <Html key={`l${s.name}`} position={[dirs[i].x * 2.25, dirs[i].y * 2.25, 0]} center zIndexRange={[10, 0]}>
            <div className="const-label mono">
              <span className="cl-name">{s.name}</span>
              <span className="cl-val" style={{ color: scoreColor((s.score / s.max) * 100) }}>
                {s.score}/{s.max}
              </span>
            </div>
          </Html>
        ))}
      </group>
    </group>
  );
}

export default function SignalConstellation({ signals }) {
  if (!signals || signals.length < 3) return null;
  return (
    <div className="const-canvas">
      <Canvas camera={{ position: [0, 0, 4.6], fov: 46 }} dpr={[1, 2]} gl={{ antialias: true, alpha: true }}>
        <Suspense fallback={null}>
          <PresentationControls global snap mass={0.6} tension={120} friction={22} polar={[-0.4, 0.4]} azimuth={[-0.6, 0.6]}>
            <Constellation signals={signals} />
          </PresentationControls>
        </Suspense>
      </Canvas>
    </div>
  );
}
