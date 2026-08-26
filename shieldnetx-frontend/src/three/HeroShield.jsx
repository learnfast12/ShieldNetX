import { useEffect, useMemo, useRef, useState } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Float, Sparkles } from '@react-three/drei';
import { EffectComposer, Bloom, Vignette, ChromaticAberration, Noise } from '@react-three/postprocessing';
import * as THREE from 'three';

export const MODE_COLORS = {
  idle: '#3E7BFA',
  scanning: '#8B5CF6',
  warn: '#FFC53D',
  threat: '#FF3B5C',
  safe: '#2DD4A0',
};

const UP = new THREE.Vector3(0, 1, 0);
const tmpQ = new THREE.Quaternion();
const tmpV = new THREE.Vector3();

function shieldGeometry() {
  const s = new THREE.Shape();
  s.moveTo(0, 1.12);
  s.bezierCurveTo(0.42, 1.26, 0.92, 1.2, 1.02, 1.02);
  s.lineTo(1.02, 0.34);
  s.bezierCurveTo(1.02, -0.42, 0.56, -0.94, 0, -1.22);
  s.bezierCurveTo(-0.56, -0.94, -1.02, -0.42, -1.02, 0.34);
  s.lineTo(-1.02, 1.02);
  s.bezierCurveTo(-0.92, 1.2, -0.42, 1.26, 0, 1.12);
  const geo = new THREE.ExtrudeGeometry(s, {
    depth: 0.16,
    bevelEnabled: true,
    bevelThickness: 0.05,
    bevelSize: 0.05,
    bevelSegments: 4,
    curveSegments: 32,
  });
  geo.center();
  return geo;
}

function hexTexture() {
  const size = 512;
  const c = document.createElement('canvas');
  c.width = c.height = size;
  const g = c.getContext('2d');
  g.strokeStyle = '#ffffff';
  g.lineWidth = 2.2;
  const R = 24;
  const hw = Math.sqrt(3) * R;
  const vh = 1.5 * R;
  let row = 0;
  for (let y = -R; y < size + R; y += vh, row++) {
    for (let x = -R; x < size + R; x += hw) {
      const cx = x + (row % 2 ? hw / 2 : 0);
      g.beginPath();
      for (let i = 0; i < 6; i++) {
        const a = (Math.PI / 3) * i + Math.PI / 6;
        const px = cx + R * 0.94 * Math.cos(a);
        const py = y + R * 0.94 * Math.sin(a);
        i ? g.lineTo(px, py) : g.moveTo(px, py);
      }
      g.closePath();
      g.stroke();
    }
  }
  const t = new THREE.CanvasTexture(c);
  t.wrapS = t.wrapT = THREE.RepeatWrapping;
  return t;
}

function ShieldCore({ color }) {
  const core = useRef();
  const wire = useRef();
  useFrame((_, d) => {
    if (core.current) core.current.rotation.y += d * 0.7;
    if (wire.current) {
      wire.current.rotation.y -= d * 0.22;
      wire.current.rotation.x += d * 0.08;
    }
  });
  return (
    <group>
      <mesh ref={core}>
        <icosahedronGeometry args={[0.34, 1]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={2.2}
          roughness={0.15}
          metalness={0.6}
        />
      </mesh>
      <mesh ref={wire} scale={1.85}>
        <icosahedronGeometry args={[0.34, 1]} />
        <meshBasicMaterial color={color} wireframe transparent opacity={0.22} />
      </mesh>
      <pointLight intensity={9} distance={4} color={color} />
    </group>
  );
}

function ShieldFortress({ color, mode }) {
  const geo = useMemo(shieldGeometry, []);
  const group = useRef();
  const shellMat = useRef();
  const scanning = mode === 'scanning';

  useFrame((state, d) => {
    if (shellMat.current) {
      const pulse = mode === 'threat' ? 0.55 + Math.sin(state.clock.elapsedTime * 14) * 0.35 : 0.32;
      shellMat.current.emissiveIntensity = THREE.MathUtils.lerp(
        shellMat.current.emissiveIntensity,
        pulse,
        0.12
      );
    }
    if (group.current) {
      group.current.rotation.y = THREE.MathUtils.lerp(group.current.rotation.y, state.pointer.x * 0.45, 0.05);
      group.current.rotation.x = THREE.MathUtils.lerp(group.current.rotation.x, -state.pointer.y * 0.3, 0.05);
      group.current.scale.setScalar(THREE.MathUtils.lerp(group.current.scale.x, scanning ? 0.88 : 1, 0.06));
    }
  });

  return (
    <group ref={group}>
      <mesh geometry={geo}>
        <meshStandardMaterial
          ref={shellMat}
          color="#101a30"
          emissive={color}
          emissiveIntensity={0.32}
          metalness={0.85}
          roughness={0.24}
        />
      </mesh>
      <mesh geometry={geo} scale={1.04}>
        <meshBasicMaterial color={color} wireframe transparent opacity={scanning ? 0.4 : 0.16} />
      </mesh>
      <ShieldCore color={color} />
    </group>
  );
}

function HexBarrier({ color, mode }) {
  const tex = useMemo(hexTexture, []);
  const a = useRef();
  const b = useRef();

  useFrame((st, d) => {
    const t = st.clock.elapsedTime;
    if (a.current) {
      a.current.rotation.y += d * 0.05;
      const base = mode === 'threat' ? 0.62 : mode === 'warn' ? 0.5 : mode === 'safe' ? 0.42 : 0.48;
      const flicker =
        mode === 'threat'
          ? base * (0.72 + Math.abs(Math.sin(t * 21)) * 0.28)
          : base * (0.92 + Math.sin(t * 2.4) * 0.08);
      a.current.material.opacity = flicker;
    }
    if (b.current) {
      b.current.rotation.y -= d * 0.035;
      b.current.material.opacity =
        mode === 'threat'
          ? 0.3 * (0.6 + Math.abs(Math.sin(t * 17)) * 0.4)
          : 0.18 + Math.sin(t * 1.7 + 2) * 0.05;
    }
  });

  return (
    <group rotation={[0.12, 0, 0.06]}>
      <mesh ref={a} scale={1.78}>
        <sphereGeometry args={[1.35, 48, 48]} />
        <meshBasicMaterial
          color={color}
          alphaMap={tex}
          transparent
          opacity={0.48}
          side={THREE.DoubleSide}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
        />
      </mesh>
      <mesh ref={b} scale={2.02}>
        <sphereGeometry args={[1.35, 40, 40]} />
        <meshBasicMaterial
          color={color}
          alphaMap={tex}
          transparent
          opacity={0.18}
          side={THREE.DoubleSide}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
        />
      </mesh>
    </group>
  );
}

function AlarmArc({ color, radius, speed, theta, opacity }) {
  const ref = useRef();
  useFrame((st, d) => {
    if (!ref.current) return;
    ref.current.rotation.z += d * speed;
    ref.current.rotation.y = Math.sin(st.clock.elapsedTime * 0.7) * 0.5;
  });
  return (
    <mesh ref={ref} rotation={[Math.PI / 2.15, 0, 0]}>
      <ringGeometry args={[radius, radius + 0.025, 80, 1, 0, theta]} />
      <meshBasicMaterial
        color={color}
        transparent
        opacity={opacity}
        side={THREE.DoubleSide}
        blending={THREE.AdditiveBlending}
        depthWrite={false}
      />
    </mesh>
  );
}

function AlarmArcs({ mode, color }) {
  if (mode !== 'threat' && mode !== 'warn') return null;
  return (
    <>
      <AlarmArc color={mode === 'threat' ? '#FF3B5C' : '#FFC53D'} radius={2.35} speed={1.6} theta={Math.PI * 0.55} opacity={0.8} />
      <AlarmArc color={mode === 'threat' ? '#FF3B5C' : '#FFC53D'} radius={2.55} speed={-1.1} theta={Math.PI * 0.35} opacity={0.6} />
    </>
  );
}

function ScanSweep({ color }) {
  const ref = useRef();
  useFrame((st) => {
    const t = st.clock.elapsedTime;
    if (!ref.current) return;
    ref.current.position.y = Math.sin(t * 1.7) * 1.2;
    ref.current.rotation.z = t * 0.5;
    ref.current.material.opacity = 0.4 + Math.sin(t * 7) * 0.14;
  });
  return (
    <mesh ref={ref} rotation={[Math.PI / 2, 0, 0]}>
      <torusGeometry args={[1.52, 0.009, 6, 90]} />
      <meshBasicMaterial color={color} transparent blending={THREE.AdditiveBlending} depthWrite={false} />
    </mesh>
  );
}

const DART_COUNT = 34;
const FLASH_COUNT = 12;

function AttackDarts({ mode }) {
  const meshes = useRef([]);
  const flashes = useRef([]);
  const st = useRef({ timer: 0.5 }).current;

  const darts = useMemo(
    () =>
      Array.from({ length: DART_COUNT }, () => ({
        pos: new THREE.Vector3(),
        vel: new THREE.Vector3(),
        life: 0,
        active: false,
      })),
    []
  );

  const flashState = useMemo(
    () => Array.from({ length: FLASH_COUNT }, () => ({ pos: new THREE.Vector3(), t: -1, color: new THREE.Color() })),
    []
  );

  const fireFlash = (pos, colorHex, big = true) => {
    const slot = flashState.find((f) => f.t < 0);
    if (!slot) return;
    slot.pos.copy(pos);
    slot.t = 0;
    slot.color.set(colorHex);
    slot.big = big;
  };

  const rateByMode = { idle: 2.9, scanning: 1.15, warn: 0.75, threat: 0.34, safe: 1.7 };
  const dartColor = mode === 'safe' ? '#7fb2ff' : '#ff4b66';

  useFrame((s, delta) => {
    st.timer -= delta;
    if (st.timer <= 0 && mode !== 'scanning') {
      spawnDart(darts);
      st.timer = (rateByMode[mode] || 2.5) * (0.6 + Math.random() * 0.8);
    } else if (st.timer <= 0) {
      for (let k = 0; k < 2; k++) spawnDart(darts);
      st.timer = rateByMode.scanning * (0.6 + Math.random() * 0.8);
    }

    const barrierR = mode === 'safe' ? Infinity : 1.66;
    const dissolveR = 2.55;

    darts.forEach((d, i) => {
      const m = meshes.current[i];
      if (!m) return;
      if (!d.active) {
        m.visible = false;
        return;
      }
      m.visible = true;
      d.pos.addScaledVector(d.vel, delta);
      m.position.copy(d.pos);
      m.quaternion.copy(tmpQ.setFromUnitVectors(UP, tmpV.copy(d.vel).normalize()));
      const dist = d.pos.length();

      if (dist <= barrierR && d.life === 0) {
        fireFlash(d.pos, mode === 'idle' || mode === 'scanning' ? '#b39dff' : dartColor);
        if (mode === 'idle' || mode === 'scanning') {
          d.vel.reflect(tmpV.copy(d.pos).normalize()).multiplyScalar(0.42);
          d.life = 0.0001;
        } else {
          d.active = false;
          m.visible = false;
        }
      } else if (dist <= dissolveR && mode === 'safe') {
        fireFlash(d.pos, '#2DD4A0', false);
        d.active = false;
        m.visible = false;
      }

      if (d.life > 0) {
        d.life += delta;
        if (d.life > 0.5) {
          d.active = false;
          m.visible = false;
        } else {
          m.material.opacity = 1 - d.life / 0.5;
        }
      }
      if (d.pos.length() > 15) {
        d.active = false;
        m.visible = false;
      }
    });

    flashState.forEach((f, i) => {
      const sp = flashes.current[i];
      if (!sp) return;
      if (f.t < 0) {
        sp.visible = false;
        return;
      }
      f.t += delta;
      const dur = f.big ? 0.38 : 0.5;
      const p = f.t / dur;
      if (p >= 1) {
        f.t = -1;
        sp.visible = false;
        return;
      }
      sp.visible = true;
      sp.position.copy(f.pos);
      const sc = (f.big ? 0.18 : 0.12) + p * (f.big ? 1.05 : 0.5);
      sp.scale.setScalar(sc);
      sp.material.color.copy(f.color);
      sp.material.opacity = (1 - p) * 0.95;
    });
  });

  function spawnDart(arr) {
    const d = arr.find((x) => !x.active);
    if (!d) return;
    const dir = new THREE.Vector3().randomDirection();
    d.pos.copy(dir).multiplyScalar(7.5 + Math.random() * 2);
    const aim = new THREE.Vector3().randomDirection().multiplyScalar(0.35);
    d.vel.copy(aim.sub(d.pos)).normalize().multiplyScalar(3 + Math.random() * 1.8);
    d.life = 0;
    d.active = true;
  }

  return (
    <group>
      {darts.map((_, i) => (
        <mesh key={`d${i}`} ref={(el) => (meshes.current[i] = el)} visible={false}>
          <coneGeometry args={[0.032, 0.17, 6]} />
          <meshBasicMaterial
            color={dartColor}
            transparent
            blending={THREE.AdditiveBlending}
            depthWrite={false}
          />
        </mesh>
      ))}
      {flashState.map((_, i) => (
        <sprite key={`f${i}`} ref={(el) => (flashes.current[i] = el)} visible={false}>
          <circleGeometry args={[0.5, 24]} />
          <spriteMaterial
            color="#ffffff"
            transparent
            blending={THREE.AdditiveBlending}
            depthWrite={false}
          />
        </sprite>
      ))}
    </group>
  );
}

function Shockwave({ trigger }) {
  const ref = useRef();
  const anim = useRef(null);

  useEffect(() => {
    if (trigger.count > 0) anim.current = { t: 0 };
  }, [trigger]);

  useFrame((_, d) => {
    if (!anim.current || !ref.current) return;
    anim.current.t += d * 1.35;
    const t = anim.current.t;
    if (t >= 1) {
      anim.current = null;
      ref.current.visible = false;
      return;
    }
    ref.current.visible = true;
    const sc = 0.5 + t * 5.2;
    ref.current.scale.set(sc, sc, sc);
    ref.current.material.opacity = 0.85 * (1 - t) * (1 - t);
  });

  return (
    <mesh ref={ref} rotation={[Math.PI / 2.3, 0.2, 0]} visible={false}>
      <torusGeometry args={[1, 0.014, 8, 100]} />
      <meshBasicMaterial color={trigger.color} transparent blending={THREE.AdditiveBlending} depthWrite={false} />
    </mesh>
  );
}

function CameraRig({ shakeRef }) {
  useFrame(({ camera }) => {
    camera.position.x = THREE.MathUtils.lerp(camera.position.x, 0, 0.07);
    camera.position.y = THREE.MathUtils.lerp(camera.position.y, 0, 0.07);
    if (shakeRef.current > 0.002) {
      camera.position.x += (Math.random() - 0.5) * shakeRef.current;
      camera.position.y += (Math.random() - 0.5) * shakeRef.current;
      shakeRef.current *= 0.86;
    }
  });
  return null;
}

function Scene({ mode }) {
  const color = MODE_COLORS[mode] || MODE_COLORS.idle;
  const prevMode = useRef(mode);
  const shakeRef = useRef(0);
  const [shock, setShock] = useState({ count: 0, color: MODE_COLORS.safe });

  useEffect(() => {
    if (prevMode.current === 'scanning' && mode !== 'scanning') {
      setShock((s) => ({ count: s.count + 1, color: MODE_COLORS[mode] || MODE_COLORS.idle }));
      if (mode === 'threat' || mode === 'warn') shakeRef.current = 0.085;
    }
    prevMode.current = mode;
  }, [mode]);

  return (
    <>
      <Float speed={1.5} rotationIntensity={0.1} floatIntensity={0.8}>
        <ShieldFortress color={color} mode={mode} />
        <HexBarrier color={color} mode={mode} />
        <AlarmArcs mode={mode} color={color} />
        {mode === 'scanning' && <ScanSweep color={color} />}
      </Float>

      <AttackDarts mode={mode} />
      <Shockwave trigger={shock} />

      <Sparkles count={90} scale={8} size={2.4} speed={0.4} color={color} opacity={0.5} />

      <ambientLight intensity={0.45} />
      <pointLight position={[4, 4, 4]} intensity={34} color={color} />
      <pointLight position={[-5, -3, 3]} intensity={20} color="#EC4899" />
      <pointLight position={[0, 2, -6]} intensity={14} color="#3E7BFA" />

      <CameraRig shakeRef={shakeRef} />

      <EffectComposer>
        <Bloom intensity={1.25} luminanceThreshold={0.12} luminanceSmoothing={0.85} mipmapBlur radius={0.75} />
        <ChromaticAberration offset={[0.00045, 0.0007]} radialModulation modulationOffset={0.4} />
        <Noise opacity={0.05} />
        <Vignette eskil={false} offset={0.22} darkness={0.62} />
      </EffectComposer>
    </>
  );
}

export default function HeroShield({ mode = 'idle' }) {
  return (
    <div className="hero-shield-canvas">
      <Canvas
        camera={{ position: [0, 0, 6], fov: 50 }}
        dpr={[1, 2]}
        gl={{ antialias: true, alpha: true, powerPreference: 'high-performance' }}
      >
        <Scene mode={mode} />
      </Canvas>
    </div>
  );
}
