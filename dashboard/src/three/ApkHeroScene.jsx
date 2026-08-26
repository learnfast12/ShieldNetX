import { Canvas, useFrame } from '@react-three/fiber';
import { Float, RoundedBox, Sparkles } from '@react-three/drei';
import { EffectComposer, Bloom } from '@react-three/postprocessing';
import { useMemo, useRef } from 'react';
import * as THREE from 'three';

const RING_COLORS = ['#3E7BFA', '#8B5CF6', '#EC4899'];

function ScanRing({ radius, speed, yOffset }) {
  const ref = useRef();
  useFrame((state) => {
    if (!ref.current) return;
    const t = state.clock.elapsedTime;
    ref.current.position.y = Math.sin(t * speed) * yOffset;
    ref.current.rotation.z = t * 0.8;
  });
  return (
    <mesh ref={ref} rotation={[Math.PI / 2, 0, 0]}>
      <torusGeometry args={[radius, 0.02, 10, 90]} />
      <meshBasicMaterial color="#3E7BFA" transparent opacity={0.85} blending={THREE.AdditiveBlending} depthWrite={false} />
    </mesh>
  );
}

function ConvergingParticles({ count = 60 }) {
  const pointsRef = useRef();
  const data = useMemo(() => {
    const pos = new Float32Array(count * 3);
    const vel = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      const r = 3.2 + Math.random() * 2.2;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      pos[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      pos[i * 3 + 1] = r * Math.cos(phi) * 0.7;
      pos[i * 3 + 2] = r * Math.sin(phi) * Math.sin(theta);
      vel[i * 3] = -pos[i * 3] / (2.2 + Math.random() * 2);
      vel[i * 3 + 1] = -pos[i * 3 + 1] / (2.2 + Math.random() * 2);
      vel[i * 3 + 2] = -pos[i * 3 + 2] / (2.2 + Math.random() * 2);
    }
    return { pos, vel };
  }, [count]);

  useFrame((_, delta) => {
    if (!pointsRef.current) return;
    const attr = pointsRef.current.geometry.attributes.position;
    const arr = attr.array;
    for (let i = 0; i < arr.length; i += 3) {
      arr[i] += data.vel[i] * delta;
      arr[i + 1] += data.vel[i + 1] * delta;
      arr[i + 2] += data.vel[i + 2] * delta;
      const d = Math.hypot(arr[i], arr[i + 1], arr[i + 2]);
      if (d < 0.35) {
        const r = 4 + Math.random() * 2.4;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);
        arr[i] = r * Math.sin(phi) * Math.cos(theta);
        arr[i + 1] = r * Math.cos(phi) * 0.7;
        arr[i + 2] = r * Math.sin(phi) * Math.sin(theta);
      }
    }
    attr.needsUpdate = true;
  });

  return (
    <points ref={pointsRef}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[data.pos, 3]} />
      </bufferGeometry>
      <pointsMaterial size={0.055} color="#7AA6FF" transparent opacity={0.8} depthWrite={false} blending={THREE.AdditiveBlending} />
    </points>
  );
}

function Package({ draggingGlow }) {
  const shell = useRef();
  const group = useRef();

  useFrame((state, delta) => {
    if (shell.current) {
      shell.current.rotation.y -= delta * 0.22;
      shell.current.rotation.x += delta * 0.07;
    }
    if (group.current) {
      group.current.rotation.y = THREE.MathUtils.lerp(group.current.rotation.y, state.pointer.x * 0.45, 0.05);
      group.current.rotation.x = THREE.MathUtils.lerp(group.current.rotation.x, -state.pointer.y * 0.28, 0.05);
    }
  });

  return (
    <Float speed={1.7} rotationIntensity={0.18} floatIntensity={1}>
      <group ref={group}>
        {/* APK package */}
        <RoundedBox args={[1.5, 1.9, 0.55]} radius={0.14} smoothness={6}>
          <meshStandardMaterial
            color="#141c2e"
            metalness={0.72}
            roughness={0.24}
            emissive="#3E7BFA"
            emissiveIntensity={draggingGlow ? 0.5 : 0.16}
          />
        </RoundedBox>
        {/* glowing chip on the front face */}
        <mesh position={[0, 0.12, 0.29]}>
          <planeGeometry args={[0.78, 0.78]} />
          <meshBasicMaterial color="#3E7BFA" transparent opacity={0.32} blending={THREE.AdditiveBlending} depthWrite={false} />
        </mesh>
        <mesh position={[0, 0.12, 0.30]}>
          <torusGeometry args={[0.26, 0.035, 10, 48]} />
          <meshBasicMaterial color="#2DD4A0" blending={THREE.AdditiveBlending} depthWrite={false} />
        </mesh>

        {/* wireframe containment shell */}
        <mesh ref={shell} scale={2.05}>
          <icosahedronGeometry args={[1, 1]} />
          <meshBasicMaterial color="#8B5CF6" wireframe transparent opacity={0.22} />
        </mesh>

        {/* scanning laser rings */}
        <ScanRing radius={1.55} speed={0.9} yOffset={1.15} />
        <ScanRing radius={1.75} speed={0.62} yOffset={1.35} />

        {/* orbiting accent satellites */}
        <OrbitDot color="#EC4899" r={2.3} speed={0.55} tilt={[0.4, 0, 0.35]} size={0.06} />
        <OrbitDot color="#F59E0B" r={2.3} speed={0.55} tilt={[0.4, 0, 0.35]} size={0.045} offset={Math.PI * 0.66} />
        <OrbitDot color="#2DD4A0" r={2.3} speed={0.55} tilt={[0.4, 0, 0.35]} size={0.05} offset={Math.PI * 1.33} />
      </group>
    </Float>
  );
}

function OrbitDot({ color, r, speed, tilt, size, offset = 0 }) {
  const ref = useRef();
  useFrame((state) => {
    if (!ref.current) return;
    const t = state.clock.elapsedTime * speed + offset;
    const v = new THREE.Vector3(Math.cos(t) * r, Math.sin(t) * r * 0.42, Math.sin(t) * r);
    v.applyEuler(new THREE.Euler(...tilt));
    ref.current.position.copy(v);
  });
  return (
    <mesh ref={ref}>
      <sphereGeometry args={[size, 14, 14]} />
      <meshBasicMaterial color={color} />
    </mesh>
  );
}

export default function ApkHeroScene({ active = false }) {
  return (
    <div className="apk-hero-canvas">
      <Canvas camera={{ position: [0, 0, 6], fov: 50 }} dpr={[1, 1.75]} gl={{ antialias: true, alpha: true }}>
        <Package draggingGlow={active} />
        <ConvergingParticles />
        <Sparkles count={60} scale={7.5} size={2} speed={0.3} color="#8B5CF6" opacity={0.5} />
        <ambientLight intensity={0.45} />
        <pointLight position={[4, 4, 5]} intensity={26} color="#3E7BFA" />
        <pointLight position={[-5, -2, 3]} intensity={16} color="#EC4899" />
        <EffectComposer>
          <Bloom intensity={1.1} luminanceThreshold={0.13} luminanceSmoothing={0.85} mipmapBlur radius={0.7} />
        </EffectComposer>
      </Canvas>
    </div>
  );
}
