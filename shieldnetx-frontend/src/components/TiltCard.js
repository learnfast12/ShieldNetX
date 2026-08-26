import { useRef, useState } from 'react';

export default function TiltCard({ children, className = '', max = 7 }) {
  const ref = useRef(null);
  const [transform, setTransform] = useState('');

  const onMove = (e) => {
    const r = ref.current.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width;
    const py = (e.clientY - r.top) / r.height;
    ref.current.style.setProperty('--mx', `${(px * 100).toFixed(1)}%`);
    ref.current.style.setProperty('--my', `${(py * 100).toFixed(1)}%`);
    setTransform(`perspective(1000px) rotateY(${(px - 0.5) * max * 2}deg) rotateX(${-(py - 0.5) * max * 2}deg)`);
  };

  return (
    <div
      ref={ref}
      className={`glass tilt-wrap ${className}`}
      style={{ transform }}
      onMouseMove={onMove}
      onMouseLeave={() => setTransform('')}
    >
      {children}
    </div>
  );
}
