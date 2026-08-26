import { useEffect, useRef, useState } from 'react';

const STEPS = [
  { label: 'Resolving domain · TLS handshake', ms: 480 },
  { label: 'Fetching page headers', ms: 380 },
  { label: 'Extracting DOM structure', ms: 500 },
  { label: 'Running HTML heuristics engine', ms: 580 },
  { label: 'Ghost sandbox rendering page', ms: 860 },
  { label: 'Capturing evidence screenshot', ms: 420 },
  { label: 'Scoring behavioral ensemble', ms: 620 },
];

export default function ScanTheater({ active, failed }) {
  const [idx, setIdx] = useState(0);
  const [done, setDone] = useState(false);
  const timerRef = useRef(null);
  const bodyRef = useRef(null);

  useEffect(() => {
    if (active) {
      setIdx(0);
      setDone(false);
      let i = 0;
      const advance = () => {
        i += 1;
        setIdx(i);
        if (i < STEPS.length) {
          timerRef.current = setTimeout(advance, STEPS[i].ms);
        }
      };
      timerRef.current = setTimeout(advance, STEPS[0].ms);
    } else {
      clearTimeout(timerRef.current);
      setIdx((cur) => {
        if (!done && cur > 0) {
          setDone(true);
          return STEPS.length;
        }
        return cur;
      });
      if (!done) setDone(true);
    }
    return () => clearTimeout(timerRef.current);
  }, [active]);

  useEffect(() => {
    if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [idx]);

  return (
    <div className={`theater mono ${failed ? 'theater-fail' : ''}`}>
      <div className="theater-head">
        <span className="theater-title">SHIELDNETX PIPELINE</span>
        <span className="theater-led" />
      </div>
      <div className="theater-body" ref={bodyRef}>
        {STEPS.map((s, i) => {
          const isDone = done || i < idx;
          const isRunning = !done && active && i === idx;
          return (
            <div key={s.label} className={`t-line ${isDone ? 't-done' : isRunning ? 't-run' : ''}`}>
              <span className="t-mark">{isDone ? '✓' : isRunning ? '▸' : '·'}</span>
              <span className="t-label">{s.label}</span>
              <span className="t-status">
                {isDone ? 'OK' : isRunning ? <span className="t-dots">···</span> : ''}
              </span>
            </div>
          );
        })}
        {done && !failed && (
          <div className="t-line t-final t-done">
            <span className="t-mark">✓</span>
            <span className="t-label">Verdict ready</span>
            <span className="t-status">OK</span>
          </div>
        )}
        {failed && (
          <div className="t-line t-err">
            <span className="t-mark">✗</span>
            <span className="t-label">Engine unreachable — is the backend running?</span>
            <span className="t-status">FAIL</span>
          </div>
        )}
      </div>
    </div>
  );
}
