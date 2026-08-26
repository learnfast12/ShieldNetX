import { useEffect, useState } from 'react';

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <nav className={`nav ${scrolled ? 'nav-scrolled' : ''}`}>
      <div className="nav-inner">
        <a href="#top" className="brand">
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none">
            <defs>
              <linearGradient id="lg-brand" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor="#3E7BFA" />
                <stop offset="55%" stopColor="#8B5CF6" />
                <stop offset="100%" stopColor="#EC4899" />
              </linearGradient>
            </defs>
            <path
              d="M12 2 L20 5.5 V11.5 C20 16.8 16.6 20.6 12 22 C7.4 20.6 4 16.8 4 11.5 V5.5 Z"
              stroke="url(#lg-brand)"
              strokeWidth="1.8"
              fill="rgba(62,123,250,0.12)"
            />
            <path d="M8.6 11.8 L11 14.3 L15.6 9.4" stroke="#2DD4A0" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span className="grad-text brand-name">ShieldNetX</span>
        </a>
        <div className="nav-links">
          <a href="#scan">Scan</a>
          <a href="#stats">Stats</a>
          <a href="#threat-radar">Threat Radar</a>
          <a href="#recent">Recent</a>
        </div>
        <div className="nav-live">
          <span className="live-dot" />
          Engines Online
        </div>
      </div>
    </nav>
  );
}
