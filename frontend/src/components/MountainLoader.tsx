/**
 * MountainLoader — ThreatAtlas signature loading animation
 * Animated SVG mountain peaks rising with crimson glow — matches the logo.
 * Coded by Lucky · v1.0
 */
import React from 'react';
import { motion } from 'framer-motion';

interface MountainLoaderProps {
  /** Label shown below animation */
  label?: string;
  /** Subtext (e.g. scan target) */
  sublabel?: string;
  /** Scan type changes the accent color */
  scanType?: 'file' | 'url' | 'domain' | 'ip' | 'default';
  /** Extra wrapper style */
  style?: React.CSSProperties;
}

// Scan-type colors — all in Inferno palette
const SCAN_COLORS: Record<string, string> = {
  file:    '#ff4500',
  url:     '#ff8c00',
  domain:  '#e8192c',
  ip:      '#ff6b35',
  default: '#ff4500',
};

const SCAN_GLOWS: Record<string, string> = {
  file:    'rgba(255,  69,  0, 0.4)',
  url:     'rgba(255, 140,  0, 0.4)',
  domain:  'rgba(232,  25, 44, 0.4)',
  ip:      'rgba(255, 107, 53, 0.4)',
  default: 'rgba(255,  69,  0, 0.4)',
};

// Mountain path data: [points as SVG polygon string, delay in seconds]
const PEAKS = [
  { d: 'M60,120 L130,20 L200,120',  delay: 0,    color: '#f0f0f0', glow: false },
  { d: 'M0,120 L80,50 L140,120',    delay: 0.15, color: '#c8c8cc', glow: false },
  { d: 'M100,120 L175,10 L250,120', delay: 0.08, color: '#ffffff', glow: true  },
  { d: 'M140,120 L210,55 L280,120', delay: 0.22, color: '#d0d0d8', glow: false },
];

export const MountainLoader: React.FC<MountainLoaderProps> = ({
  label = 'Scanning…',
  sublabel,
  scanType = 'default',
  style,
}) => {
  const color = SCAN_COLORS[scanType] ?? SCAN_COLORS.default;
  const glow  = SCAN_GLOWS[scanType]  ?? SCAN_GLOWS.default;

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      gap: '0px',
      ...style,
    }}>
      {/* ── SVG Mountain Scene ── */}
      <div style={{ position: 'relative', width: '280px', height: '130px' }}>
        {/* Ambient glow behind peaks */}
        <motion.div
          animate={{ opacity: [0.3, 0.7, 0.3], scale: [1, 1.05, 1] }}
          transition={{ repeat: Infinity, duration: 2.8, ease: 'easeInOut' }}
          style={{
            position: 'absolute',
            bottom: '0',
            left: '50%',
            transform: 'translateX(-50%)',
            width: '180px',
            height: '60px',
            borderRadius: '50%',
            background: `radial-gradient(ellipse at center, ${glow} 0%, transparent 70%)`,
            filter: 'blur(12px)',
            zIndex: 0,
          }}
        />

        {/* Globe/world circle behind peaks — matches logo */}
        <motion.div
          animate={{ opacity: [0.12, 0.22, 0.12] }}
          transition={{ repeat: Infinity, duration: 3.5, ease: 'easeInOut' }}
          style={{
            position: 'absolute',
            top: '0',
            left: '50%',
            transform: 'translateX(-50%)',
            width: '120px',
            height: '120px',
            borderRadius: '50%',
            border: `1.5px solid ${color}`,
            opacity: 0.18,
            zIndex: 0,
          }}
        />

        {/* Crosshair lines (compass rose) — matches logo */}
        <svg
          viewBox="0 0 280 130"
          style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', zIndex: 1 }}
          fill="none"
        >
          {/* Compass tick marks */}
          <line x1="140" y1="0"   x2="140" y2="12"  stroke={color} strokeWidth="1.5" opacity="0.35" />
          <line x1="140" y1="118" x2="140" y2="130" stroke={color} strokeWidth="1.5" opacity="0.35" />
          <line x1="0"   y1="65"  x2="12"  y2="65"  stroke={color} strokeWidth="1.5" opacity="0.35" />
          <line x1="268" y1="65"  x2="280" y2="65"  stroke={color} strokeWidth="1.5" opacity="0.35" />

          {/* Globe circle */}
          <circle cx="140" cy="65" r="55" stroke={color} strokeWidth="1" strokeDasharray="4 6" opacity="0.20" />

          {/* Mountain peaks: back layers first */}
          {PEAKS.map((peak, i) => (
            <motion.polygon
              key={i}
              points={peak.d.replace(/M(\S+),(\S+) L(\S+),(\S+) L(\S+),(\S+)/, (_, x1, y1, x2, y2, x3, y3) =>
                `${x1},${y1} ${x2},${y2} ${x3},${y3}`
              )}
              fill={i === 0 || i === 3 ? 'rgba(30,30,40,0.9)' : 'rgba(40,40,55,0.95)'}
              stroke={peak.glow ? color : 'rgba(200,200,220,0.25)'}
              strokeWidth={peak.glow ? '1.5' : '1'}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: peak.delay, duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
              style={{ filter: peak.glow ? `drop-shadow(0 0 6px ${color})` : undefined }}
            />
          ))}

          {/* Glowing peak line (main summit) */}
          <motion.line
            x1="175" y1="10" x2="175" y2="10"
            animate={{ x2: 175, y2: [10, 4, 10] }}
            transition={{ repeat: Infinity, duration: 2, ease: 'easeInOut' }}
            stroke={color}
            strokeWidth="2"
            strokeLinecap="round"
            opacity="0.9"
          />

          {/* Summit glow dot */}
          <motion.circle
            cx="175" cy="10" r="2.5"
            fill={color}
            animate={{ r: [2.5, 4, 2.5], opacity: [1, 0.6, 1] }}
            transition={{ repeat: Infinity, duration: 1.8, ease: 'easeInOut' }}
            style={{ filter: `drop-shadow(0 0 4px ${color})` }}
          />

          {/* Base line */}
          <line x1="0" y1="120" x2="280" y2="120" stroke="rgba(255,255,255,0.06)" strokeWidth="1" />
        </svg>

        {/* Terrain scan line sweeping across */}
        <motion.div
          animate={{ x: ['-100%', '200%'] }}
          transition={{ repeat: Infinity, duration: 2.4, ease: 'easeInOut', repeatDelay: 0.8 }}
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: '40%',
            height: '100%',
            background: `linear-gradient(90deg, transparent, ${color}18, transparent)`,
            zIndex: 2,
            pointerEvents: 'none',
          }}
        />
      </div>

      {/* ── Labels ── */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4, duration: 0.5 }}
        style={{ textAlign: 'center', marginTop: '12px' }}
      >
        <div style={{
          fontFamily: 'var(--font-display)',
          fontSize: '13px',
          fontWeight: 700,
          color,
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
          filter: `drop-shadow(0 0 8px ${glow})`,
        }}>
          {label}
        </div>
        {sublabel && (
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            color: 'var(--text-3)',
            marginTop: '5px',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            maxWidth: '260px',
          }}>
            {sublabel}
          </div>
        )}
      </motion.div>
    </div>
  );
};
