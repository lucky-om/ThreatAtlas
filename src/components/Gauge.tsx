import React, { useEffect, useState } from 'react';

interface GaugeProps {
  score: number;
  total: number;
  size?: number;
}

export const Gauge: React.FC<GaugeProps> = ({ score, total, size = 200 }) => {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    const duration = 1500;
    const steps = 60;
    const stepTime = Math.abs(Math.floor(duration / steps));
    let currentStep = 0;
    
    const timer = setInterval(() => {
      currentStep++;
      const progress = currentStep / steps;
      const easeProgress = 1 - Math.pow(1 - progress, 4); // Quartic ease out
      setAnimatedScore(Math.round(score * easeProgress));
      
      if (currentStep >= steps) {
        clearInterval(timer);
        setAnimatedScore(score);
      }
    }, stepTime);
    
    return () => clearInterval(timer);
  }, [score]);

  const strokeWidth = 16;
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const strokeDashoffset = circumference - (animatedScore / (total || 1)) * circumference;

  let color = 'var(--primary)'; // Cyan for safe
  let shadowColor = 'rgba(0, 242, 255, 0.5)';
  
  if (score > 0) {
    if (score < 5) {
      color = 'var(--warning)'; // Orange/Yellow
      shadowColor = 'rgba(255, 179, 178, 0.5)';
    } else {
      color = 'var(--secondary)'; // Crimson for danger
      shadowColor = 'rgba(255, 0, 60, 0.5)';
    }
  }

  return (
    <div style={{ position: 'relative', width: size, height: size, margin: '0 auto', filter: `drop-shadow(0 0 16px ${shadowColor})` }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="rgba(255,255,255,0.05)"
          strokeWidth={strokeWidth}
          fill="none"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth={strokeWidth}
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.1s ease-out', transform: 'rotate(-90deg)', transformOrigin: '50% 50%' }}
        />
      </svg>
      <div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <span className="font-display-lg" style={{ color: color, lineHeight: 1, textShadow: `0 0 10px ${shadowColor}` }}>{animatedScore}</span>
        <span className="font-label-caps" style={{ color: 'var(--on-surface-variant)', marginTop: '8px' }}>/ {total}</span>
      </div>
    </div>
  );
};
