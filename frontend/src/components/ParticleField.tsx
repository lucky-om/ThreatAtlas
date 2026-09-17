import React, { useEffect, useRef } from 'react';

interface ParticleFieldProps {
  count?: number;
}

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  size: number;
  opacity: number;
  life: number;
  maxLife: number;
  color: string;
}

// Ember color palette
const EMBER_COLORS = [
  'rgba(255, 69,   0, ',   // OrangeRed
  'rgba(255, 107,  53, ',  // Ember orange
  'rgba(232, 25,  44, ',   // Crimson
  'rgba(255, 140,  0, ',   // Dark amber
  'rgba(255, 200, 120, ',  // Hot yellow-white
];

export const ParticleField: React.FC<ParticleFieldProps> = ({ count = 28 }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particlesRef = useRef<Particle[]>([]);
  const animFrameRef = useRef<number>(0);

  const spawnParticle = (width: number, height: number): Particle => {
    // Spawn from bottom — simulates rising embers
    const x = Math.random() * width;
    const y = height + 10;
    const color = EMBER_COLORS[Math.floor(Math.random() * EMBER_COLORS.length)];
    const maxLife = 140 + Math.random() * 180;
    return {
      x,
      y,
      vx: (Math.random() - 0.5) * 0.7,
      vy: -(0.4 + Math.random() * 0.9),
      size: 1.2 + Math.random() * 2.2,
      opacity: 0.5 + Math.random() * 0.5,
      life: 0,
      maxLife,
      color,
    };
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const resize = () => {
      canvas.width  = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize, { passive: true });

    // Pre-spawn particles distributed vertically
    particlesRef.current = Array.from({ length: count }, () => {
      const p = spawnParticle(canvas.width, canvas.height);
      // Scatter existing particles at random heights initially
      p.y = Math.random() * canvas.height;
      p.life = Math.random() * p.maxLife * 0.7;
      return p;
    });

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      particlesRef.current = particlesRef.current.map(p => {
        const progress = p.life / p.maxLife;
        const opacity = p.opacity * (1 - progress) * (progress < 0.1 ? progress * 10 : 1);

        // Draw ember particle
        ctx.save();
        ctx.globalAlpha = Math.max(0, opacity);
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size * (1 - progress * 0.5), 0, Math.PI * 2);

        // Glow effect
        const grd = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.size * 2.5);
        grd.addColorStop(0, `${p.color}1)`);
        grd.addColorStop(0.5, `${p.color}0.4)`);
        grd.addColorStop(1, `${p.color}0)`);
        ctx.fillStyle = grd;
        ctx.fill();
        ctx.restore();

        // Update position
        const newP = {
          ...p,
          x: p.x + p.vx + Math.sin(p.life * 0.05) * 0.3,
          y: p.y + p.vy,
          life: p.life + 1,
        };

        // Reset particle if expired
        if (newP.life >= newP.maxLife || newP.y < -20) {
          return spawnParticle(canvas.width, canvas.height);
        }
        return newP;
      });

      animFrameRef.current = requestAnimationFrame(draw);
    };

    animFrameRef.current = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(animFrameRef.current);
      window.removeEventListener('resize', resize);
    };
  }, [count]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 0,
        pointerEvents: 'none',
        opacity: 0.55,
      }}
      aria-hidden="true"
    />
  );
};
