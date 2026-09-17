import React, { useRef, useState } from 'react';
import { motion, useMotionValue, useTransform, useSpring, useMotionTemplate } from 'framer-motion';

interface TiltWrapperProps {
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
  maxRotation?: number; // max degrees of rotation (e.g. 5)
  perspective?: number;
  scaleOnHover?: number;
}

export const TiltWrapper: React.FC<TiltWrapperProps> = ({
  children,
  className = '',
  style = {},
  maxRotation = 2,
  perspective = 1500,
  scaleOnHover = 1.005,
}) => {
  const ref = useRef<HTMLDivElement>(null);
  const [isHovered, setIsHovered] = useState(false);

  const x = useMotionValue(0);
  const y = useMotionValue(0);

  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);

  // Smooth out the motion values for the tilt
  const mouseXSpring = useSpring(x, { stiffness: 300, damping: 30 });
  const mouseYSpring = useSpring(y, { stiffness: 300, damping: 30 });

  // Map the mouse values to rotation values
  const rotateX = useTransform(mouseYSpring, [-0.5, 0.5], [maxRotation, -maxRotation]);
  const rotateY = useTransform(mouseXSpring, [-0.5, 0.5], [-maxRotation, maxRotation]);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!ref.current) return;
    
    const rect = ref.current.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;
    
    const mX = e.clientX - rect.left;
    const mY = e.clientY - rect.top;
    
    mouseX.set(mX);
    mouseY.set(mY);
    
    const xPct = (mX / width) - 0.5;
    const yPct = (mY / height) - 0.5;
    
    x.set(xPct);
    y.set(yPct);
  };

  const handleMouseEnter = () => setIsHovered(true);
  const handleMouseLeave = () => {
    setIsHovered(false);
    x.set(0);
    y.set(0);
  };

  return (
    <motion.div
      ref={ref}
      className={`tilt-perspective ${className}`}
      onMouseMove={handleMouseMove}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      whileHover={{ scale: scaleOnHover }}
      style={{
        perspective,
        ...style,
        position: 'relative',
        borderRadius: '12px',
        border: '1px solid var(--border-subtle)',
        background: 'var(--surface)',
        overflow: 'hidden'
      }}
    >
      {/* Spotlight Overlay */}
      <motion.div
        animate={{ opacity: isHovered ? 1 : 0 }}
        style={{
          position: 'absolute',
          top: 0, left: 0, right: 0, bottom: 0,
          pointerEvents: 'none',
          borderRadius: 'inherit',
          transition: 'opacity 0.3s ease',
          background: useMotionTemplate`
            radial-gradient(
              650px circle at ${mouseX}px ${mouseY}px,
              rgba(255,255,255,0.05),
              transparent 80%
            )
          `,
          zIndex: 10,
        }}
      />
      <motion.div
        className="tilt-element"
        style={{
          rotateX,
          rotateY,
          width: '100%',
          height: '100%',
          position: 'relative',
          zIndex: 1,
        }}
      >
        <div className="tilt-content" style={{ width: '100%', height: '100%' }}>
          {children}
        </div>
      </motion.div>
    </motion.div>
  );
};
