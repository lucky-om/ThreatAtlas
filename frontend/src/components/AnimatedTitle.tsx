import React from 'react';
import { motion } from 'framer-motion';

interface AnimatedTitleProps {
  text: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
  delay?: number;
  as?: 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6' | 'span' | 'div';
}

export const AnimatedTitle: React.FC<AnimatedTitleProps> = ({ 
  text, 
  className = '', 
  style = {}, 
  delay = 0,
  as = 'h1'
}) => {
  const Component = motion[as as keyof typeof motion] as React.ElementType;

  // We handle strings by splitting into words for a staggered word-by-word reveal.
  // If it's a ReactNode (like text mixed with a span), we just animate the whole block,
  // or the consumer can pass raw strings and wrap specific words in the parent.
  
  if (typeof text === 'string') {
    const words = text.split(' ');
    
    const container = {
      hidden: { opacity: 0 },
      visible: (i = 1) => ({
        opacity: 1,
        transition: { staggerChildren: 0.08, delayChildren: delay * i },
      }),
    };

    const child = {
      visible: {
        opacity: 1,
        y: 0,
        filter: 'blur(0px)',
        transition: {
          type: "spring" as const,
          damping: 12,
          stiffness: 100,
        },
      },
      hidden: {
        opacity: 0,
        y: 20,
        filter: 'blur(8px)',
        transition: {
          type: "spring" as const,
          damping: 12,
          stiffness: 100,
        },
      },
    };

    return (
      <Component
        className={className}
        style={{ ...style, display: 'flex', flexWrap: 'wrap', gap: '0.25em' }}
        variants={container}
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, margin: "-50px" }}
      >
        {words.map((word, index) => (
          <motion.span variants={child} key={index} style={{ display: 'inline-block' }}>
            {word}
          </motion.span>
        ))}
      </Component>
    );
  }

  // Fallback for complex React Nodes: animate as a single block but with the same physics
  return (
    <Component
      className={className}
      style={style}
      initial={{ opacity: 0, y: 30, filter: 'blur(12px)' }}
      whileInView={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
      viewport={{ once: true, margin: "-50px" }}
      transition={{ type: "spring" as const, damping: 15, stiffness: 100, delay }}
    >
      {text}
    </Component>
  );
};
