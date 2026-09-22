import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

export const ScrollToTopButton: React.FC = () => {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const toggleVisibility = () => {
      if (window.scrollY > 300) setIsVisible(true);
      else setIsVisible(false);
    };
    window.addEventListener('scroll', toggleVisibility);
    return () => window.removeEventListener('scroll', toggleVisibility);
  }, []);

  const scrollToTop = () => {
    window.scrollTo({
      top: 0,
      behavior: 'smooth'
    });
  };

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.8 }}
          style={{ position: 'fixed', bottom: '24px', left: '24px', zIndex: 998 }}
        >
          <button
            onClick={scrollToTop}
            title="Scroll to Top"
            aria-label="Scroll to top"
            style={{
              width: '56px', height: '56px', borderRadius: '50%',
              background: 'rgba(20, 15, 25, 0.8)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              color: 'var(--on-surface-2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              cursor: 'pointer',
              backdropFilter: 'blur(10px)',
              transition: 'all 0.2s ease',
            }}
            onMouseEnter={e => { 
              e.currentTarget.style.color = '#fff';
              e.currentTarget.style.border = '1px solid rgba(255,255,255,0.3)';
              e.currentTarget.style.transform = 'translateY(-4px)';
            }}
            onMouseLeave={e => { 
              e.currentTarget.style.color = 'var(--on-surface-2)';
              e.currentTarget.style.border = '1px solid rgba(255,255,255,0.1)';
              e.currentTarget.style.transform = 'translateY(0)';
            }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: '24px' }}>arrow_upward</span>
          </button>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
