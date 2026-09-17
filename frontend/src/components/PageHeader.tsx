/**
 * PageHeader — shared Inferno-themed hero section used across all module pages.
 * Provides consistent brand style: display font, badge, animated headline, description.
 */
import React from 'react';
import { motion } from 'framer-motion';

interface PageHeaderProps {
  badge?: string;
  badgeIcon?: string;
  preTitleHighlight?: string; // highlighted word prepended before title
  title: string;
  titleHighlight?: string;  // highlighted word appended after title
  description?: string;
  children?: React.ReactNode;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  badge,
  badgeIcon = 'shield',
  preTitleHighlight,
  title,
  titleHighlight,
  description,
  children,
}) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 28 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.55, ease: [0.16, 1, 0.3, 1] }}
      style={{ textAlign: 'center', marginBottom: '44px' }}
    >
      {badge && (
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: '7px',
          padding: '4px 14px', marginBottom: '20px',
          background: 'var(--brand-dim)', border: '1px solid var(--border-2)',
          borderRadius: '999px',
        }}>
          <span className="material-symbols-outlined" style={{ fontSize: '13px', color: 'var(--brand)' }}>
            {badgeIcon}
          </span>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 700,
            color: 'var(--brand)', letterSpacing: '0.14em', textTransform: 'uppercase',
          }}>
            {badge}
          </span>
        </div>
      )}

      <h1 style={{
        fontFamily: 'var(--font-display)',
        fontSize: 'clamp(38px, 6vw, 72px)',
        lineHeight: 1.0,
        letterSpacing: '0.02em',
        color: 'var(--on-surface)',
        marginBottom: titleHighlight || preTitleHighlight || description || children ? '16px' : 0,
      }}>
        {preTitleHighlight && (
          <>
            <span style={{
              color: 'var(--brand)',
              textShadow: '0 0 40px var(--brand-glow)',
            }}>
              {preTitleHighlight}
            </span>
            {' '}
          </>
        )}
        {title}
        {titleHighlight && (
          <>
            {' '}
            <span style={{
              color: 'var(--brand)',
              textShadow: '0 0 40px var(--brand-glow)',
            }}>
              {titleHighlight}
            </span>
          </>
        )}
      </h1>

      {description && (
        <p style={{
          fontFamily: 'var(--font-sans)',
          fontSize: '15px',
          color: 'var(--on-surface-3)',
          maxWidth: '580px',
          margin: '0 auto',
          lineHeight: 1.75,
          marginBottom: children ? '20px' : 0,
        }}>
          {description}
        </p>
      )}

      {children}
    </motion.div>
  );
};
