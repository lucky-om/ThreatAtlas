import React from 'react';
import { CommunityComment } from '../services/api';

interface CommunityCommentsCardProps {
  comments?: CommunityComment[];
}

export const CommunityCommentsCard: React.FC<CommunityCommentsCardProps> = ({ comments }) => {
  if (!comments || comments.length === 0) {
    return (
      <div className="glass-card animate-fade-in-up" style={{ padding: '48px', textAlign: 'center' }}>
        <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: '48px', marginBottom: '16px' }}>forum</span>
        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '8px' }}>No Community Comments</h3>
        <p className="font-body-md text-on-surface-variant">There are no user comments posted for this analysis in the threat intelligence database yet.</p>
      </div>
    );
  }

  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
      <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span className="material-symbols-outlined text-primary">groups</span>
        Community Intelligence ({comments.length})
      </h3>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {comments.map((comment) => (
          <div key={comment.id} style={{ padding: '20px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined text-primary" style={{ fontSize: '20px' }}>account_circle</span>
                <span className="font-body-md text-on-surface" style={{ fontWeight: 600 }}>{comment.author}</span>
              </div>
              <span className="font-code-sm text-on-surface-variant">
                {comment.date ? new Date(comment.date * 1000).toLocaleString() : 'N/A'}
              </span>
            </div>

            <div className="font-body-md text-on-surface" style={{ whiteSpace: 'pre-wrap', lineHeight: '1.6', wordBreak: 'break-all' }}>
              {comment.text}
            </div>

            {comment.votes && (
              <div style={{ display: 'flex', gap: '16px', marginTop: '12px', paddingTop: '12px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                <span className="font-code-sm" style={{ color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>thumb_up</span>
                  {comment.votes.positive}
                </span>
                <span className="font-code-sm" style={{ color: 'var(--secondary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>thumb_down</span>
                  {comment.votes.negative}
                </span>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
