import React, { useState } from 'react';
import { AudioForensicsReport } from '../services/mediaForensics';

interface AudioForensicsCardProps {
  report: AudioForensicsReport;
}

export const AudioForensicsCard: React.FC<AudioForensicsCardProps> = ({ report }) => {
  const [activeTab, setActiveTab] = useState<'id3' | 'stream' | 'stego'>('id3');
  const { format, duration, bitrate, sampleRate, channels, codec, encoder, id3, stego } = report;

  const stegoColor = stego.riskLevel === 'critical' ? '#ff2a5f' : stego.riskLevel === 'suspicious' ? '#fb923c' : stego.riskLevel === 'low' ? '#f59e0b' : '#00ffa3';

  return (
    <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="material-symbols-outlined" style={{ color: '#ec4899', fontSize: '24px' }}>
            graphic_eq
          </span>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: '#f1f5f9' }}>
              Audio Forensics & ID3 Stream Telemetry
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Codec encoding parameters, acoustic channel layout, tag frames & stego heuristics
            </p>
          </div>
        </div>

        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 14px',
          borderRadius: '999px',
          background: `${stegoColor}15`,
          border: `1px solid ${stegoColor}40`
        }}>
          <span className="material-symbols-outlined" style={{ color: stegoColor, fontSize: '18px' }}>
            {stego.riskScore > 0 ? 'warning' : 'verified'}
          </span>
          <span style={{ color: stegoColor, fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            Stego Risk: {stego.riskScore}/100 ({stego.riskLevel.toUpperCase()})
          </span>
        </div>
      </div>

      {/* 4 Summary Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Audio Bitrate & Channels</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {bitrate || 'VBR (Dynamic)'}
          </div>
          <div style={{ fontSize: '11px', color: '#ec4899', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {channels || 'Stereo (2 ch)'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Sampling Rate & Duration</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {sampleRate || '44.1 kHz'}
          </div>
          <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {duration ? `Length: ${duration}` : 'Stream format'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Codec & Encoder</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: '#f1f5f9', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {codec || format}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {encoder ? `Engine: ${encoder}` : 'Standard Encoder'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>ID3 Metadata Status</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: id3.title || id3.artist ? '#00ffa3' : '#94a3b8', marginTop: '4px' }}>
            {id3.title || id3.artist ? 'Tags Populated' : 'Tags Stripped'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {id3.artist ? `Artist: ${id3.artist}` : 'No artist tag'}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid #1e293b', gap: '4px' }}>
        {[
          { id: 'id3', label: '🏷️ ID3 Metadata Tags' },
          { id: 'stream', label: '🎛️ Audio Stream Parameters' },
          { id: 'stego', label: '🛡️ Steganography & Integrity' },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id as any)}
            style={{
              background: 'none',
              border: 'none',
              borderBottom: activeTab === t.id ? '2px solid #ec4899' : '2px solid transparent',
              padding: '8px 16px',
              color: activeTab === t.id ? '#ec4899' : '#94a3b8',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              fontWeight: activeTab === t.id ? 700 : 500,
              cursor: 'pointer',
              transition: 'all 0.15s ease'
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab 1: ID3 */}
      {activeTab === 'id3' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
          {[
            { label: 'Track Title', value: id3.title },
            { label: 'Artist / Performer', value: id3.artist },
            { label: 'Album', value: id3.album },
            { label: 'Release Year', value: id3.year },
            { label: 'Genre', value: id3.genre },
            { label: 'Track Number', value: id3.track },
            { label: 'Composer', value: id3.composer },
            { label: 'Comments', value: id3.comments },
          ].filter(item => item.value).map((item, idx) => (
            <div key={idx} style={{ padding: '10px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>{item.label}</div>
              <div className="font-data-mono" style={{ fontSize: '13px', color: '#f1f5f9', marginTop: '2px', wordBreak: 'break-all' }}>{item.value}</div>
            </div>
          ))}

          {!id3.title && !id3.artist && !id3.album && (
            <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', gridColumn: '1 / -1' }} className="font-data-mono">
              ID3 metadata frames were stripped or are not present in this audio stream.
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Stream */}
      {activeTab === 'stream' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
          {[
            { label: 'Audio Format', value: format },
            { label: 'Codec Identifier', value: codec },
            { label: 'Audio Bitrate', value: bitrate },
            { label: 'Sampling Rate', value: sampleRate },
            { label: 'Acoustic Channels', value: channels },
            { label: 'Playback Duration', value: duration },
            { label: 'Encoding Application', value: encoder },
          ].filter(item => item.value).map((item, idx) => (
            <div key={idx} style={{ padding: '10px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>{item.label}</div>
              <div className="font-data-mono" style={{ fontSize: '13px', color: '#f1f5f9', marginTop: '2px' }}>{item.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 3: Stego */}
      {activeTab === 'stego' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {stego.signals.map(sig => {
            const sigColor = sig.severity === 'critical' ? '#ff2a5f' : sig.severity === 'high' ? '#fb923c' : sig.severity === 'medium' ? '#f59e0b' : sig.severity === 'low' ? '#38bdf8' : '#00ffa3';
            return (
              <div key={sig.id} style={{ background: 'rgba(0,0,0,0.3)', border: `1px solid ${sigColor}30`, borderRadius: '8px', padding: '14px 18px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ color: '#f1f5f9', fontWeight: 600, fontSize: '13px' }}>{sig.label}</span>
                  <span style={{ background: `${sigColor}15`, border: `1px solid ${sigColor}40`, color: sigColor, padding: '2px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                    {sig.severity.toUpperCase()}
                  </span>
                </div>
                <div style={{ fontSize: '12px', color: '#94a3b8' }}>
                  {sig.details}
                </div>
              </div>
            );
          })}
        </div>
      )}

    </div>
  );
};
