import React, { useState } from 'react';
import { VideoForensicsReport } from '../services/mediaForensics';

interface VideoForensicsCardProps {
  report: VideoForensicsReport;
}

export const VideoForensicsCard: React.FC<VideoForensicsCardProps> = ({ report }) => {
  const [activeTab, setActiveTab] = useState<'video' | 'audio' | 'stego'>('video');
  const { format, duration, dimensions, videoCodec, audioCodec, frameRate, overallBitrate, videoBitrate, audioBitrate, encoderTool, creationDate, gpsCoordinates, stego } = report;

  const stegoColor = stego.riskLevel === 'critical' ? '#ff2a5f' : stego.riskLevel === 'suspicious' ? '#fb923c' : stego.riskLevel === 'low' ? '#f59e0b' : '#00ffa3';

  return (
    <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="material-symbols-outlined" style={{ color: '#a855f7', fontSize: '24px' }}>
            movie
          </span>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: '#f1f5f9' }}>
              Video Stream & Container Forensics Engine
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Video & audio track codecs, frame rates, container atoms, resolution & stream integrity
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
            Stream Risk: {stego.riskScore}/100 ({stego.riskLevel.toUpperCase()})
          </span>
        </div>
      </div>

      {/* 4 Summary Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Resolution & Aspect Ratio</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {dimensions.width > 0 ? `${dimensions.width} × ${dimensions.height}` : 'N/A'}
          </div>
          <div style={{ fontSize: '11px', color: '#a855f7', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {dimensions.aspectRatio} · {frameRate || 'Standard FPS'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Video Codec & Track</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {videoCodec || format}
          </div>
          <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {videoBitrate ? `Bitrate: ${videoBitrate}` : overallBitrate ? `Overall: ${overallBitrate}` : 'Variable Bitrate'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Audio Stream & Duration</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: '#f1f5f9', marginTop: '4px' }}>
            {audioCodec || 'Audio Track Encoded'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {duration ? `Length: ${duration}` : 'Stream length'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Creation & Geolocation</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: gpsCoordinates ? '#00ffa3' : '#f1f5f9', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {gpsCoordinates ? '📍 GPS Track Embedded' : (creationDate ? creationDate : 'No GPS Metadata')}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {encoderTool ? `Tool: ${encoderTool}` : 'Container Clean'}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid #1e293b', gap: '4px' }}>
        {[
          { id: 'video', label: '🎬 Video Track Parameters' },
          { id: 'audio', label: '🔊 Audio Track & Codecs' },
          { id: 'stego', label: '🛡️ Container Integrity & Alerts' },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id as any)}
            style={{
              background: 'none',
              border: 'none',
              borderBottom: activeTab === t.id ? '2px solid #a855f7' : '2px solid transparent',
              padding: '8px 16px',
              color: activeTab === t.id ? '#a855f7' : '#94a3b8',
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

      {/* Tab 1: Video Track */}
      {activeTab === 'video' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
          {[
            { label: 'Container Format', value: format },
            { label: 'Video Codec', value: videoCodec },
            { label: 'Frame Dimensions', value: dimensions.width > 0 ? `${dimensions.width} × ${dimensions.height}` : undefined },
            { label: 'Aspect Ratio', value: dimensions.aspectRatio },
            { label: 'Frame Rate', value: frameRate },
            { label: 'Overall Bitrate', value: overallBitrate },
            { label: 'Video Bitrate', value: videoBitrate },
            { label: 'Encoding Software', value: encoderTool },
            { label: 'Creation Date', value: creationDate },
            { label: 'GPS Coordinates', value: gpsCoordinates },
          ].filter(item => item.value).map((item, idx) => (
            <div key={idx} style={{ padding: '10px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>{item.label}</div>
              <div className="font-data-mono" style={{ fontSize: '13px', color: '#f1f5f9', marginTop: '2px' }}>{item.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 2: Audio Track */}
      {activeTab === 'audio' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
          {[
            { label: 'Audio Codec', value: audioCodec },
            { label: 'Audio Bitrate', value: audioBitrate },
            { label: 'Track Duration', value: duration },
          ].filter(item => item.value).map((item, idx) => (
            <div key={idx} style={{ padding: '10px 14px', background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>{item.label}</div>
              <div className="font-data-mono" style={{ fontSize: '13px', color: '#f1f5f9', marginTop: '2px' }}>{item.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 3: Stego & Alerts */}
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
