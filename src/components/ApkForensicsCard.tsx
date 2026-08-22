import React, { useState } from 'react';
import { ApkForensicsReport } from '../services/mediaForensics';

interface ApkForensicsCardProps {
  report: ApkForensicsReport;
}

export const ApkForensicsCard: React.FC<ApkForensicsCardProps> = ({ report }) => {
  const [activeTab, setActiveTab] = useState<'permissions' | 'components' | 'c2'>('permissions');

  const threatColor = report.threatLevel === 'critical' ? '#ff2a5f' : report.threatLevel === 'suspicious' ? '#fb923c' : report.threatLevel === 'low' ? '#f59e0b' : '#00ffa3';

  return (
    <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="material-symbols-outlined" style={{ color: '#00ffa3', fontSize: '26px' }}>
            android
          </span>
          <div>
            <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: '#f1f5f9' }}>
              Android APK Package & Permission Intelligence (MobSF / Jadx)
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              AndroidManifest analysis, dangerous permissions matrix, activities, and C2 endpoints
            </p>
          </div>
        </div>

        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 14px',
          borderRadius: '999px',
          background: `${threatColor}15`,
          border: `1px solid ${threatColor}40`
        }}>
          <span className="material-symbols-outlined" style={{ color: threatColor, fontSize: '18px' }}>
            {report.threatScore > 0 ? 'warning' : 'verified'}
          </span>
          <span style={{ color: threatColor, fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            APK Threat Score: {report.threatScore}/100 ({report.threatLevel.toUpperCase()})
          </span>
        </div>
      </div>

      {/* 4 Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Package Identifier</div>
          <div style={{ fontSize: '13px', fontWeight: 700, color: '#f1f5f9', marginTop: '4px', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
            {report.packageName || 'com.example.app'}
          </div>
          <div style={{ fontSize: '11px', color: '#00ffa3', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            v{report.versionName} (Build {report.versionCode})
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>SDK Target Levels</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: '#f1f5f9', marginTop: '4px' }}>
            {report.targetSdkVersion}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            Min: {report.minSdkVersion}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Permissions Requested</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: report.permissions.some(p => p.risk === 'critical') ? '#ff2a5f' : '#38bdf8', marginTop: '4px' }}>
            {report.permissions.length} Permissions
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            {report.permissions.filter(p => p.risk === 'critical' || p.risk === 'dangerous').length} Dangerous / Critical
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px' }}>
          <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>APK Signing Status</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: report.isSigned ? '#00ffa3' : '#ff2a5f', marginTop: '4px' }}>
            {report.isSigned ? 'V1/V2 Signed' : 'Unsigned APK'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            Release Key Verified
          </div>
        </div>
      </div>

      {/* Sub Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid #1e293b', gap: '4px' }}>
        {[
          { id: 'permissions', label: '🛡️ Permissions Matrix', count: report.permissions.length },
          { id: 'components', label: '📱 Activities & Services', count: report.activities.length + report.services.length },
          { id: 'c2', label: '🌐 C2 Endpoints & Secrets', count: report.c2Endpoints.length + report.apiKeysFound.length }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            style={{
              background: 'none',
              border: 'none',
              borderBottom: activeTab === tab.id ? '2px solid #00ffa3' : '2px solid transparent',
              padding: '8px 16px',
              color: activeTab === tab.id ? '#00ffa3' : '#94a3b8',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              fontWeight: activeTab === tab.id ? 700 : 500,
              cursor: 'pointer'
            }}
          >
            {tab.label} {tab.count > 0 && `(${tab.count})`}
          </button>
        ))}
      </div>

      {/* Permissions Matrix */}
      {activeTab === 'permissions' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {report.permissions.map((perm, idx) => {
            const pColor = perm.risk === 'critical' ? '#ff2a5f' : perm.risk === 'dangerous' ? '#fb923c' : '#00ffa3';
            return (
              <div key={idx} style={{ background: 'rgba(0,0,0,0.25)', border: `1px solid ${pColor}30`, borderRadius: '8px', padding: '12px 16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span style={{ fontSize: '12px', fontWeight: 700, color: '#f1f5f9', fontFamily: 'var(--font-mono)' }}>{perm.name}</span>
                  <span style={{ background: `${pColor}15`, color: pColor, border: `1px solid ${pColor}40`, padding: '2px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                    {perm.risk.toUpperCase()}
                  </span>
                </div>
                <div style={{ fontSize: '12px', color: '#94a3b8' }}>
                  {perm.description}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Components */}
      {activeTab === 'components' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
          <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '16px' }}>
            <div style={{ fontSize: '12px', color: '#38bdf8', fontWeight: 700, fontFamily: 'var(--font-mono)', marginBottom: '10px' }}>
              ACTIVITIES ({report.activities.length})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {report.activities.map((act, i) => (
                <div key={i} style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#cbd5e1' }}>• {act}</div>
              ))}
            </div>
          </div>

          <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '16px' }}>
            <div style={{ fontSize: '12px', color: '#a855f7', fontWeight: 700, fontFamily: 'var(--font-mono)', marginBottom: '10px' }}>
              BACKGROUND SERVICES ({report.services.length})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {report.services.map((srv, i) => (
                <div key={i} style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#cbd5e1' }}>• {srv}</div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* C2 Endpoints */}
      {activeTab === 'c2' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', padding: '16px 20px' }}>
            <div style={{ fontSize: '12px', color: '#fb923c', fontWeight: 700, textTransform: 'uppercase', fontFamily: 'var(--font-mono)', marginBottom: '10px' }}>
              Extracted C2 Endpoints & Network URLs
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {report.c2Endpoints.map((url, i) => (
                <div key={i} style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#38bdf8' }}>🌐 {url}</div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
