import { Link } from 'react-router-dom';
import { EntityRelations } from '../services/api';

interface RelationsCardProps {
  relations?: EntityRelations;
  entityId?: string;
}

export const RelationsCard: React.FC<RelationsCardProps> = ({ relations, entityId }) => {
  if (!relations) {
    return (
      <div className="glass-card animate-fade-in-up" style={{ padding: '48px', textAlign: 'center' }}>
        <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: '48px', marginBottom: '16px' }}>hub</span>
        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '8px' }}>No Relations Found</h3>
        <p className="font-body-md text-on-surface-variant">No related network endpoints or parent/child artifacts found for this entity.</p>
      </div>
    );
  }

  const hasData = relations.resolutions?.length ||
                  relations.subdomains?.length ||
                  relations.historicalWhois?.length ||
                  relations.historicalSsl?.length ||
                  relations.communicatingFiles?.length ||
                  relations.downloadedFiles?.length ||
                  relations.contactedIps?.length ||
                  relations.contactedDomains?.length ||
                  relations.contactedUrls?.length;

  if (!hasData) {
    return (
      <div className="glass-card animate-fade-in-up" style={{ padding: '48px', textAlign: 'center' }}>
        <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: '48px', marginBottom: '16px' }}>hub</span>
        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '8px' }}>No Relations Found</h3>
        <p className="font-body-md text-on-surface-variant">No related network endpoints or parent/child artifacts found for this entity.</p>
      </div>
    );
  }

  const renderTable = (headers: string[], data: any[], renderRow: (row: any) => React.ReactNode) => (
    <div style={{ overflowX: 'auto', marginBottom: '32px' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
            {headers.map(h => (
              <th key={h} className="font-label-caps text-on-surface-variant" style={{ padding: '12px', whiteSpace: 'nowrap' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
              {renderRow(row)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: '32px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '24px' }}>
        <h3 className="font-headline-sm text-on-surface" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="material-symbols-outlined text-primary">hub</span>
          Relations &amp; Network Graph
        </h3>
        {entityId && (
          <Link to={`/threat-graph?q=${encodeURIComponent(entityId)}`} style={{ textDecoration: 'none' }}>
            <button className="btn-primary" style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 16px', fontSize: '13px' }}>
              <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>account_tree</span>
              Generate Threat Graph
            </button>
          </Link>
        )}
      </div>

      {relations.resolutions && relations.resolutions.length > 0 && (
        <>
          <h4 className="font-label-caps text-on-surface-variant" style={{ marginBottom: '12px' }}>Passive DNS Replication ({relations.resolutions.length})</h4>
          {renderTable(['Date Resolved', 'Detections', 'IP Address'], relations.resolutions, (r) => (
            <>
              <td style={{ padding: '12px' }} className="font-code-sm">{r.date ? new Date(r.date * 1000).toISOString().split('T')[0] : '-'}</td>
              <td style={{ padding: '12px' }} className="font-code-sm">{r.stats ? `${r.stats.malicious} / ${Object.values(r.stats).reduce((a:any, b:any) => a+b, 0)}` : '-'}</td>
              <td style={{ padding: '12px' }} className="font-data-mono text-primary">{r.ip}</td>
            </>
          ))}
        </>
      )}

      {relations.subdomains && relations.subdomains.length > 0 && (
        <>
          <h4 className="font-label-caps text-on-surface-variant" style={{ marginBottom: '12px', marginTop: '24px' }}>Subdomains ({relations.subdomains.length})</h4>
          {renderTable(['Subdomain', 'Detections'], relations.subdomains, (r) => (
            <>
              <td style={{ padding: '12px' }} className="font-data-mono text-primary">{r.id}</td>
              <td style={{ padding: '12px' }} className="font-code-sm">{r.stats ? `${r.stats.malicious} / ${Object.values(r.stats).reduce((a:any, b:any) => a+b, 0)}` : '-'}</td>
            </>
          ))}
        </>
      )}

      {relations.contactedIps && relations.contactedIps.length > 0 && (
        <>
          <h4 className="font-label-caps text-on-surface-variant" style={{ marginBottom: '12px', marginTop: '24px' }}>Contacted IP Addresses ({relations.contactedIps.length})</h4>
          {renderTable(['IP Address', 'Country', 'Detections'], relations.contactedIps, (r) => (
            <>
              <td style={{ padding: '12px' }} className="font-data-mono text-primary">{r.ip}</td>
              <td style={{ padding: '12px' }} className="font-body-md">{r.country || '-'}</td>
              <td style={{ padding: '12px' }} className="font-code-sm">{r.stats ? `${r.stats.malicious} / ${Object.values(r.stats).reduce((a:any, b:any) => a+b, 0)}` : '-'}</td>
            </>
          ))}
        </>
      )}

      {relations.contactedDomains && relations.contactedDomains.length > 0 && (
        <>
          <h4 className="font-label-caps text-on-surface-variant" style={{ marginBottom: '12px', marginTop: '24px' }}>Contacted Domains ({relations.contactedDomains.length})</h4>
          {renderTable(['Domain', 'Detections'], relations.contactedDomains, (r) => (
            <>
              <td style={{ padding: '12px' }} className="font-data-mono text-primary">{r.domain}</td>
              <td style={{ padding: '12px' }} className="font-code-sm">{r.stats ? `${r.stats.malicious} / ${Object.values(r.stats).reduce((a:any, b:any) => a+b, 0)}` : '-'}</td>
            </>
          ))}
        </>
      )}

      {relations.contactedUrls && relations.contactedUrls.length > 0 && (
        <>
          <h4 className="font-label-caps text-on-surface-variant" style={{ marginBottom: '12px', marginTop: '24px' }}>Contacted URLs ({relations.contactedUrls.length})</h4>
          {renderTable(['URL', 'Detections'], relations.contactedUrls, (r) => (
            <>
              <td style={{ padding: '12px', wordBreak: 'break-all' }} className="font-data-mono text-primary">{r.url}</td>
              <td style={{ padding: '12px' }} className="font-code-sm">{r.stats ? `${r.stats.malicious} / ${Object.values(r.stats).reduce((a:any, b:any) => a+b, 0)}` : '-'}</td>
            </>
          ))}
        </>
      )}

      {relations.communicatingFiles && relations.communicatingFiles.length > 0 && (
        <>
          <h4 className="font-label-caps text-on-surface-variant" style={{ marginBottom: '12px', marginTop: '24px' }}>Communicating Files ({relations.communicatingFiles.length})</h4>
          {renderTable(['File Name / ID', 'Type', 'Detections'], relations.communicatingFiles, (r) => (
            <>
              <td style={{ padding: '12px' }} className="font-data-mono text-primary">{r.name || r.id}</td>
              <td style={{ padding: '12px' }} className="font-body-md">{r.type || '-'}</td>
              <td style={{ padding: '12px' }} className="font-code-sm">{r.stats ? `${r.stats.malicious} / ${Object.values(r.stats).reduce((a:any, b:any) => a+b, 0)}` : '-'}</td>
            </>
          ))}
        </>
      )}

      {relations.downloadedFiles && relations.downloadedFiles.length > 0 && (
        <>
          <h4 className="font-label-caps text-on-surface-variant" style={{ marginBottom: '12px', marginTop: '24px' }}>Downloaded Files ({relations.downloadedFiles.length})</h4>
          {renderTable(['File Name / ID', 'Type', 'Detections'], relations.downloadedFiles, (r) => (
            <>
              <td style={{ padding: '12px' }} className="font-data-mono text-primary">{r.name || r.id}</td>
              <td style={{ padding: '12px' }} className="font-body-md">{r.type || '-'}</td>
              <td style={{ padding: '12px' }} className="font-code-sm">{r.stats ? `${r.stats.malicious} / ${Object.values(r.stats).reduce((a:any, b:any) => a+b, 0)}` : '-'}</td>
            </>
          ))}
        </>
      )}

      {relations.historicalWhois && relations.historicalWhois.length > 0 && (
        <>
          <h4 className="font-label-caps text-on-surface-variant" style={{ marginBottom: '12px', marginTop: '24px' }}>Historical Whois Lookups ({relations.historicalWhois.length})</h4>
          {renderTable(['Last Updated', 'Registrar', 'Registrant'], relations.historicalWhois, (r) => (
            <>
              <td style={{ padding: '12px' }} className="font-code-sm">{r.date ? new Date(r.date * 1000).toISOString().split('T')[0] : '-'}</td>
              <td style={{ padding: '12px' }} className="font-body-md">{r.registrar || '-'}</td>
              <td style={{ padding: '12px' }} className="font-body-md">{r.registrant || '-'}</td>
            </>
          ))}
        </>
      )}

      {relations.historicalSsl && relations.historicalSsl.length > 0 && (
        <>
          <h4 className="font-label-caps text-on-surface-variant" style={{ marginBottom: '12px', marginTop: '24px' }}>Historical SSL Certificates ({relations.historicalSsl.length})</h4>
          {renderTable(['First Seen', 'Subject', 'Thumbprint'], relations.historicalSsl, (r) => (
            <>
              <td style={{ padding: '12px' }} className="font-code-sm">{r.date ? new Date(r.date * 1000).toISOString().split('T')[0] : '-'}</td>
              <td style={{ padding: '12px' }} className="font-body-md">{r.subject || '-'}</td>
              <td style={{ padding: '12px', wordBreak: 'break-all', fontSize: '12px' }} className="font-data-mono">{r.thumbprint || '-'}</td>
            </>
          ))}
        </>
      )}
    </div>
  );
};
