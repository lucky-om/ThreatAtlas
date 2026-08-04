import React, { useEffect, useState } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { Gauge } from '../components/Gauge';
import { EngineGrid } from '../components/EngineGrid';
import { AiSummary } from '../components/AiSummary';
import { pollAnalysis, lookupHash, NormalizedAnalysis, NormalizedFile, isValidHash } from '../services/api';
import { RelationsCard } from '../components/RelationsCard';
import { BehaviorCard } from '../components/BehaviorCard';
import { CommunityCommentsCard } from '../components/CommunityCommentsCard';

type Tab = 'SUMMARY' | 'DETECTION' | 'DETAILS' | 'RELATIONS' | 'BEHAVIOR' | 'COMMUNITY';

export const Results: React.FC = () => {
  const { id: pathId, hash: pathHash, tab } = useParams();
  const [searchParams] = useSearchParams();
  let rawId = pathId || searchParams.get('id') || undefined;
  let rawHash = pathHash || searchParams.get('hash') || undefined;

  if (rawHash && !isValidHash(rawHash)) {
    rawId = rawHash;
    rawHash = undefined;
  }

  const id = rawId;
  const hash = rawHash;

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [analysisResult, setAnalysisResult] = useState<NormalizedAnalysis | null>(null);
  const [fileResult, setFileResult] = useState<NormalizedFile | null>(null);

  const [activeTab, setActiveTab] = useState<Tab>('DETECTION');
  const [activeSection, setActiveSection] = useState<string>('Security Vendors');

  const navigate = useNavigate();

  useEffect(() => {
    if (tab) {
      const upperTab = tab.toUpperCase() as Tab;
      if (['SUMMARY', 'DETECTION', 'DETAILS', 'RELATIONS', 'BEHAVIOR', 'COMMUNITY'].includes(upperTab)) {
        setActiveTab(upperTab);
      }
    }
  }, [tab]);

  useEffect(() => {
    if (!id && !hash) {
      navigate('/');
      return;
    }

    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        if (id) {
          const data = await pollAnalysis(id, (progress) => {
            setAnalysisResult(progress);
          });
          setAnalysisResult(data);

          if (data.hash) {
            try {
              const fileData = await lookupHash(data.hash);
              setFileResult(fileData);
            } catch (e) {
              console.warn("Failed to fetch full file metadata:", e);
            }
          }
        } else if (hash) {
          const data = await lookupHash(hash);
          setFileResult(data);
        }
      } catch (err: any) {
        console.error(err);
        if (err.response?.status === 401 || err.status === 401) {
          setError("API Key Error: Unauthorized (401). Ensure the correct VirusTotal API key is used.");
        } else if (err.response?.status === 404 || err.status === 404) {
          setError("Not Found (404): The requested report was not found.");
        } else {
          setError(err.message || "An error occurred fetching results.");
        }
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [id, hash, navigate]);

  if (loading && !analysisResult && !fileResult) {
    return (
      <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '100px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <div className="digital-grid"></div>
        <div className="glow-cyan"></div>
        <div className="container" style={{ position: 'relative', zIndex: 10, textAlign: 'center', marginTop: '100px' }}>
          <span className="material-symbols-outlined text-primary spin" style={{ fontSize: '64px', marginBottom: '16px' }}>sync</span>
          <h2 className="font-display-lg text-on-surface">Analyzing Data...</h2>
          <p className="font-body-md text-on-surface-variant">Please wait while we gather threat intelligence.</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '100px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <div className="digital-grid"></div>
        <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '800px', marginTop: '100px' }}>
          <div className="glass-card" style={{ padding: '48px', textAlign: 'center', borderColor: 'var(--secondary)' }}>
            <span className="material-symbols-outlined text-secondary" style={{ fontSize: '64px', marginBottom: '16px', filter: 'drop-shadow(0 0 10px rgba(255,0,60,0.5))' }}>warning</span>
            <h2 className="font-display-lg text-secondary" style={{ marginBottom: '16px' }}>Scan Failed</h2>
            <p className="font-data-mono">{error}</p>
            <button className="btn-primary" onClick={() => navigate('/')} style={{ marginTop: '24px' }}>
              Return Home
            </button>
          </div>
        </div>
      </div>
    );
  }

  const isPending = analysisResult?.status === 'queued' || analysisResult?.status === 'in-progress';
  const stats = fileResult?.stats || analysisResult?.stats;
  const engines = fileResult?.engines || analysisResult?.engines || [];

  const score = stats?.malicious || 0;
  const total = (stats?.malicious || 0) + (stats?.undetected || 0) + (stats?.harmless || 0) + (stats?.suspicious || 0) + (stats?.timeout || 0);

  // Add a dynamic background glow based on threat level
  const dynamicGlow = {
    background: score > 0
      ? (score < 5 ? 'radial-gradient(circle at bottom left, rgba(255, 179, 178, 0.15) 0%, transparent 50%)'
        : 'radial-gradient(circle at bottom left, rgba(255, 0, 60, 0.15) 0%, transparent 50%)')
      : 'radial-gradient(circle at bottom left, rgba(0, 242, 255, 0.15) 0%, transparent 50%)'
  };

  const handleTabChange = (t: Tab) => {
    setActiveTab(t);
    if (t === 'SUMMARY') setActiveSection('Overview');
    if (t === 'DETECTION') setActiveSection('Security Vendors');
    if (t === 'DETAILS') setActiveSection('Basic Properties');
    if (t === 'COMMUNITY') setActiveSection('Comments');
    
    const basePath = hash ? `/file/${hash}` : `/url/${id}`;
    navigate(`${basePath}/${t.toLowerCase()}`, { replace: true });
  };

  return (
    <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '100px', paddingBottom: '64px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <div className="digital-grid"></div>
      <div style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0, transition: 'background 1s ease', ...dynamicGlow }}></div>

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1200px' }}>

        {isPending && (
          <div className="glass-card" style={{ padding: '16px 24px', marginBottom: '32px', display: 'flex', alignItems: 'center', gap: '16px', borderColor: 'var(--primary)' }}>
            <span className="material-symbols-outlined text-primary spin">sync</span>
            <div>
              <div className="font-label-caps text-primary">Analysis in progress...</div>
              <p className="font-code-sm text-on-surface-variant" style={{ margin: 0 }}>Results will update automatically.</p>
            </div>
          </div>
        )}

        {/* Top Header Cards */}
        <div className="grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '24px', marginBottom: '32px' }}>
          {/* Left Card: Score */}
          <div className="col-12 md-col-3">
            <div className="glass-card animate-fade-in-up" style={{ padding: '32px 16px', textAlign: 'center', height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <Gauge score={score} total={total} size={140} />
              <div className="font-label-caps text-on-surface-variant" style={{ marginTop: '16px' }}>Community Score</div>
            </div>
          </div>
          {/* Right Card: Report Info */}
          <div className="col-12 md-col-9">
            <div className="glass-card animate-fade-in-up" style={{ padding: '32px', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div className="font-body-md text-on-surface-variant" style={{ marginBottom: '16px' }}>
                  {(fileResult?.type ? 'FILE' : 'URL') + ' report for '}
                  <span className="text-on-surface font-code-sm">{(fileResult?.lastSeen || analysisResult?.date) ? new Date((fileResult?.lastSeen || analysisResult?.date || 0) * 1000).toUTCString() : 'N/A'}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '48px', height: '48px', borderRadius: '50%', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)' }}>
                  <span className="material-symbols-outlined" style={{ fontSize: '24px', color: 'var(--on-surface)' }}>
                    {fileResult?.type ? 'description' : 'public'}
                  </span>
                </div>
              </div>
              <h2 className="font-headline-md text-primary" style={{ wordBreak: 'break-all', marginBottom: '8px' }}>
                {analysisResult?.url || fileResult?.names?.[0] || hash || id}
              </h2>
              {fileResult?.names && fileResult.names.length > 1 && (
                <div className="font-code-sm text-on-surface-variant" style={{ marginBottom: '24px' }}>
                  Also known as: {fileResult.names.slice(1, 4).join(', ')}
                </div>
              )}

              <div style={{ display: 'flex', gap: '48px', marginTop: '24px', flexWrap: 'wrap' }}>
                {fileResult?.size && (
                  <div>
                    <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Size</div>
                    <div className="font-data-mono text-on-surface">{(fileResult.size / 1024 / 1024).toFixed(2)} MB</div>
                  </div>
                )}
                {fileResult?.type && (
                  <div>
                    <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Content Type</div>
                    <div className="font-data-mono text-on-surface">{fileResult.type}</div>
                  </div>
                )}
                {analysisResult?.status && (
                  <div>
                    <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Status</div>
                    <div className="font-data-mono text-on-surface uppercase">{analysisResult.status}</div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Tabs Navigation */}
        <div className="scanner-tabs animate-fade-in-up" style={{ marginBottom: '32px', flexWrap: 'wrap' }}>
          {(['SUMMARY', 'DETECTION', 'DETAILS', 'RELATIONS', 'BEHAVIOR', 'COMMUNITY'] as Tab[]).map((tab) => (
            <button
              key={tab}
              className={`scanner-tab font-label-caps ${activeTab === tab ? 'active' : ''}`}
              onClick={() => handleTabChange(tab)}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Two-Column Content Area */}
        <div className="grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '24px' }}>

          {/* Table of Contents (Sidebar) */}
          <div className="col-12 md-col-3">
            <div className="glass-card animate-fade-in-up" style={{ padding: '24px' }}>
              <div className="font-label-caps text-on-surface" style={{ marginBottom: '16px' }}>Table of Contents</div>
              <ul className="sidebar-menu">
                {activeTab === 'SUMMARY' && (
                  <>
                    <button className={`sidebar-item ${activeSection === 'Overview' ? 'active' : ''}`} onClick={() => setActiveSection('Overview')}>Overview</button>
                  </>
                )}
                {activeTab === 'DETECTION' && (
                  <>
                    <button className={`sidebar-item ${activeSection === 'Security Vendors' ? 'active' : ''}`} onClick={() => setActiveSection('Security Vendors')}>Security vendors' analysis</button>
                  </>
                )}
                {activeTab === 'DETAILS' && (
                  <>
                    <button className={`sidebar-item ${activeSection === 'Basic Properties' ? 'active' : ''}`} onClick={() => { setActiveSection('Basic Properties'); document.getElementById('details-basic')?.scrollIntoView({behavior: 'smooth'}); }}>Basic Properties</button>
                    {((fileResult?.extended?.categories || analysisResult?.extended?.categories) && Object.keys(fileResult?.extended?.categories || analysisResult?.extended?.categories || {}).length > 0) ? (
                      <button className={`sidebar-item ${activeSection === 'Categories' ? 'active' : ''}`} onClick={() => { setActiveSection('Categories'); document.getElementById('details-categories')?.scrollIntoView({behavior: 'smooth'}); }}>Categories</button>
                    ) : null}
                    <button className={`sidebar-item ${activeSection === 'History' ? 'active' : ''}`} onClick={() => { setActiveSection('History'); document.getElementById('details-history')?.scrollIntoView({behavior: 'smooth'}); }}>History</button>
                    {((fileResult?.extended?.redirectionChain || analysisResult?.extended?.redirectionChain) && (fileResult?.extended?.redirectionChain?.length || analysisResult?.extended?.redirectionChain?.length)) ? (
                      <button className={`sidebar-item ${activeSection === 'Redirection Chain' ? 'active' : ''}`} onClick={() => { setActiveSection('Redirection Chain'); document.getElementById('details-redirection')?.scrollIntoView({behavior: 'smooth'}); }}>Redirection Chain</button>
                    ) : null}
                    {(fileResult?.extended?.httpResponse || analysisResult?.extended?.httpResponse) ? (
                      <button className={`sidebar-item ${activeSection === 'HTTP Response' ? 'active' : ''}`} onClick={() => { setActiveSection('HTTP Response'); document.getElementById('details-http')?.scrollIntoView({behavior: 'smooth'}); }}>HTTP Response</button>
                    ) : null}
                    {(fileResult?.extended?.htmlInfo || analysisResult?.extended?.htmlInfo) ? (
                      <button className={`sidebar-item ${activeSection === 'HTML Info' ? 'active' : ''}`} onClick={() => { setActiveSection('HTML Info'); document.getElementById('details-html')?.scrollIntoView({behavior: 'smooth'}); }}>HTML Info</button>
                    ) : null}
                    {(fileResult?.extended?.favicon || analysisResult?.extended?.favicon) ? (
                      <button className={`sidebar-item ${activeSection === 'Favicon' ? 'active' : ''}`} onClick={() => { setActiveSection('Favicon'); document.getElementById('details-favicon')?.scrollIntoView({behavior: 'smooth'}); }}>Favicon</button>
                    ) : null}
                    {(fileResult?.extended?.networkRequests || analysisResult?.extended?.networkRequests) ? (
                      <button className={`sidebar-item ${activeSection === 'Network Requests' ? 'active' : ''}`} onClick={() => { setActiveSection('Network Requests'); document.getElementById('details-network')?.scrollIntoView({behavior: 'smooth'}); }}>Network Requests</button>
                    ) : null}
                    {(fileResult?.extended?.outgoingLinks || analysisResult?.extended?.outgoingLinks) ? (
                      <button className={`sidebar-item ${activeSection === 'External Outbound Links' ? 'active' : ''}`} onClick={() => { setActiveSection('External Outbound Links'); document.getElementById('details-outbound')?.scrollIntoView({behavior: 'smooth'}); }}>External Outbound Links</button>
                    ) : null}
                    {(fileResult?.extended?.javascriptVariables || analysisResult?.extended?.javascriptVariables) ? (
                      <button className={`sidebar-item ${activeSection === 'Javascript Global Variables' ? 'active' : ''}`} onClick={() => { setActiveSection('Javascript Global Variables'); document.getElementById('details-js')?.scrollIntoView({behavior: 'smooth'}); }}>Javascript Global Variables</button>
                    ) : null}
                    {(fileResult?.magic || fileResult?.trid) ? (
                      <button className={`sidebar-item ${activeSection === 'File Identification' ? 'active' : ''}`} onClick={() => { setActiveSection('File Identification'); document.getElementById('details-file-id')?.scrollIntoView({behavior: 'smooth'}); }}>File Identification</button>
                    ) : null}
                    {fileResult?.extended?.peInfo ? (
                      <button className={`sidebar-item ${activeSection === 'PE Info' ? 'active' : ''}`} onClick={() => { setActiveSection('PE Info'); document.getElementById('details-pe-info')?.scrollIntoView({behavior: 'smooth'}); }}>PE Info</button>
                    ) : null}
                    {fileResult?.extended?.signatureInfo ? (
                      <button className={`sidebar-item ${activeSection === 'Signature Info' ? 'active' : ''}`} onClick={() => { setActiveSection('Signature Info'); document.getElementById('details-signature')?.scrollIntoView({behavior: 'smooth'}); }}>Signature Info</button>
                    ) : null}
                    {fileResult?.extended?.exiftool ? (
                      <button className={`sidebar-item ${activeSection === 'ExifTool' ? 'active' : ''}`} onClick={() => { setActiveSection('ExifTool'); document.getElementById('details-exif')?.scrollIntoView({behavior: 'smooth'}); }}>ExifTool</button>
                    ) : null}
                    {fileResult?.extended?.packers ? (
                      <button className={`sidebar-item ${activeSection === 'Packers' ? 'active' : ''}`} onClick={() => { setActiveSection('Packers'); document.getElementById('details-packers')?.scrollIntoView({behavior: 'smooth'}); }}>Packers</button>
                    ) : null}
                  </>
                )}
                {activeTab === 'COMMUNITY' && (
                  <>
                    <button className={`sidebar-item ${activeSection === 'Comments' ? 'active' : ''}`} onClick={() => setActiveSection('Comments')}>Comments</button>
                  </>
                )}
              </ul>
            </div>
          </div>

          {/* Main Content */}
          <div className="col-12 md-col-9">
            <div className="glass-card animate-fade-in-up" style={{ padding: '32px', minHeight: '400px' }}>

              {/* Content based on tab and section */}
              {activeTab === 'SUMMARY' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                  <AiSummary threatData={fileResult || analysisResult} type={fileResult ? 'file' : (id?.startsWith('u-') ? 'url' : 'file')} />
                </div>
              )}

              {activeTab === 'DETECTION' && activeSection === 'Security Vendors' && (
                <div>
                  <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px' }}>Security vendors' analysis</h3>
                  {engines.length > 0 ? (
                    <EngineGrid results={engines} />
                  ) : (
                    <div style={{ textAlign: 'center', padding: '48px', color: 'var(--on-surface-variant)' }} className="font-data-mono">
                      {isPending ? "Waiting for engines to return results..." : "No engine data available."}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'DETAILS' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
                    
                    <div id="details-basic">
                      <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px' }}>Basic Properties</h3>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '0 16px' }}>
                          {(hash || analysisResult?.hash) && (
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '12px' }}>
                              <div className="font-label-caps text-on-surface-variant" style={{ width: '200px', flexShrink: 0 }}>SHA-256</div>
                              <div className="font-data-mono text-primary" style={{ wordBreak: 'break-all', textAlign: 'right' }}>{hash || analysisResult?.hash}</div>
                            </div>
                          )}
                          {fileResult?.md5 && (
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '12px' }}>
                              <div className="font-label-caps text-on-surface-variant" style={{ width: '200px', flexShrink: 0 }}>MD5</div>
                              <div className="font-data-mono text-primary" style={{ wordBreak: 'break-all', textAlign: 'right' }}>{fileResult.md5}</div>
                            </div>
                          )}
                          {fileResult?.sha1 && (
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '12px' }}>
                              <div className="font-label-caps text-on-surface-variant" style={{ width: '200px', flexShrink: 0 }}>SHA-1</div>
                              <div className="font-data-mono text-primary" style={{ wordBreak: 'break-all', textAlign: 'right' }}>{fileResult.sha1}</div>
                            </div>
                          )}
                          {fileResult?.type && (
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '12px' }}>
                              <div className="font-label-caps text-on-surface-variant" style={{ width: '200px', flexShrink: 0 }}>File Type</div>
                              <div className="font-data-mono text-on-surface" style={{ textAlign: 'right' }}>{fileResult.type}</div>
                            </div>
                          )}
                      </div>
                    </div>

                    {(fileResult?.extended?.categories || analysisResult?.extended?.categories) && Object.keys(fileResult?.extended?.categories || analysisResult?.extended?.categories || {}).length > 0 && (
                      <div id="details-categories">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>category</span> Categories
                        </h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '0 16px' }}>
                          {Object.entries(fileResult?.extended?.categories || analysisResult?.extended?.categories || {}).map(([vendor, cat]) => (
                            <div key={vendor} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.02)', paddingBottom: '8px' }}>
                              <div className="font-data-mono text-on-surface">{vendor}</div>
                              <div className="font-data-mono text-on-surface-variant">{cat}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div id="details-history">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                           <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>history</span> History
                        </h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '0 16px' }}>
                          {(fileResult?.extended?.history?.firstSubmission || analysisResult?.extended?.history?.firstSubmission) && (
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '12px' }}>
                              <div className="font-label-caps text-on-surface-variant">First Submission</div>
                              <div className="font-data-mono text-on-surface">{new Date((fileResult?.extended?.history?.firstSubmission || analysisResult?.extended?.history?.firstSubmission || 0) * 1000).toUTCString()}</div>
                            </div>
                          )}
                          {(fileResult?.extended?.history?.lastSubmission || analysisResult?.extended?.history?.lastSubmission) && (
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '12px' }}>
                              <div className="font-label-caps text-on-surface-variant">Last Submission</div>
                              <div className="font-data-mono text-on-surface">{new Date((fileResult?.extended?.history?.lastSubmission || analysisResult?.extended?.history?.lastSubmission || 0) * 1000).toUTCString()}</div>
                            </div>
                          )}
                          {(fileResult?.extended?.history?.lastAnalysis || analysisResult?.extended?.history?.lastAnalysis || fileResult?.lastSeen || analysisResult?.date) && (
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '12px' }}>
                              <div className="font-label-caps text-on-surface-variant">Last Analysis</div>
                              <div className="font-data-mono text-on-surface">{new Date((fileResult?.extended?.history?.lastAnalysis || analysisResult?.extended?.history?.lastAnalysis || fileResult?.lastSeen || analysisResult?.date || 0) * 1000).toUTCString()}</div>
                            </div>
                          )}
                        </div>
                    </div>

                    {(fileResult?.extended?.redirectionChain || analysisResult?.extended?.redirectionChain) && (fileResult?.extended?.redirectionChain?.length || analysisResult?.extended?.redirectionChain?.length) ? (
                       <div id="details-redirection">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                           <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>route</span> Redirection Chain
                        </h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '0 16px' }}>
                          {(fileResult?.extended?.redirectionChain || analysisResult?.extended?.redirectionChain || []).map((url, i) => (
                            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                              <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: '16px' }}>subdirectory_arrow_right</span>
                              <div className="font-data-mono text-primary" style={{ wordBreak: 'break-all' }}>{url}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : null}

                    {(fileResult?.extended?.httpResponse || analysisResult?.extended?.httpResponse) && (
                      <div id="details-http">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                           <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>http</span> HTTP Response
                        </h3>
                        
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '0 16px' }}>
                          { (fileResult?.extended?.httpResponse?.finalUrl || analysisResult?.extended?.httpResponse?.finalUrl) && (
                            <div>
                              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Final URL</div>
                              <div className="font-data-mono text-primary">{fileResult?.extended?.httpResponse?.finalUrl || analysisResult?.extended?.httpResponse?.finalUrl}</div>
                            </div>
                          )}
                          
                          { (fileResult?.extended?.httpResponse?.servingIp || analysisResult?.extended?.httpResponse?.servingIp) && (
                            <div>
                              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Serving IP Address</div>
                              <div className="font-data-mono text-on-surface">{fileResult?.extended?.httpResponse?.servingIp || analysisResult?.extended?.httpResponse?.servingIp}</div>
                            </div>
                          )}
                          
                          { (fileResult?.extended?.httpResponse?.statusCode || analysisResult?.extended?.httpResponse?.statusCode) && (
                            <div>
                              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Status Code</div>
                              <div className="font-data-mono text-on-surface">{fileResult?.extended?.httpResponse?.statusCode || analysisResult?.extended?.httpResponse?.statusCode}</div>
                            </div>
                          )}
                          
                          { (fileResult?.extended?.httpResponse?.bodyLength || analysisResult?.extended?.httpResponse?.bodyLength) && (
                            <div>
                              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Body Length</div>
                              <div className="font-data-mono text-on-surface">{(fileResult?.extended?.httpResponse?.bodyLength || analysisResult?.extended?.httpResponse?.bodyLength || 0).toLocaleString()} Bytes</div>
                            </div>
                          )}
                          
                          { (fileResult?.extended?.httpResponse?.headers || analysisResult?.extended?.httpResponse?.headers) && (
                            <div style={{ marginTop: '16px' }}>
                              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '8px' }}>Headers</div>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', background: 'rgba(0,0,0,0.3)', padding: '16px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.05)' }}>
                                {Object.entries(fileResult?.extended?.httpResponse?.headers || analysisResult?.extended?.httpResponse?.headers || {}).map(([key, val]) => (
                                  <div key={key} style={{ display: 'flex' }}>
                                    <div className="font-data-mono text-on-surface-variant" style={{ width: '180px', flexShrink: 0 }}>{key}</div>
                                    <div className="font-data-mono text-on-surface" style={{ wordBreak: 'break-all' }}>{String(val)}</div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {(fileResult?.extended?.htmlInfo || analysisResult?.extended?.htmlInfo) && (
                      <div id="details-html">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                           <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>html</span> HTML Info
                        </h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '0 16px' }}>
                          
                          {(fileResult?.extended?.htmlInfo?.title || analysisResult?.extended?.htmlInfo?.title) && (
                            <div>
                              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '4px' }}>Title</div>
                              <div className="font-data-mono text-primary">{fileResult?.extended?.htmlInfo?.title || analysisResult?.extended?.htmlInfo?.title}</div>
                            </div>
                          )}

                          {(fileResult?.extended?.htmlInfo?.meta || analysisResult?.extended?.htmlInfo?.meta) && Object.keys(fileResult?.extended?.htmlInfo?.meta || analysisResult?.extended?.htmlInfo?.meta || {}).length > 0 && (
                            <div>
                              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '8px' }}>Meta Tags</div>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                {Object.entries(fileResult?.extended?.htmlInfo?.meta || analysisResult?.extended?.htmlInfo?.meta || {}).map(([key, values]) => (
                                  <div key={key} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', paddingBottom: '8px' }}>
                                    <div className="font-data-mono text-on-surface-variant">{key}:</div>
                                     <div className="font-data-mono text-on-surface" style={{ marginTop: '4px', wordBreak: 'break-all', paddingLeft: '16px' }}>{Array.isArray(values) ? values.join(', ') : String(values)}</div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                          
                        </div>
                      </div>
                    )}

                    {(fileResult?.extended?.favicon || analysisResult?.extended?.favicon) && (
                      <div id="details-favicon">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                           <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>image</span> Favicon
                        </h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '0 16px' }}>
                          { (fileResult?.extended?.favicon?.dhash || analysisResult?.extended?.favicon?.dhash) && (
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '12px' }}>
                              <div className="font-label-caps text-on-surface-variant">dhash:</div>
                              <div className="font-data-mono text-primary">{fileResult?.extended?.favicon?.dhash || analysisResult?.extended?.favicon?.dhash}</div>
                            </div>
                          )}
                          { (fileResult?.extended?.favicon?.raw_md5 || analysisResult?.extended?.favicon?.raw_md5) && (
                            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '12px' }}>
                              <div className="font-label-caps text-on-surface-variant">raw md5:</div>
                              <div className="font-data-mono text-primary">{fileResult?.extended?.favicon?.raw_md5 || analysisResult?.extended?.favicon?.raw_md5}</div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {(fileResult?.extended?.networkRequests || analysisResult?.extended?.networkRequests) && (fileResult?.extended?.networkRequests?.length || analysisResult?.extended?.networkRequests?.length) ? (
                      <div id="details-network">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                           <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>lan</span> Network Requests / HTTPs Transactions
                        </h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', padding: '0 16px' }}>
                          {(fileResult?.extended?.networkRequests || analysisResult?.extended?.networkRequests || []).map((req, i) => (
                            <div key={i} style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.05)' }}>
                              <div className="font-data-mono text-primary" style={{ flex: '1 1 100%', wordBreak: 'break-all' }}>{req.url}</div>
                              {req.status && <div className="font-data-mono text-on-surface-variant">Status: {req.status}</div>}
                              {req.contentType && <div className="font-data-mono text-on-surface-variant">Type: {req.contentType}</div>}
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : null}

                    {(fileResult?.extended?.outgoingLinks || analysisResult?.extended?.outgoingLinks) && (fileResult?.extended?.outgoingLinks?.length || analysisResult?.extended?.outgoingLinks?.length) ? (
                      <div id="details-outbound">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                           <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>link</span> External Outbound Links
                        </h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '0 16px' }}>
                          {(fileResult?.extended?.outgoingLinks || analysisResult?.extended?.outgoingLinks || []).map((link, i) => (
                            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '12px', borderBottom: '1px solid rgba(255,255,255,0.02)', paddingBottom: '8px' }}>
                              <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: '16px' }}>public</span>
                              <div className="font-data-mono text-primary" style={{ wordBreak: 'break-all' }}>{link}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : null}

                    {(fileResult?.extended?.javascriptVariables || analysisResult?.extended?.javascriptVariables) && (fileResult?.extended?.javascriptVariables?.length || analysisResult?.extended?.javascriptVariables?.length) ? (
                      <div id="details-js">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                           <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>data_object</span> Javascript Global Variables
                        </h3>
                        <div style={{ overflowX: 'auto', padding: '0 16px' }}>
                          <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
                            <thead>
                              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                                <th className="font-label-caps text-on-surface-variant" style={{ padding: '8px 0' }}>Variable name</th>
                                <th className="font-label-caps text-on-surface-variant" style={{ padding: '8px 0' }}>Type</th>
                                <th className="font-label-caps text-on-surface-variant" style={{ padding: '8px 0' }}>Value</th>
                              </tr>
                            </thead>
                            <tbody>
                              {Array.isArray(fileResult?.extended?.javascriptVariables || analysisResult?.extended?.javascriptVariables) ? (
                                (fileResult?.extended?.javascriptVariables || analysisResult?.extended?.javascriptVariables || []).map((v: any, i: number) => (
                                  <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
                                    <td className="font-data-mono text-on-surface" style={{ padding: '8px 0' }}>{v.name || v.key || '-'}</td>
                                    <td className="font-data-mono text-on-surface-variant" style={{ padding: '8px 0' }}>{v.type || '-'}</td>
                                    <td className="font-data-mono text-on-surface" style={{ padding: '8px 0', wordBreak: 'break-all' }}>{String(v.value ?? '-')}</td>
                                  </tr>
                                ))
                              ) : (
                                Object.entries(fileResult?.extended?.javascriptVariables || analysisResult?.extended?.javascriptVariables || {}).map(([key, val]: [string, any], i: number) => (
                                  <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
                                    <td className="font-data-mono text-on-surface" style={{ padding: '8px 0' }}>{key}</td>
                                    <td className="font-data-mono text-on-surface-variant" style={{ padding: '8px 0' }}>-</td>
                                    <td className="font-data-mono text-on-surface" style={{ padding: '8px 0', wordBreak: 'break-all' }}>{String(val)}</td>
                                  </tr>
                                ))
                              )}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    ) : null}

                    {/* Table of Contents / Quick Links */}
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '24px', padding: '0 16px' }}>
                      {((fileResult?.extended?.redirectionChain || analysisResult?.extended?.redirectionChain)?.length ?? 0) > 0 && <a href="#details-redirection" className="font-label-caps" style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', textDecoration: 'none', color: 'var(--primary)' }}>Redirection</a>}
                      {(fileResult?.extended?.httpResponse || analysisResult?.extended?.httpResponse) && <a href="#details-http" className="font-label-caps" style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', textDecoration: 'none', color: 'var(--primary)' }}>HTTP</a>}
                      {(fileResult?.extended?.htmlInfo || analysisResult?.extended?.htmlInfo) && <a href="#details-html" className="font-label-caps" style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', textDecoration: 'none', color: 'var(--primary)' }}>HTML</a>}
                      {(fileResult?.extended?.magic || fileResult?.extended?.trid) && <a href="#details-file-id" className="font-label-caps" style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', textDecoration: 'none', color: 'var(--primary)' }}>File ID</a>}
                      {fileResult?.extended?.peInfo && <a href="#details-pe-info" className="font-label-caps" style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', textDecoration: 'none', color: 'var(--primary)' }}>PE Info</a>}
                      {fileResult?.extended?.signatureInfo && <a href="#details-signature" className="font-label-caps" style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', textDecoration: 'none', color: 'var(--primary)' }}>Signature</a>}
                      {fileResult?.extended?.exiftool && <a href="#details-exif" className="font-label-caps" style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', textDecoration: 'none', color: 'var(--primary)' }}>ExifTool</a>}
                      {fileResult?.extended?.packers && <a href="#details-packers" className="font-label-caps" style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', textDecoration: 'none', color: 'var(--primary)' }}>Packers</a>}
                    </div>

                    {/* File Properties */}
                    {(fileResult?.extended?.magic || fileResult?.extended?.trid) && (
                      <div id="details-file-id">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                           <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>fingerprint</span> File Identification
                        </h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '0 16px' }}>
                          {fileResult?.extended?.magic && (
                            <div>
                              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '8px' }}>Magic</div>
                              <div className="font-data-mono text-primary">{fileResult?.extended?.magic}</div>
                            </div>
                          )}
                          {fileResult?.extended?.trid && fileResult.extended.trid.length > 0 && (
                            <div>
                              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '8px' }}>TrID</div>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                {fileResult.extended.trid.map((t, i) => (
                                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.02)', paddingBottom: '4px' }}>
                                    <div className="font-data-mono text-on-surface">{t.file_type}</div>
                                    <div className="font-data-mono text-on-surface-variant">{t.probability.toFixed(1)}%</div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {fileResult?.extended?.peInfo && (
                      <div id="details-pe-info">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                           <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>integration_instructions</span> PE Info
                        </h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '0 16px' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            {fileResult.extended.peInfo.imphash && (
                              <div style={{ display: 'flex' }}>
                                <div className="font-label-caps text-on-surface-variant" style={{ width: '180px' }}>Imphash</div>
                                <div className="font-data-mono text-primary" style={{ wordBreak: 'break-all' }}>{fileResult.extended.peInfo.imphash}</div>
                              </div>
                            )}
                            {fileResult.extended.peInfo.machine_type && (
                              <div style={{ display: 'flex' }}>
                                <div className="font-label-caps text-on-surface-variant" style={{ width: '180px' }}>Machine Type</div>
                                <div className="font-data-mono text-on-surface">{fileResult.extended.peInfo.machine_type}</div>
                              </div>
                            )}
                            {fileResult.extended.peInfo.entry_point && (
                              <div style={{ display: 'flex' }}>
                                <div className="font-label-caps text-on-surface-variant" style={{ width: '180px' }}>Entry Point</div>
                                <div className="font-data-mono text-on-surface">{fileResult.extended.peInfo.entry_point}</div>
                              </div>
                            )}
                          </div>
                          
                          {fileResult.extended.peInfo.sections && fileResult.extended.peInfo.sections.length > 0 && (
                            <div>
                              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '8px' }}>Sections</div>
                              <div style={{ overflowX: 'auto' }}>
                                <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
                                  <thead>
                                    <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                                      <th className="font-label-caps text-on-surface-variant" style={{ padding: '8px 0' }}>Name</th>
                                      <th className="font-label-caps text-on-surface-variant" style={{ padding: '8px 0' }}>Entropy</th>
                                      <th className="font-label-caps text-on-surface-variant" style={{ padding: '8px 0' }}>Virtual Size</th>
                                      <th className="font-label-caps text-on-surface-variant" style={{ padding: '8px 0' }}>Raw Size</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {fileResult.extended.peInfo.sections.map((s, i) => (
                                      <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
                                        <td className="font-data-mono text-primary" style={{ padding: '8px 0' }}>{s.name}</td>
                                        <td className="font-data-mono text-on-surface" style={{ padding: '8px 0' }}>{s.entropy.toFixed(2)}</td>
                                        <td className="font-data-mono text-on-surface-variant" style={{ padding: '8px 0' }}>{s.virtual_size}</td>
                                        <td className="font-data-mono text-on-surface-variant" style={{ padding: '8px 0' }}>{s.raw_size}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            </div>
                          )}

                          {fileResult.extended.peInfo.import_list && fileResult.extended.peInfo.import_list.length > 0 && (
                            <div>
                              <div className="font-label-caps text-on-surface-variant" style={{ marginBottom: '8px' }}>Imports</div>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                {fileResult.extended.peInfo.import_list.map((imp, i) => (
                                  <div key={i} style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.05)' }}>
                                    <div className="font-data-mono text-primary" style={{ marginBottom: '8px', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '4px' }}>{imp.library_name}</div>
                                    <div className="font-data-mono text-on-surface" style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                                      {imp.imported_functions.map((func, j) => (
                                        <span key={j} style={{ background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: '4px' }}>{func}</span>
                                      ))}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {fileResult?.extended?.signatureInfo && Object.keys(fileResult.extended.signatureInfo).length > 0 && (
                      <div id="details-signature">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                           <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>verified_user</span> Signature Info
                        </h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '0 16px' }}>
                          {Object.entries(fileResult.extended.signatureInfo).map(([key, val]) => (
                            <div key={key} style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.02)', paddingBottom: '8px' }}>
                              <div className="font-data-mono text-on-surface-variant" style={{ width: '180px', flexShrink: 0 }}>{key}</div>
                              <div className="font-data-mono text-on-surface" style={{ wordBreak: 'break-all' }}>{String(val)}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {fileResult?.extended?.exiftool && Object.keys(fileResult.extended.exiftool).length > 0 && (
                      <div id="details-exif">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                           <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>image_search</span> ExifTool
                        </h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '0 16px' }}>
                          {Object.entries(fileResult.extended.exiftool).map(([key, val]) => (
                            <div key={key} style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.02)', paddingBottom: '8px' }}>
                              <div className="font-data-mono text-on-surface-variant" style={{ width: '220px', flexShrink: 0 }}>{key}</div>
                              <div className="font-data-mono text-on-surface" style={{ wordBreak: 'break-all' }}>{String(val)}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {fileResult?.extended?.packers && Object.keys(fileResult.extended.packers).length > 0 && (
                      <div id="details-packers">
                        <h3 className="font-headline-sm text-on-surface" style={{ marginBottom: '24px', borderBottom: '1px solid var(--border)', paddingBottom: '12px', background: 'rgba(255,255,255,0.02)', padding: '12px 16px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                           <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>inventory_2</span> Packers
                        </h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', padding: '0 16px' }}>
                          {Object.entries(fileResult.extended.packers).map(([key, val]) => (
                            <div key={key} style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.02)', paddingBottom: '8px' }}>
                              <div className="font-data-mono text-on-surface-variant" style={{ width: '180px', flexShrink: 0 }}>{key}</div>
                              <div className="font-data-mono text-on-surface" style={{ wordBreak: 'break-all' }}>{String(val)}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
              )}

              {activeTab === 'RELATIONS' && (
                <RelationsCard relations={fileResult?.relations || analysisResult?.relations} />
              )}

              {activeTab === 'BEHAVIOR' && (
                <BehaviorCard mitreAttack={fileResult?.extended?.mitreAttack} />
              )}

              {activeTab === 'COMMUNITY' && (
                <CommunityCommentsCard comments={fileResult?.comments || analysisResult?.comments} />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
