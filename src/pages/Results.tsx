import React, { useEffect, useState } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { Gauge } from '../components/Gauge';
import { EngineGrid } from '../components/EngineGrid';
import { AiSummary } from '../components/AiSummary';
import { 
  pollAnalysis, 
  lookupHash, 
  lookupDomain, 
  getUrlReport, 
  scanUrl,
  lookupIpGeo,
  NormalizedAnalysis, 
  NormalizedFile, 
  NormalizedDomain,
  NormalizedIp,
  isValidHash,
  isValidIp,
  detectInputType
} from '../services/api';
import { RelationsCard } from '../components/RelationsCard';
import { BehaviorCard } from '../components/BehaviorCard';
import { CommunityCommentsCard } from '../components/CommunityCommentsCard';
import { analyzeWithPhishGuard, PhishGuardResult } from '../services/phishguard';
import { runWebFoxRecon, WebFoxReconResult } from '../services/webfox';
import { PhishGuardCard } from '../components/PhishGuardCard';
import { WebFoxCard } from '../components/WebFoxCard';
import { AutomaticYaraCard } from '../components/AutomaticYaraCard';
import { isImageFile, extractImageForensics } from '../services/imageForensics';
import { 
  getFileCategory, 
  extractAudioForensics, 
  extractVideoForensics, 
  extractDocumentForensics, 
  extractArchiveForensics 
} from '../services/mediaForensics';
import { ImageForensicsCard } from '../components/ImageForensicsCard';
import { AudioForensicsCard } from '../components/AudioForensicsCard';
import { VideoForensicsCard } from '../components/VideoForensicsCard';
import { DocumentForensicsCard } from '../components/DocumentForensicsCard';
import { ArchiveForensicsCard } from '../components/ArchiveForensicsCard';
import { CertInspectorCard } from '../components/CertInspectorCard';
import { ThreatFeedCard } from '../components/ThreatFeedCard';
import { generatePdfThreatReport } from '../utils/pdfExport';
import { addScanHistoryItem } from '../services/historyStore';
import { getCachedItem, setCachedItem } from '../services/cache';
import { formatRelativeTime, formatBytes } from '../utils/sanitize';

type Tab = 'DETECTION' | 'DETAILS' | 'BEHAVIOR' | 'RELATIONS' | 'COMMUNITY' | 'SUMMARY';

export const Results: React.FC = () => {
  const { id: pathId, hash: pathHash, query: pathQuery, tab } = useParams();
  const [searchParams] = useSearchParams();
  
  const rawTarget = pathId || pathHash || pathQuery || searchParams.get('id') || searchParams.get('hash') || searchParams.get('q') || searchParams.get('query') || '';

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [analysisResult, setAnalysisResult] = useState<NormalizedAnalysis | null>(null);
  const [fileResult, setFileResult] = useState<NormalizedFile | null>(null);
  const [domainResult, setDomainResult] = useState<NormalizedDomain | null>(null);
  const [ipResult, setIpResult] = useState<NormalizedIp | null>(null);
  const [behaviorData, setBehaviorData] = useState<any | null>(null);

  // PhishGuard & WebFox Live Integration (STRICTLY for URLs & Domains)
  const [phishResult, setPhishResult] = useState<PhishGuardResult | null>(null);
  const [webfoxResult, setWebfoxResult] = useState<WebFoxReconResult | null>(null);
  const [isWebfoxLoading, setIsWebfoxLoading] = useState<boolean>(false);

  const [activeTab, setActiveTab] = useState<Tab>('DETECTION');
  const [activeSection, setActiveSection] = useState<string>('Basic Properties');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [communityVote, setCommunityVote] = useState<'up' | 'down' | null>(null);
  const [isExportingPdf, setIsExportingPdf] = useState(false);

  const navigate = useNavigate();

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  useEffect(() => {
    if (tab) {
      const upperTab = tab.toUpperCase() as Tab;
      if (['DETECTION', 'DETAILS', 'BEHAVIOR', 'RELATIONS', 'COMMUNITY', 'SUMMARY'].includes(upperTab)) {
        setActiveTab(upperTab);
      }
    }
  }, [tab]);

  useEffect(() => {
    if (!rawTarget) {
      navigate('/');
      return;
    }

    const fetchData = async () => {
      setLoading(true);
      setError(null);

      const target = rawTarget.trim();
      const detected = detectInputType(target);
      const isHash = isValidHash(target) || detected === 'hash';
      const isIp = isValidIp(target) || detected === 'ip';
      
      const isAnalysisToken = target.startsWith('u-') || 
        target.includes(':') || 
        (target.length >= 44 && !isHash && /[+/=]/.test(target));

      // ── Check Fast Cache first ───────────────────────────────────────────
      const cached = getCachedItem<any>(target);
      if (cached) {
        if (cached.sha256 || cached.names) setFileResult(cached);
        else if (cached.domain) setDomainResult(cached);
        else if (cached.ip) setIpResult(cached);
        else setAnalysisResult(cached);
        setLoading(false);
      }

      // ── 1. Cryptographic Hash Search (Direct File Lookup) ─────────────────
      if (isHash) {
        try {
          const data = await lookupHash(target);
          setFileResult(data);
          setCachedItem(target, data);

          addScanHistoryItem({
            id: data.id || target,
            target,
            type: 'file',
            name: data.name || data.names?.[0] || target,
            hash: data.sha256,
            verdict: data.verdict || (data.stats?.malicious > 0 ? 'malicious' : 'clean'),
            threatScore: data.stats?.malicious || 0,
            maliciousCount: data.stats?.malicious || 0,
            totalEngines: data.engines?.length || 70,
            fileSize: data.size
          });

          try {
            const behaviorRes = await fetch(`/api/vt/files/${target}/behaviours?limit=5`);
            if (behaviorRes.ok) {
              const behaviorJson = await behaviorRes.json();
              setBehaviorData(behaviorJson);
            }
          } catch (_) {}
        } catch (err: any) {
          setError(err.message || 'Failed to fetch file analysis from VirusTotal.');
        } finally {
          setLoading(false);
        }
        return;
      }

      // ── 2. VirusTotal Analysis Token (Fresh File or URL Scan) ──────────────
      if (isAnalysisToken) {
        try {
          const analysisData = await pollAnalysis(target, (progress) => {
            setAnalysisResult(progress);
          });
          setAnalysisResult(analysisData);
          setCachedItem(target, analysisData);

          if (analysisData.hash) {
            try {
              const fullFileData = await lookupHash(analysisData.hash);
              setFileResult(fullFileData);
              setCachedItem(analysisData.hash, fullFileData);

              addScanHistoryItem({
                id: fullFileData.id || analysisData.hash,
                target: analysisData.hash,
                type: 'file',
                name: fullFileData.name || fullFileData.names?.[0] || 'Sample File',
                hash: fullFileData.sha256,
                verdict: fullFileData.verdict || (fullFileData.stats?.malicious > 0 ? 'malicious' : 'clean'),
                threatScore: fullFileData.stats?.malicious || 0,
                maliciousCount: fullFileData.stats?.malicious || 0,
                totalEngines: fullFileData.engines?.length || 70,
                fileSize: fullFileData.size
              });

              try {
                const behaviorRes = await fetch(`/api/vt/files/${analysisData.hash}/behaviours?limit=5`);
                if (behaviorRes.ok) setBehaviorData(await behaviorRes.json());
              } catch (_) {}
            } catch (_) {}
          } else if (analysisData.url) {
            addScanHistoryItem({
              id: analysisData.id || target,
              target: analysisData.url,
              type: 'url',
              name: analysisData.url,
              verdict: analysisData.verdict || (analysisData.stats?.malicious > 0 ? 'malicious' : 'clean'),
              threatScore: analysisData.stats?.malicious || 0,
              maliciousCount: analysisData.stats?.malicious || 0,
              totalEngines: analysisData.engines?.length || 70
            });

            try {
              setPhishResult(analyzeWithPhishGuard(analysisData.url));
            } catch (_) {}
            setIsWebfoxLoading(true);
            runWebFoxRecon(analysisData.url)
              .then(wf => setWebfoxResult(wf))
              .catch(() => {})
              .finally(() => setIsWebfoxLoading(false));
          }
        } catch (err: any) {
          try {
            const fallbackData = await lookupHash(target);
            setFileResult(fallbackData);
          } catch (_) {
            setError(err.message || 'Analysis processing in progress. Please refresh in a few moments.');
          }
        } finally {
          setLoading(false);
        }
        return;
      }

      // ── 3. IP Address Search ──────────────────────────────────────────────
      if (isIp) {
        try {
          const ipData = await lookupIpGeo(target);
          setIpResult(ipData);
          setCachedItem(target, ipData);

          addScanHistoryItem({
            id: ipData.ip || target,
            target,
            type: 'ip',
            name: `${ipData.ip} (${ipData.country || 'Unknown'})`,
            verdict: (ipData.stats?.malicious || 0) > 0 ? 'malicious' : 'clean',
            threatScore: ipData.stats?.malicious || 0,
            maliciousCount: ipData.stats?.malicious || 0,
            totalEngines: ipData.engines?.length || 70
          });
        } catch (err: any) {
          setError(err.message || 'Failed to lookup IP address.');
        } finally {
          setLoading(false);
        }
        return;
      }

      // ── 4. Domain Name Search ─────────────────────────────────────────────
      const isPlainDomain = detected === 'domain' || (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(target) && !target.includes('/'));
      if (isPlainDomain) {
        const targetUrl = `https://${target}`;
        try {
          setPhishResult(analyzeWithPhishGuard(targetUrl));
        } catch (_) {}
        setIsWebfoxLoading(true);
        runWebFoxRecon(targetUrl)
          .then(wf => setWebfoxResult(wf))
          .catch(() => {})
          .finally(() => setIsWebfoxLoading(false));

        try {
          const domainData = await lookupDomain(target);
          setDomainResult(domainData);
          setCachedItem(target, domainData);

          addScanHistoryItem({
            id: domainData.domain || target,
            target,
            type: 'domain',
            name: domainData.domain,
            verdict: (domainData.stats?.malicious || 0) > 0 ? 'malicious' : 'clean',
            threatScore: domainData.stats?.malicious || 0,
            maliciousCount: domainData.stats?.malicious || 0,
            totalEngines: domainData.engines?.length || 70
          });
        } catch (err: any) {
          setError(err.message || 'Failed to fetch domain intelligence.');
        } finally {
          setLoading(false);
        }
        return;
      }

      // ── 5. URL Search / Direct Submission ─────────────────────────────────
      const targetUrl = target.startsWith('http') ? target : `https://${target}`;
      try {
        setPhishResult(analyzeWithPhishGuard(targetUrl));
      } catch (_) {}
      setIsWebfoxLoading(true);
      runWebFoxRecon(targetUrl)
        .then(wf => setWebfoxResult(wf))
        .catch(() => {})
        .finally(() => setIsWebfoxLoading(false));

      try {
        const report = await getUrlReport(targetUrl);
        setAnalysisResult(report);
        setCachedItem(target, report);

        addScanHistoryItem({
          id: report.id || target,
          target: targetUrl,
          type: 'url',
          name: targetUrl,
          verdict: report.verdict || ((report.stats?.malicious || 0) > 0 ? 'malicious' : 'clean'),
          threatScore: report.stats?.malicious || 0,
          maliciousCount: report.stats?.malicious || 0,
          totalEngines: report.engines?.length || 70
        });
      } catch (_) {
        try {
          const scanRes = await scanUrl(targetUrl);
          if (scanRes?.data?.id) {
            const data = await pollAnalysis(scanRes.data.id, (progress) => {
              setAnalysisResult(progress);
            });
            setAnalysisResult(data);
          }
        } catch (err: any) {
          setError(err.message || 'Failed to scan URL.');
        }
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [rawTarget, navigate]);

  if (loading && !analysisResult && !fileResult && !domainResult && !ipResult) {
    return (
      <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '100px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <div className="digital-grid"></div>
        <div className="glow-cyan"></div>
        <div className="container" style={{ position: 'relative', zIndex: 10, textAlign: 'center', marginTop: '100px' }}>
          <span className="material-symbols-outlined text-primary spin" style={{ fontSize: '64px', marginBottom: '16px' }}>sync</span>
          <h2 className="font-display-lg text-on-surface">Analyzing Data...</h2>
          <p className="font-body-md text-on-surface-variant">Gathering threat intelligence from 70+ security vendors.</p>
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
            <h2 className="font-display-lg text-secondary" style={{ marginBottom: '16px' }}>Scan Notice</h2>
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
  const isFile = Boolean(fileResult || (analysisResult && !analysisResult.url && !analysisResult.hash));
  const stats = fileResult?.stats || analysisResult?.stats || domainResult?.stats || ipResult?.stats;
  const engines = fileResult?.engines || analysisResult?.engines || domainResult?.engines || ipResult?.engines || [];

  const score = stats?.malicious || 0;
  const total = (stats?.malicious || 0) + (stats?.undetected || 0) + (stats?.harmless || 0) + (stats?.suspicious || 0) + (stats?.timeout || 0) || engines.length || 60;

  // Visual filetype extension label
  const fileName = fileResult?.names?.[0] || fileResult?.name || analysisResult?.fileName || (isFile ? 'sample.bin' : '');
  const fileExt: string = (fileName && fileName.includes('.') ? fileName.split('.').pop()?.toUpperCase() : (fileResult?.type ? fileResult.type.slice(0, 4).toUpperCase() : 'FILE')) || 'FILE';
  const displayHash = fileResult?.sha256 || fileResult?.md5 || analysisResult?.hash || domainResult?.domain || ipResult?.ip || rawTarget;
  const lastAnalysisTs = fileResult?.lastSeen || analysisResult?.date || domainResult?.lastSeen || ipResult?.lastSeen;

  // ── Multi-Format Specialized Forensics Engines & Deduplication Logic ───────
  const fileCategory = isFile ? getFileCategory(fileResult, rawTarget) : 'generic';
  
  const isImage = fileCategory === 'image' || isImageFile(fileResult, rawTarget);
  const imageForensics = isImage ? extractImageForensics(fileResult) : null;
  const audioForensics = fileCategory === 'audio' ? extractAudioForensics(fileResult) : null;
  const videoForensics = fileCategory === 'video' ? extractVideoForensics(fileResult) : null;
  const docForensics = fileCategory === 'document' ? extractDocumentForensics(fileResult) : null;
  const archiveForensics = fileCategory === 'archive' ? extractArchiveForensics(fileResult) : null;

  const hasSpecializedModule = Boolean(isImage || audioForensics || videoForensics || docForensics || archiveForensics);

  const handleExportPdf = () => {
    const data = fileResult || analysisResult || domainResult || ipResult;
    if (!data) return;
    setIsExportingPdf(true);
    try {
      const summaryText = score > 0 
        ? `🚨 VERDICT: CRITICAL / SUSPICIOUS (${score}/${total} vendors flagged malicious). Target exhibits indicators of compromise (IOC), suspicious signature patterns, or hostile communication telemetry.\n• Immediate Action: Quarantine endpoint, block SHA-256 hash/IP at firewall boundary, and inspect SIEM/EDR logs.`
        : `🛡️ VERDICT: VERIFIED CLEAN (0/${total} detections). Zero security vendors flagged this ${isFile ? 'file' : 'target'}.\n• Cryptographic integrity, entropy, and structural headers check out cleanly. Safe to use under baseline corporate policy.`;

      generatePdfThreatReport({
        threatData: data,
        targetType: isFile ? 'file' : domainResult ? 'domain' : ipResult ? 'ip' : 'url',
        aiSummaryText: summaryText,
        imageForensics,
        audioForensics,
        videoForensics,
        docForensics,
        archiveForensics,
        yaraMatches: fileResult?.extended?.crowdsourcedYara
      });
    } finally {
      setTimeout(() => setIsExportingPdf(false), 1000);
    }
  };

  const handleTabChange = (t: Tab) => {
    setActiveTab(t);
    if (t === 'DETECTION') setActiveSection('Security Vendors');
    if (t === 'DETAILS') {
      if (isImage) setActiveSection('Image Forensics');
      else if (audioForensics) setActiveSection('Audio Forensics');
      else if (videoForensics) setActiveSection('Video Forensics');
      else if (docForensics) setActiveSection('Document Forensics');
      else if (archiveForensics) setActiveSection('Archive Forensics');
      else setActiveSection('Basic Properties');
    }
    if (t === 'COMMUNITY') setActiveSection('Comments');
    if (t === 'BEHAVIOR') setActiveSection('Behavior');
    if (t === 'RELATIONS') setActiveSection('Relations');
  };

  return (
    <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '80px', paddingBottom: '64px', backgroundColor: '#0b111e', color: '#c3c8d4' }}>
      <div className="digital-grid" style={{ opacity: 0.3 }}></div>

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1280px' }}>

        {isPending && (
          <div style={{ padding: '14px 20px', marginBottom: '24px', background: 'rgba(0, 242, 255, 0.08)', border: '1px solid rgba(0, 242, 255, 0.3)', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '14px' }}>
            <span className="material-symbols-outlined text-primary spin">sync</span>
            <div>
              <div className="font-label-caps text-primary">Analysis in progress...</div>
              <p className="font-code-sm text-on-surface-variant" style={{ margin: 0 }}>Results will update automatically.</p>
            </div>
          </div>
        )}

        {/* ── TOP HEADER CARD (VIRUSTOTAL AUTHENTIC DESIGN) ────────────────────── */}
        <div style={{
          display: 'flex',
          gap: '20px',
          marginBottom: '24px',
          alignItems: 'stretch',
          flexWrap: 'wrap'
        }}>
          {/* Left Gauge Box */}
          <div style={{
            background: '#111927',
            border: '1px solid #1e293b',
            borderRadius: '10px',
            padding: '24px 20px',
            width: '180px',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0
          }}>
            <Gauge score={score} total={total} size={110} />
            
            <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '11px', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Community Score
              </span>
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', background: 'rgba(255,255,255,0.04)', padding: '3px 10px', borderRadius: '999px', border: '1px solid rgba(255,255,255,0.08)' }}>
                <button 
                  onClick={() => setCommunityVote(communityVote === 'up' ? null : 'up')}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: communityVote === 'up' ? '#00ffa3' : '#64748b', display: 'flex', padding: 0 }}
                  title="Vote Safe"
                >
                  <span className="material-symbols-outlined" style={{ fontSize: '15px' }}>thumb_up</span>
                </button>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#cbd5e1' }}>
                  {communityVote === 'up' ? '+1' : communityVote === 'down' ? '-1' : '-'}
                </span>
                <button 
                  onClick={() => setCommunityVote(communityVote === 'down' ? null : 'down')}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: communityVote === 'down' ? '#ff2a5f' : '#64748b', display: 'flex', padding: 0 }}
                  title="Vote Malicious"
                >
                  <span className="material-symbols-outlined" style={{ fontSize: '15px' }}>thumb_down</span>
                </button>
              </div>
            </div>
          </div>

          {/* Right Info Box */}
          <div style={{
            background: '#111927',
            border: '1px solid #1e293b',
            borderRadius: '10px',
            padding: '24px 28px',
            flex: '1 1 500px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between'
          }}>
            {/* Top Status + Actions Row */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                {score === 0 ? (
                  <>
                    <span className="material-symbols-outlined" style={{ color: '#00ffa3', fontSize: '22px' }}>check_circle</span>
                    <span style={{ color: '#00ffa3', fontSize: '14px', fontWeight: 600 }}>
                      No security vendors flagged this {isFile ? 'file' : 'target'} as malicious
                    </span>
                  </>
                ) : (
                  <>
                    <span className="material-symbols-outlined" style={{ color: '#ff2a5f', fontSize: '22px' }}>cancel</span>
                    <span style={{ color: '#ff2a5f', fontSize: '14px', fontWeight: 600 }}>
                      {score} security vendor{score > 1 ? 's' : ''} flagged this {isFile ? 'file' : 'target'} as malicious
                    </span>
                  </>
                )}
              </div>

              {/* Action Buttons (Reanalyze, Similar, Export PDF, More) */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <button 
                  className="font-code-sm"
                  onClick={() => window.location.reload()}
                  style={{
                    background: 'transparent',
                    border: '1px solid #334155',
                    color: '#cbd5e1',
                    borderRadius: '6px',
                    padding: '5px 12px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '12px',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.borderColor = '#00f2ff'; e.currentTarget.style.color = '#fff'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.borderColor = '#334155'; e.currentTarget.style.color = '#cbd5e1'; }}
                >
                  <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>sync</span>
                  Reanalyze
                </button>

                <button 
                  className="font-code-sm"
                  style={{
                    background: 'transparent',
                    border: '1px solid #334155',
                    color: '#cbd5e1',
                    borderRadius: '6px',
                    padding: '5px 12px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '12px'
                  }}
                  onClick={() => navigate(`/search?query=${encodeURIComponent(displayHash)}`)}
                >
                  <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>compare_arrows</span>
                  Similar
                </button>

                {/* 1-Click Executive PDF Report Download */}
                <button 
                  className="font-code-sm"
                  onClick={handleExportPdf}
                  disabled={isExportingPdf}
                  style={{
                    background: 'linear-gradient(135deg, rgba(0, 242, 255, 0.15), rgba(185, 66, 255, 0.15))',
                    border: '1px solid rgba(0, 242, 255, 0.4)',
                    color: '#00f2ff',
                    borderRadius: '6px',
                    padding: '5px 12px',
                    cursor: isExportingPdf ? 'wait' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '12px',
                    fontWeight: 700,
                    boxShadow: '0 0 12px rgba(0,242,255,0.15)',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.boxShadow = '0 0 20px rgba(0,242,255,0.3)'; e.currentTarget.style.borderColor = '#00f2ff'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.boxShadow = '0 0 12px rgba(0,242,255,0.15)'; e.currentTarget.style.borderColor = 'rgba(0, 242, 255, 0.4)'; }}
                >
                  <span className="material-symbols-outlined" style={{ fontSize: '15px' }}>
                    {isExportingPdf ? 'sync' : 'picture_as_pdf'}
                  </span>
                  {isExportingPdf ? 'Generating...' : 'Export PDF'}
                </button>

                <button 
                  className="font-code-sm"
                  style={{
                    background: 'transparent',
                    border: '1px solid #334155',
                    color: '#cbd5e1',
                    borderRadius: '6px',
                    padding: '5px 10px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    fontSize: '12px'
                  }}
                >
                  More
                  <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>expand_more</span>
                </button>
              </div>
            </div>

            {/* Target Hash & Meaningful Name */}
            <div style={{ marginBottom: '18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                <span className="font-data-mono" style={{ fontSize: '15px', color: '#e2e8f0', wordBreak: 'break-all', fontWeight: 600 }}>
                  {displayHash}
                </span>
                <button
                  onClick={() => handleCopy(displayHash, 'header_hash')}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'header_hash' ? '#00ffa3' : '#64748b', display: 'flex', padding: 0 }}
                  title="Copy Hash"
                >
                  <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>
                    {copiedKey === 'header_hash' ? 'check' : 'content_copy'}
                  </span>
                </button>
              </div>

              {fileName && (
                <div style={{ fontSize: '14px', color: '#94a3b8', marginBottom: '8px' }}>
                  {fileName}
                </div>
              )}

              {/* Tags Badges */}
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {fileResult?.tags && fileResult.tags.length > 0 ? (
                  fileResult.tags.slice(0, 6).map((t, idx) => (
                    <span 
                      key={idx}
                      style={{
                        background: 'rgba(0, 242, 255, 0.08)',
                        border: '1px solid rgba(0, 242, 255, 0.2)',
                        color: '#38bdf8',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontFamily: 'var(--font-mono)'
                      }}
                    >
                      {t}
                    </span>
                  ))
                ) : (
                  <span 
                    style={{
                      background: 'rgba(0, 242, 255, 0.08)',
                      border: '1px solid rgba(0, 242, 255, 0.2)',
                      color: '#38bdf8',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)'
                    }}
                  >
                    {fileExt.toLowerCase()}
                  </span>
                )}

                {/* Specialized Telemetry Header Badges */}
                {isImage && imageForensics && imageForensics.geometry.width > 0 && (
                  <>
                    <span style={{ background: 'rgba(0, 255, 163, 0.08)', border: '1px solid rgba(0, 255, 163, 0.25)', color: '#00ffa3', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                      {imageForensics.geometry.width}×{imageForensics.geometry.height}
                    </span>
                    <span style={{ background: 'rgba(251, 146, 60, 0.08)', border: '1px solid rgba(251, 146, 60, 0.25)', color: '#fb923c', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                      {imageForensics.geometry.megapixels}
                    </span>
                  </>
                )}

                {audioForensics && (
                  <span style={{ background: 'rgba(236, 72, 153, 0.08)', border: '1px solid rgba(236, 72, 153, 0.25)', color: '#ec4899', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                    {audioForensics.bitrate || audioForensics.format}
                  </span>
                )}

                {videoForensics && videoForensics.dimensions.width > 0 && (
                  <span style={{ background: 'rgba(168, 85, 247, 0.08)', border: '1px solid rgba(168, 85, 247, 0.25)', color: '#a855f7', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                    {videoForensics.dimensions.width}×{videoForensics.dimensions.height} ({videoForensics.dimensions.aspectRatio})
                  </span>
                )}

                {docForensics && docForensics.pageCount && (
                  <span style={{ background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.25)', color: '#ef4444', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                    {docForensics.pageCount} Pages
                  </span>
                )}

                {archiveForensics && archiveForensics.fileCount > 0 && (
                  <span style={{ background: 'rgba(234, 179, 8, 0.08)', border: '1px solid rgba(234, 179, 8, 0.25)', color: '#eab308', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                    {archiveForensics.fileCount} Files
                  </span>
                )}
              </div>
            </div>

            {/* Bottom Metadata Info Row */}
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              borderTop: '1px solid rgba(255,255,255,0.05)',
              paddingTop: '14px',
              flexWrap: 'wrap',
              gap: '16px'
            }}>
              <div style={{ display: 'flex', gap: '32px', flexWrap: 'wrap' }}>
                {fileResult?.size ? (
                  <div>
                    <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Size</div>
                    <div style={{ fontSize: '13px', color: '#e2e8f0', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                      {(fileResult.size / 1024).toFixed(2)} KB
                    </div>
                  </div>
                ) : null}

                {lastAnalysisTs ? (
                  <div>
                    <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Last Analysis Date</div>
                    <div 
                      style={{ fontSize: '13px', color: '#e2e8f0', fontFamily: 'var(--font-mono)', marginTop: '2px' }}
                      title={new Date(lastAnalysisTs * 1000).toUTCString()}
                    >
                      {formatRelativeTime(lastAnalysisTs)}
                    </div>
                  </div>
                ) : null}
              </div>

              {/* Filetype Icon Badge */}
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: '50%',
                background: '#1e293b',
                border: '1px solid #334155',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#94a3b8'
              }}>
                <span className="material-symbols-outlined" style={{ fontSize: '18px', color: '#38bdf8' }}>
                  {isImage ? 'image' : audioForensics ? 'graphic_eq' : videoForensics ? 'movie' : docForensics ? 'description' : archiveForensics ? 'folder_zip' : isFile ? 'description' : 'public'}
                </span>
                <span style={{ fontSize: '8px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#e2e8f0' }}>
                  {fileExt.slice(0, 3)}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* ── TABS NAVIGATION ROW ──────────────────────────────────────────────── */}
        <div style={{
          display: 'flex',
          borderBottom: '1px solid #1e293b',
          marginBottom: '20px',
          gap: '4px',
          overflowX: 'auto'
        }}>
          {(['DETECTION', 'DETAILS', 'BEHAVIOR', 'RELATIONS', 'COMMUNITY', 'SUMMARY'] as Tab[]).map((t) => {
            const isActive = activeTab === t;
            return (
              <button
                key={t}
                onClick={() => handleTabChange(t)}
                style={{
                  background: 'none',
                  border: 'none',
                  borderBottom: isActive ? '2px solid #00f2ff' : '2px solid transparent',
                  padding: '10px 20px',
                  color: isActive ? '#00f2ff' : '#94a3b8',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '12px',
                  fontWeight: isActive ? 700 : 500,
                  letterSpacing: '0.05em',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  whiteSpace: 'nowrap'
                }}
                onMouseEnter={(e) => { if (!isActive) e.currentTarget.style.color = '#fff'; }}
                onMouseLeave={(e) => { if (!isActive) e.currentTarget.style.color = '#94a3b8'; }}
              >
                {t}
              </button>
            );
          })}
        </div>

        {/* ── TAB 1: DETECTION ─────────────────────────────────────────────────── */}
        {activeTab === 'DETECTION' && (
          <div style={{
            background: '#111927',
            border: '1px solid #1e293b',
            borderRadius: '10px',
            padding: '28px 32px'
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '20px',
              borderBottom: '1px solid #1e293b',
              paddingBottom: '14px',
              flexWrap: 'wrap',
              gap: '10px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                  Security vendors' analysis
                </h3>
                <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#64748b' }}>info</span>
              </div>

              <div style={{ fontSize: '12px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                Do you want to automate checks?
              </div>
            </div>

            {engines.length > 0 ? (
              <EngineGrid results={engines} />
            ) : (
              <div style={{ textAlign: 'center', padding: '48px', color: '#64748b' }} className="font-data-mono">
                {isPending ? "Waiting for engines to return results..." : "No engine data available."}
              </div>
            )}
          </div>
        )}

        {/* ── TAB 2: DETAILS (WITH STRICT DEDUPLICATION) ───────────────────────── */}
        {activeTab === 'DETAILS' && (
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(12, 1fr)',
            gap: '24px'
          }}>
            {/* Sidebar Table of Contents */}
            <div style={{ gridColumn: 'span 3' }}>
              <div style={{
                background: '#111927',
                border: '1px solid #1e293b',
                borderRadius: '10px',
                padding: '20px 16px',
                position: 'sticky',
                top: '100px'
              }}>
                <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', marginBottom: '12px', paddingLeft: '8px' }}>
                  Table of Contents
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {[
                    ...(isImage && imageForensics ? [{ id: 'details-image-forensics', label: '🖼️ Image Forensics & Stego' }] : []),
                    ...(audioForensics ? [{ id: 'details-audio-forensics', label: '🎧 Audio Stream & ID3 Forensics' }] : []),
                    ...(videoForensics ? [{ id: 'details-video-forensics', label: '🎬 Video Stream & Codecs' }] : []),
                    ...(docForensics ? [{ id: 'details-doc-forensics', label: '📄 Document Security & Macros' }] : []),
                    ...(archiveForensics ? [{ id: 'details-archive-forensics', label: '📦 Archive & Container Forensics' }] : []),
                    { id: 'details-basic', label: 'Basic properties' },
                    { id: 'details-history', label: 'History' },
                    { id: 'details-names', label: 'Names' },
                    { id: 'details-yara', label: 'YARA Rules & Signatures' },
                    ...(fileResult?.extended?.peInfo ? [{ id: 'details-pe', label: 'PE Headers & Sections' }] : []),
                    ...(fileResult?.extended?.mitreAttack ? [{ id: 'details-mitre', label: 'MITRE ATT&CK Matrix' }] : []),
                    ...(fileResult?.extended?.signatureInfo ? [{ id: 'details-signature', label: 'Signature Info' }] : []),
                    ...(!hasSpecializedModule && fileResult?.extended?.exiftool && Object.keys(fileResult.extended.exiftool).length > 0 ? [{ id: 'details-exif', label: 'ExifTool Metadata' }] : []),
                    ...(fileResult?.extended?.packers ? [{ id: 'details-packers', label: 'Packers' }] : []),
                  ].map((sec) => (
                    <button
                      key={sec.id}
                      onClick={() => {
                        setActiveSection(sec.label);
                        document.getElementById(sec.id)?.scrollIntoView({ behavior: 'smooth' });
                      }}
                      style={{
                        background: activeSection === sec.label ? 'rgba(0, 242, 255, 0.08)' : 'transparent',
                        border: 'none',
                        borderRadius: '6px',
                        padding: '8px 12px',
                        color: activeSection === sec.label ? '#00f2ff' : '#94a3b8',
                        textAlign: 'left',
                        fontSize: '13px',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease'
                      }}
                    >
                      {sec.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Main Details Sections */}
            <div style={{ gridColumn: 'span 9', display: 'flex', flexDirection: 'column', gap: '28px' }}>

              {/* 0A. Deep Image Forensics & Steganography Engine */}
              {isImage && imageForensics && (
                <div id="details-image-forensics">
                  <ImageForensicsCard report={imageForensics} />
                </div>
              )}

              {/* 0B. Audio Forensics & ID3 Stream Telemetry */}
              {audioForensics && (
                <div id="details-audio-forensics">
                  <AudioForensicsCard report={audioForensics} />
                </div>
              )}

              {/* 0C. Video Stream & Container Forensics Engine */}
              {videoForensics && (
                <div id="details-video-forensics">
                  <VideoForensicsCard report={videoForensics} />
                </div>
              )}

              {/* 0D. Document Security & Macro Forensics Engine */}
              {docForensics && (
                <div id="details-doc-forensics">
                  <DocumentForensicsCard report={docForensics} />
                </div>
              )}

              {/* 0E. Archive & Container Forensics Engine */}
              {archiveForensics && (
                <div id="details-archive-forensics">
                  <ArchiveForensicsCard report={archiveForensics} />
                </div>
              )}

              {/* 1. Basic Properties */}
              <div id="details-basic" style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                    Basic properties
                  </h3>
                  <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#64748b' }}>info</span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  {/* MD5 */}
                  {fileResult?.md5 && (
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ width: '140px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>MD5</div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, justifyContent: 'flex-end' }}>
                        <span className="font-data-mono" style={{ color: '#e2e8f0', fontSize: '13px' }}>{fileResult.md5}</span>
                        <button onClick={() => handleCopy(fileResult.md5, 'md5')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'md5' ? '#00ffa3' : '#64748b' }}>
                          <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>{copiedKey === 'md5' ? 'check' : 'content_copy'}</span>
                        </button>
                      </div>
                    </div>
                  )}

                  {/* SHA-1 */}
                  {fileResult?.sha1 && (
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ width: '140px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>SHA-1</div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, justifyContent: 'flex-end' }}>
                        <span className="font-data-mono" style={{ color: '#e2e8f0', fontSize: '13px' }}>{fileResult.sha1}</span>
                        <button onClick={() => handleCopy(fileResult.sha1, 'sha1')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'sha1' ? '#00ffa3' : '#64748b' }}>
                          <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>{copiedKey === 'sha1' ? 'check' : 'content_copy'}</span>
                        </button>
                      </div>
                    </div>
                  )}

                  {/* SHA-256 */}
                  {(fileResult?.sha256 || displayHash) && (
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ width: '140px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>SHA-256</div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, justifyContent: 'flex-end' }}>
                        <span className="font-data-mono" style={{ color: '#e2e8f0', fontSize: '13px', wordBreak: 'break-all' }}>{fileResult?.sha256 || displayHash}</span>
                        <button onClick={() => handleCopy(fileResult?.sha256 || displayHash, 'sha256')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'sha256' ? '#00ffa3' : '#64748b' }}>
                          <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>{copiedKey === 'sha256' ? 'check' : 'content_copy'}</span>
                        </button>
                      </div>
                    </div>
                  )}

                  {/* SSDEEP */}
                  {fileResult?.extended?.ssdeep && (
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ width: '140px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>SSDEEP</div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, justifyContent: 'flex-end' }}>
                        <span className="font-data-mono" style={{ color: '#e2e8f0', fontSize: '12px', wordBreak: 'break-all' }}>{fileResult.extended.ssdeep}</span>
                        <button onClick={() => handleCopy(fileResult.extended?.ssdeep || '', 'ssdeep')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'ssdeep' ? '#00ffa3' : '#64748b' }}>
                          <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>{copiedKey === 'ssdeep' ? 'check' : 'content_copy'}</span>
                        </button>
                      </div>
                    </div>
                  )}

                  {/* TLSH */}
                  {fileResult?.extended?.tlsh && (
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ width: '140px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>TLSH</div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, justifyContent: 'flex-end' }}>
                        <span className="font-data-mono" style={{ color: '#e2e8f0', fontSize: '12px', wordBreak: 'break-all' }}>{fileResult.extended.tlsh}</span>
                        <button onClick={() => handleCopy(fileResult.extended?.tlsh || '', 'tlsh')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'tlsh' ? '#00ffa3' : '#64748b' }}>
                          <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>{copiedKey === 'tlsh' ? 'check' : 'content_copy'}</span>
                        </button>
                      </div>
                    </div>
                  )}

                  {/* File Type */}
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                    <div style={{ width: '140px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>File type</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                      <span style={{ color: '#f1f5f9', fontSize: '13px', fontWeight: 600 }}>{fileResult?.type || fileExt}</span>
                      {(fileResult?.tags || ['binary']).map((t, idx) => (
                        <span key={idx} style={{ background: 'rgba(0, 242, 255, 0.08)', border: '1px solid rgba(0, 242, 255, 0.2)', color: '#38bdf8', padding: '1px 6px', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Magic */}
                  {fileResult?.extended?.magic && (
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ width: '140px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Magic</div>
                      <div className="font-data-mono" style={{ color: '#cbd5e1', fontSize: '12px', textAlign: 'right', flex: 1 }}>{fileResult.extended.magic}</div>
                    </div>
                  )}

                  {/* TrID */}
                  {fileResult?.extended?.trid && fileResult.extended.trid.length > 0 && (
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ width: '140px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>TrID</div>
                      <div className="font-data-mono" style={{ color: '#cbd5e1', fontSize: '12px', textAlign: 'right', flex: 1 }}>
                        {fileResult.extended.trid.map((t) => `${t.file_type} (${t.probability.toFixed(1)}%)`).join(' | ')}
                      </div>
                    </div>
                  )}

                  {/* Magika */}
                  {fileResult?.extended?.magika && (
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ width: '140px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Magika</div>
                      <div className="font-data-mono" style={{ color: '#cbd5e1', fontSize: '12px', textAlign: 'right' }}>{fileResult.extended.magika}</div>
                    </div>
                  )}

                  {/* File Size */}
                  {fileResult?.size && (
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                      <div style={{ width: '140px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>File size</div>
                      <div className="font-data-mono" style={{ color: '#cbd5e1', fontSize: '13px', textAlign: 'right' }}>
                        {formatBytes(fileResult.size)}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* 2. History */}
              <div id="details-history" style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                    History
                  </h3>
                  <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#64748b' }}>info</span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {fileResult?.firstSeen ? (
                    <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>First Submission</div>
                      <div style={{ color: '#cbd5e1', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
                        {new Date(fileResult.firstSeen * 1000).toUTCString()} ({formatRelativeTime(fileResult.firstSeen)})
                      </div>
                    </div>
                  ) : null}

                  {fileResult?.lastSeen ? (
                    <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Last Analysis</div>
                      <div style={{ color: '#cbd5e1', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
                        {new Date(fileResult.lastSeen * 1000).toUTCString()} ({formatRelativeTime(fileResult.lastSeen)})
                      </div>
                    </div>
                  ) : null}

                  {fileResult?.timesSubmitted ? (
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Times Submitted</div>
                      <div style={{ color: '#cbd5e1', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>{fileResult.timesSubmitted}</div>
                    </div>
                  ) : null}
                </div>
              </div>

              {/* 3. Names */}
              {fileResult?.names && fileResult.names.length > 0 && (
                <div id="details-names" style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                      Names
                    </h3>
                    <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#64748b' }}>info</span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {fileResult.names.map((nm, idx) => (
                      <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                        <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#38bdf8' }}>description</span>
                        <span className="font-data-mono" style={{ fontSize: '13px', color: '#f1f5f9' }}>{nm}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 4. Automatic YARA Rules & Signatures Evaluation */}
              <div id="details-yara" style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                  <span className="material-symbols-outlined" style={{ color: '#22d3ee', fontSize: '20px' }}>rule</span>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                    Automatic YARA Rules & Signature Inspection
                  </h3>
                </div>

                <AutomaticYaraCard 
                  fileResult={fileResult}
                  crowdsourcedYara={fileResult?.extended?.crowdsourcedYara}
                />
              </div>

              {/* 5. PE Headers & Sections */}
              {fileResult?.extended?.peInfo && (
                <div id="details-pe" style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                      PE Headers & Sections
                    </h3>
                    <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#64748b' }}>info</span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    {fileResult.extended.peInfo.imphash && (
                      <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                        <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>ImpHash</div>
                        <div className="font-data-mono" style={{ color: '#38bdf8', fontSize: '13px' }}>{fileResult.extended.peInfo.imphash}</div>
                      </div>
                    )}

                    {fileResult.extended.peInfo.machine_type && (
                      <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                        <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Machine Type</div>
                        <div style={{ color: '#f1f5f9', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>{fileResult.extended.peInfo.machine_type}</div>
                      </div>
                    )}

                    {/* PE Sections Table with Entropy Visualizer */}
                    {fileResult.extended.peInfo.sections && fileResult.extended.peInfo.sections.length > 0 && (
                      <div style={{ marginTop: '12px' }}>
                        <div style={{ fontSize: '13px', color: '#94a3b8', fontWeight: 600, marginBottom: '10px' }}>Sections ({fileResult.extended.peInfo.sections.length})</div>
                        <div style={{ overflowX: 'auto' }}>
                          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                            <thead>
                              <tr style={{ borderBottom: '1px solid #334155', color: '#64748b' }}>
                                <th style={{ padding: '8px' }}>Name</th>
                                <th style={{ padding: '8px' }}>Entropy (0-8)</th>
                                <th style={{ padding: '8px' }}>Virtual Size</th>
                                <th style={{ padding: '8px' }}>Raw Size</th>
                              </tr>
                            </thead>
                            <tbody>
                              {fileResult.extended.peInfo.sections.map((sec, i) => {
                                const entropyPercent = Math.min(100, Math.round((sec.entropy / 8) * 100));
                                const entropyColor = sec.entropy > 7 ? '#ff2a5f' : sec.entropy > 6 ? '#fb923c' : '#00ffa3';
                                return (
                                  <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                                    <td style={{ padding: '8px', color: '#38bdf8', fontWeight: 600 }}>{sec.name}</td>
                                    <td style={{ padding: '8px' }}>
                                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                        <div style={{ width: '80px', height: '6px', background: 'rgba(255,255,255,0.1)', borderRadius: '999px', overflow: 'hidden' }}>
                                          <div style={{ width: `${entropyPercent}%`, height: '100%', background: entropyColor }}></div>
                                        </div>
                                        <span style={{ color: entropyColor }}>{sec.entropy.toFixed(2)}</span>
                                      </div>
                                    </td>
                                    <td style={{ padding: '8px', color: '#cbd5e1' }}>{sec.virtual_size}</td>
                                    <td style={{ padding: '8px', color: '#cbd5e1' }}>{sec.raw_size}</td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 6. MITRE ATT&CK Matrix */}
              {fileResult?.extended?.mitreAttack && fileResult.extended.mitreAttack.length > 0 && (
                <div id="details-mitre" style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                      MITRE ATT&CK Matrix Techniques
                    </h3>
                    <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#64748b' }}>info</span>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
                    {fileResult.extended.mitreAttack.map((m, idx) => (
                      <div key={idx} style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 42, 95, 0.2)', borderRadius: '8px', padding: '12px 16px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <span style={{ color: '#ff2a5f', fontWeight: 700, fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{m.id}</span>
                          <span style={{ background: 'rgba(255,255,255,0.05)', color: '#94a3b8', padding: '2px 6px', borderRadius: '4px', fontSize: '10px', fontFamily: 'var(--font-mono)' }}>{m.tactic}</span>
                        </div>
                        <div style={{ fontSize: '13px', color: '#f1f5f9', fontWeight: 500 }}>{m.signature_description}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 7. Signature Info */}
              {fileResult?.extended?.signatureInfo && Object.keys(fileResult.extended.signatureInfo).length > 0 && (
                <div id="details-signature" style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                      Signature Info
                    </h3>
                    <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#64748b' }}>verified</span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {Object.entries(fileResult.extended.signatureInfo).map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '8px' }}>
                        <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>{k}</div>
                        <div className="font-data-mono" style={{ color: '#e2e8f0', fontSize: '13px' }}>{String(v)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 8. ExifTool Metadata */}
              {!hasSpecializedModule && fileResult?.extended?.exiftool && Object.keys(fileResult.extended.exiftool).length > 0 && (
                <div id="details-exif" style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                      ExifTool Metadata
                    </h3>
                    <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#64748b' }}>info</span>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px' }}>
                    {Object.entries(fileResult.extended.exiftool).map(([k, v]) => (
                      <div key={k} style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.04)' }}>
                        <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', marginBottom: '2px' }}>{k}</div>
                        <div className="font-data-mono" style={{ fontSize: '12px', color: '#cbd5e1', wordBreak: 'break-all' }}>{String(v)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 9. Packers */}
              {fileResult?.extended?.packers && Object.keys(fileResult.extended.packers).length > 0 && (
                <div id="details-packers" style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                      Packers
                    </h3>
                    <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#64748b' }}>info</span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {Object.entries(fileResult.extended.packers).map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '8px' }}>
                        <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>{k}</div>
                        <div className="font-data-mono" style={{ color: '#e2e8f0', fontSize: '13px' }}>{String(v)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </div>
          </div>
        )}

        {/* ── TAB 3: BEHAVIOR ─────────────────────────────────────────────────── */}
        {activeTab === 'BEHAVIOR' && (
          <div style={{
            background: '#111927',
            border: '1px solid #1e293b',
            borderRadius: '10px',
            padding: '28px 32px'
          }}>
            <BehaviorCard
              mitreAttack={fileResult?.extended?.mitreAttack}
              behaviorData={behaviorData}
            />
          </div>
        )}

        {/* ── TAB 4: RELATIONS ─────────────────────────────────────────────────── */}
        {activeTab === 'RELATIONS' && (
          <div style={{
            background: '#111927',
            border: '1px solid #1e293b',
            borderRadius: '10px',
            padding: '28px 32px'
          }}>
            <RelationsCard relations={fileResult?.relations || analysisResult?.relations || domainResult?.relations || ipResult?.relations} />
          </div>
        )}

        {/* ── TAB 5: COMMUNITY ─────────────────────────────────────────────────── */}
        {activeTab === 'COMMUNITY' && (
          <div style={{
            background: '#111927',
            border: '1px solid #1e293b',
            borderRadius: '10px',
            padding: '28px 32px'
          }}>
            <CommunityCommentsCard comments={fileResult?.comments || analysisResult?.comments || domainResult?.comments || ipResult?.comments} />
          </div>
        )}

        {/* ── TAB 6: SUMMARY (AI ATLAS SUMMARY + THREAT FEEDS + SSL) ───────────── */}
        {activeTab === 'SUMMARY' && (
          <div style={{
            background: '#111927',
            border: '1px solid #1e293b',
            borderRadius: '10px',
            padding: '28px 32px',
            display: 'flex',
            flexDirection: 'column',
            gap: '24px'
          }}>
            <AiSummary threatData={fileResult || analysisResult || domainResult || ipResult} type={isFile ? 'file' : 'url'} />
            
            {/* Multi-Source Threat Feeds */}
            <ThreatFeedCard target={displayHash} threatScore={score} tags={fileResult?.tags} />

            {/* X.509 Certificate Inspector (For URLs and Domains) */}
            {!isFile && (
              <CertInspectorCard domain={analysisResult?.url || domainResult?.domain || rawTarget} />
            )}

            {!isFile && phishResult && (
              <PhishGuardCard result={phishResult} url={analysisResult?.url || domainResult?.domain || rawTarget} />
            )}
            {!isFile && (webfoxResult || isWebfoxLoading) && (
              <WebFoxCard recon={webfoxResult || { domain: analysisResult?.url || domainResult?.domain || rawTarget, dnsRecords: [], subdomains: [], securityHeaders: [], headerSecurityScore: 0 }} loading={isWebfoxLoading} />
            )}
          </div>
        )}

      </div>
    </div>
  );
};
