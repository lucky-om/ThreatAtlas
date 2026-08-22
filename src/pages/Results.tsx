import React, { useEffect, useState, useRef } from 'react';
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
import { getCachedItem, setCachedItem, clearCache } from '../services/cache';
import { formatRelativeTime, formatBytes } from '../utils/sanitize';

type Tab = 'DETECTION' | 'DETAILS' | 'BEHAVIOR' | 'RELATIONS' | 'COMMUNITY' | 'SUMMARY';

export const Results: React.FC = () => {
  const { id: pathId, hash: pathHash, query: pathQuery, tab } = useParams();
  const [searchParams] = useSearchParams();
  
  const rawTarget = pathId || pathHash || pathQuery || searchParams.get('id') || searchParams.get('hash') || searchParams.get('q') || searchParams.get('query') || '';

  const [loading, setLoading] = useState(true);
  const [scanStep, setScanStep] = useState<number>(1);
  const [error, setError] = useState<string | null>(null);

  const [analysisResult, setAnalysisResult] = useState<NormalizedAnalysis | null>(null);
  const [fileResult, setFileResult] = useState<NormalizedFile | null>(null);
  const [domainResult, setDomainResult] = useState<NormalizedDomain | null>(null);
  const [ipResult, setIpResult] = useState<NormalizedIp | null>(null);
  const [behaviorData, setBehaviorData] = useState<any | null>(null);

  // PhishGuard & WebFox Live Integration
  const [phishResult, setPhishResult] = useState<PhishGuardResult | null>(null);
  const [webfoxResult, setWebfoxResult] = useState<WebFoxReconResult | null>(null);
  const [isWebfoxLoading, setIsWebfoxLoading] = useState<boolean>(false);

  const [activeTab, setActiveTab] = useState<Tab>('DETECTION');
  const [activeSection, setActiveSection] = useState<string>('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [communityVote, setCommunityVote] = useState<'up' | 'down' | null>(null);
  const [isExportingPdf, setIsExportingPdf] = useState(false);
  const [showMoreMenu, setShowMoreMenu] = useState(false);

  const moreMenuRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (moreMenuRef.current && !moreMenuRef.current.contains(e.target as Node)) {
        setShowMoreMenu(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    if (tab) {
      const upperTab = tab.toUpperCase() as Tab;
      if (['DETECTION', 'DETAILS', 'BEHAVIOR', 'RELATIONS', 'COMMUNITY', 'SUMMARY'].includes(upperTab)) {
        setActiveTab(upperTab);
      }
    }
  }, [tab]);

  const executeUnifiedScan = async (forceFresh = false) => {
    setLoading(true);
    setError(null);
    setScanStep(1);

    const target = rawTarget.trim();
    if (!target) {
      navigate('/');
      return;
    }

    const isUrlToken = target.startsWith('u-') || target.startsWith('http://') || target.startsWith('https://');
    const isHash = !isUrlToken && isValidHash(target);
    const isIp = isValidIp(target);
    const detected = detectInputType(target);
    
    const isAnalysisToken = target.startsWith('u-') || 
      target.includes(':') || 
      (target.length >= 44 && !isHash && /[+/=]/.test(target));

    if (forceFresh) {
      clearCache();
    }

    // ── Check Fast Cache first (unless forced fresh) ───────────────────────
    if (!forceFresh) {
      const cached = getCachedItem<any>(target);
      if (cached) {
        if (cached.sha256 || cached.names) setFileResult(cached);
        else if (cached.domain) setDomainResult(cached);
        else if (cached.ip) setIpResult(cached);
        else setAnalysisResult(cached);
        setLoading(false);
        return;
      }
    }

    // Smooth step updates for pipeline visibility (caps at 4 until complete)
    const stepTimer = setInterval(() => {
      setScanStep(s => (s < 4 ? s + 1 : s));
    }, 600);

    try {
      // ── 1. Cryptographic Hash Search (Direct File Lookup) ─────────────────
      if (isHash) {
        const [fileData, behaviorRes] = await Promise.allSettled([
          lookupHash(target),
          fetch(`/api/vt/files/${target}/behaviours?limit=5`).then(r => r.ok ? r.json() : null)
        ]);

        if (fileData.status === 'fulfilled') {
          const data = fileData.value;
          setFileResult(data);
          setCachedItem(target, data);
          setScanStep(5);

          if (behaviorRes.status === 'fulfilled' && behaviorRes.value) {
            setBehaviorData(behaviorRes.value);
          }

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
        } else {
          throw new Error('Failed to retrieve file analysis. Please verify the hash.');
        }
        return;
      }

      // ── 2. VirusTotal Analysis Token (Fresh File or URL Scan) ──────────────
      if (isAnalysisToken) {
        // Stream live engine results as they arrive
        const analysisData = await pollAnalysis(target, (progress) => {
          setAnalysisResult(progress);
          if (progress.status === 'completed') {
            setScanStep(5);
          } else {
            setScanStep(s => Math.max(s, 3));
          }
        });
        setAnalysisResult(analysisData);
        setCachedItem(target, analysisData);
        setScanStep(5);

        if (analysisData.hash || (!analysisData.url && analysisData.fileName)) {
          const fallbackHash = analysisData.hash || target;
          const fallbackFile: NormalizedFile = {
            id: fallbackHash,
            sha256: fallbackHash,
            sha1: '',
            md5: '',
            name: analysisData.fileName || 'Sample File',
            names: analysisData.fileName ? [analysisData.fileName] : ['Sample File'],
            size: analysisData.fileSize || 0,
            type: analysisData.fileName ? analysisData.fileName.split('.').pop()?.toUpperCase() || 'File' : 'File',
            mimeType: '',
            firstSeen: analysisData.date || Math.floor(Date.now() / 1000),
            lastSeen: analysisData.date || Math.floor(Date.now() / 1000),
            timesSubmitted: 1,
            verdict: analysisData.verdict,
            stats: analysisData.stats,
            tags: [],
            engines: analysisData.engines,
            extended: analysisData.extended
          };
          setFileResult(fallbackFile);

          if (analysisData.hash) {
            try {
              const [fullFileData, behaviorRes] = await Promise.allSettled([
                lookupHash(analysisData.hash),
                fetch(`/api/vt/files/${analysisData.hash}/behaviours?limit=5`).then(r => r.ok ? r.json() : null)
              ]);

              if (fullFileData.status === 'fulfilled') {
                setFileResult(fullFileData.value);
                setCachedItem(analysisData.hash, fullFileData.value);
                if (behaviorRes.status === 'fulfilled' && behaviorRes.value) setBehaviorData(behaviorRes.value);

                addScanHistoryItem({
                  id: fullFileData.value.id || analysisData.hash,
                  target: analysisData.hash,
                  type: 'file',
                  name: fullFileData.value.name || fullFileData.value.names?.[0] || 'Sample File',
                  hash: fullFileData.value.sha256,
                  verdict: fullFileData.value.verdict || (fullFileData.value.stats?.malicious > 0 ? 'malicious' : 'clean'),
                  threatScore: fullFileData.value.stats?.malicious || 0,
                  maliciousCount: fullFileData.value.stats?.malicious || 0,
                  totalEngines: fullFileData.value.engines?.length || 70,
                  fileSize: fullFileData.value.size
                });
              }
            } catch (_) {}
          }
        } else {
          const effectiveUrl = analysisData.url || (analysisData.extended?.httpResponse?.finalUrl) || target;
          addScanHistoryItem({
            id: analysisData.id || target,
            target: effectiveUrl,
            type: 'url',
            name: effectiveUrl,
            verdict: analysisData.verdict || (analysisData.stats?.malicious > 0 ? 'malicious' : 'clean'),
            threatScore: analysisData.stats?.malicious || 0,
            maliciousCount: analysisData.stats?.malicious || 0,
            totalEngines: analysisData.engines?.length || 70
          });

          if (effectiveUrl && effectiveUrl.startsWith('http')) {
            setPhishResult(analyzeWithPhishGuard(effectiveUrl));
            setIsWebfoxLoading(true);
            runWebFoxRecon(effectiveUrl)
              .then(wf => setWebfoxResult(wf))
              .catch(() => {})
              .finally(() => setIsWebfoxLoading(false));
          }
        }
        return;
      }

      // ── 3. IP Address Search ──────────────────────────────────────────────
      if (isIp) {
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
        return;
      }

      // ── 4. Domain Name Search ─────────────────────────────────────────────
      const isPlainDomain = detected === 'domain' || (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(target) && !target.includes('/'));
      if (isPlainDomain) {
        const targetUrl = `https://${target}`;
        setPhishResult(analyzeWithPhishGuard(targetUrl));
        setIsWebfoxLoading(true);
        runWebFoxRecon(targetUrl)
          .then(wf => setWebfoxResult(wf))
          .catch(() => {})
          .finally(() => setIsWebfoxLoading(false));

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
        return;
      }

      // ── 5. URL Search / Direct Submission ─────────────────────────────────
      const targetUrl = target.startsWith('http') ? target : `https://${target}`;
      setPhishResult(analyzeWithPhishGuard(targetUrl));
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
        const scanRes = await scanUrl(targetUrl);
        if (scanRes?.data?.id) {
          const data = await pollAnalysis(scanRes.data.id, (progress) => {
            setAnalysisResult(progress);
            if (progress.status === 'completed') {
              setScanStep(5);
            } else {
              setScanStep(s => Math.max(s, 3));
            }
          });
          setAnalysisResult(data);
          setCachedItem(target, data);
          setScanStep(5);
        }
      }
    } catch (err: any) {
      setError(err.message || 'Threat scan failed. Please verify the target.');
    } finally {
      clearInterval(stepTimer);
      setScanStep(5);
      setLoading(false);
    }
  };

  useEffect(() => {
    executeUnifiedScan(false);
  }, [rawTarget]);

  // ── UNIFIED SCAN PROGRESS ORCHESTRATOR ────────────────────────────────────
  // Show orchestrator only while initial data handshake is establishing
  const hasAnyData = Boolean(
    fileResult || 
    domainResult || 
    ipResult || 
    (analysisResult && (analysisResult.engines?.length > 0 || analysisResult.status === 'completed'))
  );

  if (loading && !hasAnyData) {
    const steps = [
      { id: 1, label: 'Multi-Vendor Antivirus Matrix (70+ Engines)', desc: 'Querying global threat intelligence signatures' },
      { id: 2, label: 'Target Category Protocol Inspection', desc: 'Evaluating protocol structures, headers, and certificates' },
      { id: 3, label: 'Specialized Telemetry & Forensics Engine', desc: 'Running dedicated category heuristics and anomaly detection' },
      { id: 4, label: 'Network Recon & Threat Feed Aggregator', desc: 'Cross-referencing AbuseIPDB, AlienVault OTX, and DNS records' },
      { id: 5, label: 'Atlas Neural AI Threat Synthesizer', desc: 'Synthesizing final executive verdict and remediation steps' }
    ];

    return (
      <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '100px', display: 'flex', flexDirection: 'column', alignItems: 'center', backgroundColor: '#0b111e', color: '#c3c8d4' }}>
        <div className="digital-grid" style={{ opacity: 0.3 }}></div>
        <div className="glow-cyan"></div>
        
        <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '680px', width: '100%', marginTop: '40px', padding: '0 20px' }}>
          <div style={{
            background: '#111927',
            border: '1px solid #1e293b',
            borderRadius: '12px',
            padding: '36px 32px',
            boxShadow: '0 20px 50px rgba(0,0,0,0.8)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '16px' }}>
              <span className="material-symbols-outlined spin text-primary" style={{ fontSize: '32px' }}>sync</span>
              <div>
                <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 700, color: '#f1f5f9' }}>
                  Unified Threat Intelligence Pipeline
                </h2>
                <div style={{ fontSize: '12px', color: '#64748b', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                  Target: {rawTarget.slice(0, 36)}{rawTarget.length > 36 ? '...' : ''}
                </div>
              </div>
            </div>

            {/* Steps Progress List */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {steps.map((s) => {
                const isDone = scanStep > s.id;
                const isCurrent = scanStep === s.id;
                return (
                  <div key={s.id} style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 14px',
                    borderRadius: '8px',
                    background: isCurrent ? 'rgba(0, 242, 255, 0.05)' : 'rgba(255,255,255,0.02)',
                    border: isCurrent ? '1px solid rgba(0, 242, 255, 0.3)' : '1px solid rgba(255,255,255,0.04)',
                    transition: 'all 0.2s ease'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      {isDone ? (
                        <span className="material-symbols-outlined" style={{ color: '#00ffa3', fontSize: '20px' }}>check_circle</span>
                      ) : isCurrent ? (
                        <span className="material-symbols-outlined spin" style={{ color: '#00f2ff', fontSize: '20px' }}>progress_activity</span>
                      ) : (
                        <span className="material-symbols-outlined" style={{ color: '#475569', fontSize: '20px' }}>radio_button_unchecked</span>
                      )}
                      <div>
                        <div style={{ fontSize: '13px', fontWeight: 600, color: isCurrent ? '#00f2ff' : isDone ? '#f1f5f9' : '#64748b' }}>
                          {s.label}
                        </div>
                        <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                          {s.desc}
                        </div>
                      </div>
                    </div>

                    <span style={{
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)',
                      color: isDone ? '#00ffa3' : isCurrent ? '#00f2ff' : '#475569',
                      fontWeight: 700
                    }}>
                      {isDone ? 'COMPLETED' : isCurrent ? 'RUNNING' : 'QUEUED'}
                    </span>
                  </div>
                );
              })}
            </div>

            {/* Bottom Progress Bar */}
            <div style={{ marginTop: '24px', paddingTop: '16px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: '#94a3b8', fontFamily: 'var(--font-mono)', marginBottom: '6px' }}>
                <span>Streaming live telemetry from security engines...</span>
                <span>{Math.min(100, scanStep * 20)}%</span>
              </div>
              <div style={{ width: '100%', height: '4px', background: 'rgba(255,255,255,0.06)', borderRadius: '999px', overflow: 'hidden' }}>
                <div style={{ width: `${Math.min(100, scanStep * 20)}%`, height: '100%', background: 'linear-gradient(90deg, #00f2ff, #b942ff)', transition: 'width 0.3s ease' }}></div>
              </div>
            </div>

          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '100px', display: 'flex', flexDirection: 'column', alignItems: 'center', backgroundColor: '#0b111e' }}>
        <div className="digital-grid" style={{ opacity: 0.3 }}></div>
        <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '800px', marginTop: '80px' }}>
          <div className="glass-card" style={{ padding: '48px', textAlign: 'center', borderColor: 'var(--secondary)', background: '#111927' }}>
            <span className="material-symbols-outlined text-secondary" style={{ fontSize: '64px', marginBottom: '16px', filter: 'drop-shadow(0 0 10px rgba(255,0,60,0.5))' }}>warning</span>
            <h2 className="font-display-lg text-secondary" style={{ marginBottom: '16px' }}>Scan Notice</h2>
            <p className="font-data-mono" style={{ color: '#cbd5e1' }}>{error}</p>
            <button className="btn-primary" onClick={() => executeUnifiedScan(true)} style={{ marginTop: '24px' }}>
              Retry Scan
            </button>
          </div>
        </div>
      </div>
    );
  }

  const isPending = analysisResult?.status === 'queued' || analysisResult?.status === 'in-progress' || isWebfoxLoading;

  // ── PRECISE TARGET CATEGORIZATION ENGINE ──────────────────────────────────
  const targetClean = rawTarget.trim();
  const isUrlToken = targetClean.startsWith('u-') || targetClean.startsWith('http://') || targetClean.startsWith('https://');
  const isPureHash = !isUrlToken && isValidHash(targetClean);
  const isPureIp = isValidIp(targetClean);
  const detected = detectInputType(targetClean);

  const isFile = Boolean(fileResult || (isPureHash && !isUrlToken) || (analysisResult?.hash && isValidHash(analysisResult.hash)));
  const isUrlScan = Boolean(!isFile && (isUrlToken || detected === 'url' || (analysisResult && !analysisResult.hash)));
  const isDomainScan = Boolean(!isFile && !isUrlScan && (domainResult || detected === 'domain'));
  const isIpScan = Boolean(!isFile && !isUrlScan && !isDomainScan && (ipResult || isPureIp));

  const targetCategory: 'file' | 'url' | 'domain' | 'ip' = isFile ? 'file' : isUrlScan ? 'url' : isDomainScan ? 'domain' : 'ip';

  const stats = fileResult?.stats || analysisResult?.stats || domainResult?.stats || ipResult?.stats;
  const engines = fileResult?.engines || analysisResult?.engines || domainResult?.engines || ipResult?.engines || [];

  const score = stats?.malicious || 0;
  const total = (stats?.malicious || 0) + (stats?.undetected || 0) + (stats?.harmless || 0) + (stats?.suspicious || 0) + (stats?.timeout || 0) || engines.length || 60;

  // Header display details
  const displayTitle = isFile 
    ? (fileResult?.names?.[0] || fileResult?.name || fileResult?.sha256 || targetClean)
    : isUrlScan
      ? (analysisResult?.url || analysisResult?.extended?.httpResponse?.finalUrl || targetClean)
      : isDomainScan
        ? (domainResult?.domain || targetClean)
        : (ipResult?.ip || targetClean);

  const displaySubtitle = isFile
    ? (fileResult?.sha256 || targetClean)
    : isUrlScan
      ? (analysisResult?.url || targetClean)
      : isDomainScan
        ? (domainResult?.domain || targetClean)
        : `${ipResult?.country || '—'} · ${ipResult?.asOwner || '—'}`;

  const categoryBadge = isFile
    ? (fileResult?.type ? fileResult.type.slice(0, 8).toUpperCase() : 'FILE')
    : isUrlScan
      ? 'URL'
      : isDomainScan
        ? 'DOMAIN'
        : 'IP ADDRESS';

  const categoryIcon = isFile
    ? 'description'
    : isUrlScan
      ? 'link'
      : isDomainScan
        ? 'language'
        : 'router';

  const lastAnalysisTs = fileResult?.lastSeen || analysisResult?.date || domainResult?.lastSeen || ipResult?.lastSeen;

  // ── Multi-Format Specialized Forensics Engines (FILES ONLY) ───────────────
  const fileCategory = isFile ? getFileCategory(fileResult, targetClean) : 'generic';
  
  const isImage = isFile && (fileCategory === 'image' || isImageFile(fileResult, targetClean));
  const imageForensics = isImage ? extractImageForensics(fileResult) : null;
  const audioForensics = isFile && fileCategory === 'audio' ? extractAudioForensics(fileResult) : null;
  const videoForensics = isFile && fileCategory === 'video' ? extractVideoForensics(fileResult) : null;
  const docForensics = isFile && fileCategory === 'document' ? extractDocumentForensics(fileResult) : null;
  const archiveForensics = isFile && fileCategory === 'archive' ? extractArchiveForensics(fileResult) : null;

  const hasSpecializedFileModule = Boolean(isImage || audioForensics || videoForensics || docForensics || archiveForensics);

  const handleExportPdf = () => {
    const data = fileResult || analysisResult || domainResult || ipResult;
    if (!data) return;
    setIsExportingPdf(true);
    setShowMoreMenu(false);
    try {
      const summaryText = score > 0 
        ? `🚨 VERDICT: CRITICAL / SUSPICIOUS (${score}/${total} vendors flagged malicious). Target exhibits indicators of compromise (IOC), suspicious signature patterns, or hostile communication telemetry.\n• Immediate Action: Quarantine endpoint, block SHA-256 hash/IP at firewall boundary, and inspect SIEM/EDR logs.`
        : `🛡️ VERDICT: VERIFIED CLEAN (0/${total} detections). Zero security vendors flagged this ${targetCategory}.\n• Structural headers and telemetry check out cleanly. Safe to use under baseline corporate policy.`;

      generatePdfThreatReport({
        threatData: data,
        targetType: targetCategory,
        aiSummaryText: summaryText,
        imageForensics,
        audioForensics,
        videoForensics,
        docForensics,
        archiveForensics,
        yaraMatches: isFile ? fileResult?.extended?.crowdsourcedYara : undefined
      });
    } finally {
      setTimeout(() => setIsExportingPdf(false), 1000);
    }
  };

  const handleSimilarSearch = () => {
    setShowMoreMenu(false);
    const imphash = fileResult?.extended?.peInfo?.imphash;
    const tag = fileResult?.tags?.[0];
    if (imphash) {
      navigate(`/search?query=imphash:${imphash}`);
    } else if (tag) {
      navigate(`/search?query=tag:${tag}`);
    } else {
      navigate(`/search?query=${encodeURIComponent(displayTitle)}`);
    }
  };

  const handleCopyJson = () => {
    const data = fileResult || analysisResult || domainResult || ipResult;
    if (data) {
      handleCopy(JSON.stringify(data, null, 2), 'json_report');
    }
    setShowMoreMenu(false);
  };

  const handleTabChange = (t: Tab) => {
    setActiveTab(t);
  };

  return (
    <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '80px', paddingBottom: '64px', backgroundColor: '#0b111e', color: '#c3c8d4' }}>
      <div className="digital-grid" style={{ opacity: 0.3 }}></div>

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1280px' }}>

        {isPending && (
          <div style={{
            padding: '14px 20px',
            marginBottom: '24px',
            background: 'linear-gradient(90deg, rgba(0, 242, 255, 0.08), rgba(185, 66, 255, 0.08))',
            border: '1px solid rgba(0, 242, 255, 0.35)',
            borderRadius: '10px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '12px',
            boxShadow: '0 0 20px rgba(0, 242, 255, 0.1)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
              <span className="material-symbols-outlined text-primary spin" style={{ fontSize: '24px' }}>sync</span>
              <div>
                <div style={{ fontSize: '13px', fontWeight: 700, color: '#00f2ff', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>LIVE SCAN IN PROGRESS</span>
                  <span style={{ fontSize: '11px', background: 'rgba(0, 242, 255, 0.15)', padding: '2px 8px', borderRadius: '4px', color: '#fff', fontFamily: 'var(--font-mono)' }}>
                    {engines.length} / {total || 70} Engines Evaluated
                  </span>
                </div>
                <p className="font-code-sm text-on-surface-variant" style={{ margin: '4px 0 0 0', fontSize: '12px' }}>
                  Security engines and forensic modules are streaming results in real-time. Report is updating live.
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#00ffa3', display: 'inline-block', boxShadow: '0 0 8px #00ffa3' }}></span>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#00ffa3', fontWeight: 700 }}>STREAMING LIVE</span>
            </div>
          </div>
        )}

        {/* ── TOP HEADER CARD ──────────────────────────────────────────────────── */}
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
                      No security vendors flagged this {targetCategory} as malicious
                    </span>
                  </>
                ) : (
                  <>
                    <span className="material-symbols-outlined" style={{ color: '#ff2a5f', fontSize: '22px' }}>cancel</span>
                    <span style={{ color: '#ff2a5f', fontSize: '14px', fontWeight: 600 }}>
                      {score} security vendor{score > 1 ? 's' : ''} flagged this {targetCategory} as malicious
                    </span>
                  </>
                )}
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                
                {/* 1. Reanalyze */}
                <button 
                  className="font-code-sm"
                  onClick={() => executeUnifiedScan(true)}
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
                  title="Flush cache and run fresh multi-engine analysis"
                >
                  <span className="material-symbols-outlined" style={{ fontSize: '15px' }}>sync</span>
                  Reanalyze
                </button>

                {/* 2. Similar (For Files / Hashes) */}
                {isFile && (
                  <button 
                    className="font-code-sm"
                    onClick={handleSimilarSearch}
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
                    title="Find related samples by ImpHash / tags"
                  >
                    <span className="material-symbols-outlined" style={{ fontSize: '15px' }}>compare_arrows</span>
                    Similar
                  </button>
                )}

                {/* 3. Export PDF */}
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

                {/* 4. More Actions Dropdown */}
                <div ref={moreMenuRef} style={{ position: 'relative' }}>
                  <button 
                    className="font-code-sm"
                    onClick={() => setShowMoreMenu(!showMoreMenu)}
                    style={{
                      background: showMoreMenu ? 'rgba(255,255,255,0.1)' : 'transparent',
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
                    <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>
                      {showMoreMenu ? 'expand_less' : 'expand_more'}
                    </span>
                  </button>

                  {showMoreMenu && (
                    <div style={{
                      position: 'absolute',
                      top: 'calc(100% + 6px)',
                      right: 0,
                      width: '210px',
                      background: '#111927',
                      border: '1px solid #1e293b',
                      borderRadius: '8px',
                      padding: '6px',
                      zIndex: 100,
                      boxShadow: '0 10px 30px rgba(0,0,0,0.8)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '2px'
                    }}>
                      <button
                        onClick={handleCopyJson}
                        style={{
                          background: 'none', border: 'none', color: '#cbd5e1', padding: '8px 12px',
                          textAlign: 'left', fontSize: '12px', fontFamily: 'var(--font-mono)', cursor: 'pointer',
                          display: 'flex', alignItems: 'center', gap: '8px', borderRadius: '4px'
                        }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0, 242, 255, 0.08)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                      >
                        <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#38bdf8' }}>data_object</span>
                        Copy JSON Report
                      </button>

                      <button
                        onClick={() => { setShowMoreMenu(false); navigate('/threat-graph'); }}
                        style={{
                          background: 'none', border: 'none', color: '#cbd5e1', padding: '8px 12px',
                          textAlign: 'left', fontSize: '12px', fontFamily: 'var(--font-mono)', cursor: 'pointer',
                          display: 'flex', alignItems: 'center', gap: '8px', borderRadius: '4px'
                        }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0, 242, 255, 0.08)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                      >
                        <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#b942ff' }}>hub</span>
                        Open Threat Graph
                      </button>

                      <button
                        onClick={() => {
                          setShowMoreMenu(false);
                          window.open(`https://www.virustotal.com/gui/${isFile ? 'file' : isDomainScan ? 'domain' : isIpScan ? 'ip-address' : 'url'}/${encodeURIComponent(targetClean)}`, '_blank');
                        }}
                        style={{
                          background: 'none', border: 'none', color: '#cbd5e1', padding: '8px 12px',
                          textAlign: 'left', fontSize: '12px', fontFamily: 'var(--font-mono)', cursor: 'pointer',
                          display: 'flex', alignItems: 'center', gap: '8px', borderRadius: '4px'
                        }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0, 242, 255, 0.08)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                      >
                        <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#00ffa3' }}>open_in_new</span>
                        View on VirusTotal
                      </button>
                    </div>
                  )}
                </div>

              </div>
            </div>

            {/* Target Display Title & Meaningful Subtitle */}
            <div style={{ marginBottom: '18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                <span className="font-data-mono" style={{ fontSize: '15px', color: '#e2e8f0', wordBreak: 'break-all', fontWeight: 600 }}>
                  {displayTitle}
                </span>
                <button
                  onClick={() => handleCopy(displayTitle, 'header_target')}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'header_target' ? '#00ffa3' : '#64748b', display: 'flex', padding: 0 }}
                  title="Copy Target"
                >
                  <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>
                    {copiedKey === 'header_target' ? 'check' : 'content_copy'}
                  </span>
                </button>
              </div>

              {displaySubtitle && displaySubtitle !== displayTitle && (
                <div style={{ fontSize: '13px', color: '#94a3b8', marginBottom: '8px', wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
                  {displaySubtitle}
                </div>
              )}

              {/* Tags Badges */}
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                <span 
                  style={{
                    background: 'rgba(0, 242, 255, 0.08)',
                    border: '1px solid rgba(0, 242, 255, 0.2)',
                    color: '#38bdf8',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700
                  }}
                >
                  {categoryBadge}
                </span>

                {fileResult?.tags?.slice(0, 5).map((t, idx) => (
                  <span 
                    key={idx}
                    style={{
                      background: 'rgba(255, 255, 255, 0.04)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      color: '#cbd5e1',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)'
                    }}
                  >
                    {t}
                  </span>
                ))}
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
                {isFile && fileResult?.size ? (
                  <div>
                    <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Size</div>
                    <div style={{ fontSize: '13px', color: '#e2e8f0', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                      {formatBytes(fileResult.size)}
                    </div>
                  </div>
                ) : isUrlScan && analysisResult?.extended?.httpResponse?.statusCode ? (
                  <div>
                    <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Status Code</div>
                    <div style={{ fontSize: '13px', color: '#00ffa3', fontFamily: 'var(--font-mono)', marginTop: '2px', fontWeight: 600 }}>
                      {analysisResult.extended.httpResponse.statusCode} OK
                    </div>
                  </div>
                ) : isIpScan && ipResult?.country ? (
                  <div>
                    <div style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Country</div>
                    <div style={{ fontSize: '13px', color: '#e2e8f0', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                      {ipResult.country}
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

              {/* Category Icon Badge */}
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: '50%',
                background: '#1e293b',
                border: '1px solid #334155',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#38bdf8'
              }}>
                <span className="material-symbols-outlined" style={{ fontSize: '20px' }}>
                  {categoryIcon}
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
                Multi-engine verdict verification
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

        {/* ── TAB 2: DETAILS (STRICT CATEGORY ISOLATION) ───────────────────────── */}
        {activeTab === 'DETAILS' && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '24px' }}>
            
            {/* ─────────────────────────────────────────────────────────────────── */}
            {/* 1. URL SCAN DETAILS (NO FILE HASHES, NO YARA, NO PE)               */}
            {/* ─────────────────────────────────────────────────────────────────── */}
            {isUrlScan && (
              <div style={{ gridColumn: 'span 12', display: 'flex', flexDirection: 'column', gap: '24px' }}>
                
                {/* 1A. URL & HTTP Telemetry Properties */}
                <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                    <span className="material-symbols-outlined" style={{ color: '#00f2ff', fontSize: '20px' }}>http</span>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                      URL & HTTP Response Properties
                    </h3>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ width: '160px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Target URL</div>
                      <div className="font-data-mono" style={{ color: '#e2e8f0', fontSize: '13px', wordBreak: 'break-all', textAlign: 'right', flex: 1 }}>
                        {analysisResult?.url || targetClean}
                      </div>
                    </div>

                    {analysisResult?.extended?.httpResponse?.finalUrl && (
                      <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                        <div style={{ width: '160px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Final Resolved URL</div>
                        <div className="font-data-mono" style={{ color: '#00ffa3', fontSize: '13px', wordBreak: 'break-all', textAlign: 'right', flex: 1 }}>
                          {analysisResult.extended.httpResponse.finalUrl}
                        </div>
                      </div>
                    )}

                    {analysisResult?.extended?.httpResponse?.servingIp && (
                      <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                        <div style={{ width: '160px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Serving IP</div>
                        <div className="font-data-mono" style={{ color: '#38bdf8', fontSize: '13px' }}>
                          {analysisResult.extended.httpResponse.servingIp}
                        </div>
                      </div>
                    )}

                    {analysisResult?.extended?.httpResponse?.statusCode && (
                      <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                        <div style={{ width: '160px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Status Code</div>
                        <div className="font-data-mono" style={{ color: '#00ffa3', fontSize: '13px', fontWeight: 600 }}>
                          {analysisResult.extended.httpResponse.statusCode} OK
                        </div>
                      </div>
                    )}

                    {analysisResult?.extended?.httpResponse?.bodyLength && (
                      <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                        <div style={{ width: '160px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Body Length</div>
                        <div className="font-data-mono" style={{ color: '#cbd5e1', fontSize: '13px' }}>
                          {formatBytes(analysisResult.extended.httpResponse.bodyLength)}
                        </div>
                      </div>
                    )}

                    {analysisResult?.extended?.htmlInfo?.title && (
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <div style={{ width: '160px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Page Title</div>
                        <div style={{ color: '#f1f5f9', fontSize: '13px', textAlign: 'right', flex: 1, fontWeight: 500 }}>
                          {analysisResult.extended.htmlInfo.title}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* 1B. HTTP Response Headers */}
                {analysisResult?.extended?.httpResponse?.headers && Object.keys(analysisResult.extended.httpResponse.headers).length > 0 && (
                  <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                      <span className="material-symbols-outlined" style={{ color: '#38bdf8', fontSize: '20px' }}>security</span>
                      <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                        HTTP Response & Security Headers
                      </h3>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {Object.entries(analysisResult.extended.httpResponse.headers).map(([hdr, val]) => (
                        <div key={hdr} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px' }}>
                          <span style={{ color: '#94a3b8', fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{hdr}</span>
                          <span className="font-data-mono" style={{ color: '#cbd5e1', fontSize: '12px', wordBreak: 'break-all', textAlign: 'right', maxWidth: '60%' }}>
                            {String(val)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 1C. SSL / TLS Certificate Inspector */}
                <CertInspectorCard domain={analysisResult?.url || targetClean} />

                {/* 1D. PhishGuard & WebFox Live Modules */}
                {phishResult && <PhishGuardCard result={phishResult} url={analysisResult?.url || targetClean} />}
                {(webfoxResult || isWebfoxLoading) && (
                  <WebFoxCard 
                    recon={webfoxResult || { domain: analysisResult?.url || targetClean, dnsRecords: [], subdomains: [], securityHeaders: [], headerSecurityScore: 0 }} 
                    loading={isWebfoxLoading} 
                  />
                )}

                {/* 1E. Threat Feed Reputation */}
                <ThreatFeedCard target={analysisResult?.url || targetClean} threatScore={score} />
              </div>
            )}

            {/* ─────────────────────────────────────────────────────────────────── */}
            {/* 2. DOMAIN SCAN DETAILS (NO FILE HASHES, NO YARA, NO PE)            */}
            {/* ─────────────────────────────────────────────────────────────────── */}
            {isDomainScan && (
              <div style={{ gridColumn: 'span 12', display: 'flex', flexDirection: 'column', gap: '24px' }}>
                
                {/* 2A. Domain Properties & WHOIS */}
                <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                    <span className="material-symbols-outlined" style={{ color: '#00f2ff', fontSize: '20px' }}>language</span>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                      Domain Properties & WHOIS
                    </h3>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Domain Name</div>
                      <div className="font-data-mono" style={{ color: '#e2e8f0', fontSize: '13px' }}>{domainResult?.domain || targetClean}</div>
                    </div>

                    {domainResult?.registrar && (
                      <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                        <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Registrar</div>
                        <div style={{ color: '#cbd5e1', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>{domainResult.registrar}</div>
                      </div>
                    )}

                    {domainResult?.creation ? (
                      <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                        <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Creation Date</div>
                        <div style={{ color: '#cbd5e1', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
                          {new Date(domainResult.creation * 1000).toUTCString()} ({formatRelativeTime(domainResult.creation)})
                        </div>
                      </div>
                    ) : null}

                    {domainResult?.expiration ? (
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Expiration Date</div>
                        <div style={{ color: '#cbd5e1', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
                          {new Date(domainResult.expiration * 1000).toUTCString()}
                        </div>
                      </div>
                    ) : null}
                  </div>
                </div>

                {/* 2B. SSL / TLS Certificate Inspector */}
                <CertInspectorCard domain={domainResult?.domain || targetClean} />

                {/* 2C. PhishGuard & WebFox Live Modules */}
                {phishResult && <PhishGuardCard result={phishResult} url={domainResult?.domain || targetClean} />}
                {(webfoxResult || isWebfoxLoading) && (
                  <WebFoxCard 
                    recon={webfoxResult || { domain: domainResult?.domain || targetClean, dnsRecords: [], subdomains: [], securityHeaders: [], headerSecurityScore: 0 }} 
                    loading={isWebfoxLoading} 
                  />
                )}

                {/* 2D. Threat Feed Reputation */}
                <ThreatFeedCard target={domainResult?.domain || targetClean} threatScore={score} />
              </div>
            )}

            {/* ─────────────────────────────────────────────────────────────────── */}
            {/* 3. IP ADDRESS SCAN DETAILS (NO FILE HASHES, NO YARA, NO PE)        */}
            {/* ─────────────────────────────────────────────────────────────────── */}
            {isIpScan && (
              <div style={{ gridColumn: 'span 12', display: 'flex', flexDirection: 'column', gap: '24px' }}>
                
                {/* 3A. IP Geolocation & Routing */}
                <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                    <span className="material-symbols-outlined" style={{ color: '#00f2ff', fontSize: '20px' }}>public</span>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                      IP Geolocation & Autonomous System Telemetry
                    </h3>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>IP Address</div>
                      <div className="font-data-mono" style={{ color: '#e2e8f0', fontSize: '13px' }}>{ipResult?.ip || targetClean}</div>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Country / Region</div>
                      <div style={{ color: '#cbd5e1', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
                        {ipResult?.country || 'Unknown'}
                      </div>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                      <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Autonomous System (ASN)</div>
                      <div className="font-data-mono" style={{ color: '#38bdf8', fontSize: '13px' }}>
                        {ipResult?.asn ? `AS${ipResult.asn}` : '—'} ({ipResult?.asOwner || '—'})
                      </div>
                    </div>

                    {ipResult?.network && (
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Network Block</div>
                        <div className="font-data-mono" style={{ color: '#cbd5e1', fontSize: '13px' }}>{ipResult.network}</div>
                      </div>
                    )}
                  </div>
                </div>

                {/* 3B. Threat Feed Reputation */}
                <ThreatFeedCard target={ipResult?.ip || targetClean} threatScore={score} />
              </div>
            )}

            {/* ─────────────────────────────────────────────────────────────────── */}
            {/* 4. FILE SCAN DETAILS (COMPLETE CRYPTOGRAPHIC HASHES & FORENSICS)   */}
            {/* ─────────────────────────────────────────────────────────────────── */}
            {isFile && (
              <>
                {/* Sidebar Table of Contents for Files */}
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
                        ...(!hasSpecializedFileModule && fileResult?.extended?.exiftool && Object.keys(fileResult.extended.exiftool).length > 0 ? [{ id: 'details-exif', label: 'ExifTool Metadata' }] : []),
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

                {/* Main Details Sections for Files */}
                <div style={{ gridColumn: 'span 9', display: 'flex', flexDirection: 'column', gap: '28px' }}>

                  {/* Image Forensics */}
                  {isImage && imageForensics && (
                    <div id="details-image-forensics">
                      <ImageForensicsCard report={imageForensics} />
                    </div>
                  )}

                  {/* Audio Forensics */}
                  {audioForensics && (
                    <div id="details-audio-forensics">
                      <AudioForensicsCard report={audioForensics} />
                    </div>
                  )}

                  {/* Video Forensics */}
                  {videoForensics && (
                    <div id="details-video-forensics">
                      <VideoForensicsCard report={videoForensics} />
                    </div>
                  )}

                  {/* Document Forensics */}
                  {docForensics && (
                    <div id="details-doc-forensics">
                      <DocumentForensicsCard report={docForensics} />
                    </div>
                  )}

                  {/* Archive Forensics */}
                  {archiveForensics && (
                    <div id="details-archive-forensics">
                      <ArchiveForensicsCard report={archiveForensics} />
                    </div>
                  )}

                  {/* Basic Properties */}
                  <div id="details-basic" style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                      <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                        Basic properties
                      </h3>
                      <span className="material-symbols-outlined" style={{ fontSize: '16px', color: '#64748b' }}>info</span>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
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

                      {(fileResult?.sha256 || targetClean) && (
                        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                          <div style={{ width: '140px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>SHA-256</div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, justifyContent: 'flex-end' }}>
                            <span className="font-data-mono" style={{ color: '#e2e8f0', fontSize: '13px', wordBreak: 'break-all' }}>{fileResult?.sha256 || targetClean}</span>
                            <button onClick={() => handleCopy(fileResult?.sha256 || targetClean, 'sha256')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'sha256' ? '#00ffa3' : '#64748b' }}>
                              <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>{copiedKey === 'sha256' ? 'check' : 'content_copy'}</span>
                            </button>
                          </div>
                        </div>
                      )}

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

                  {/* History */}
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
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Last Analysis</div>
                          <div style={{ color: '#cbd5e1', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
                            {new Date(fileResult.lastSeen * 1000).toUTCString()} ({formatRelativeTime(fileResult.lastSeen)})
                          </div>
                        </div>
                      ) : null}
                    </div>
                  </div>

                  {/* Names */}
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

                  {/* Automatic YARA Rules (FILES ONLY) */}
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

                  {/* PE Headers & Sections (FILES ONLY) */}
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

                        {fileResult.extended.peInfo.sections && fileResult.extended.peInfo.sections.length > 0 && (
                          <div style={{ marginTop: '12px' }}>
                            <div style={{ fontSize: '13px', color: '#94a3b8', fontWeight: 600, marginBottom: '10px' }}>Sections ({fileResult.extended.peInfo.sections.length})</div>
                            <div style={{ overflowX: 'auto' }}>
                              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                                <thead>
                                  <tr style={{ borderBottom: '1px solid #334155', color: '#64748b' }}>
                                    <th style={{ padding: '8px' }}>Name</th>
                                    <th style={{ padding: '8px' }}>Entropy</th>
                                    <th style={{ padding: '8px' }}>Virtual Size</th>
                                    <th style={{ padding: '8px' }}>Raw Size</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {fileResult.extended.peInfo.sections.map((sec, i) => (
                                    <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                                      <td style={{ padding: '8px', color: '#38bdf8', fontWeight: 600 }}>{sec.name}</td>
                                      <td style={{ padding: '8px', color: sec.entropy > 7 ? '#ff2a5f' : '#00ffa3' }}>{sec.entropy.toFixed(2)}</td>
                                      <td style={{ padding: '8px', color: '#cbd5e1' }}>{sec.virtual_size}</td>
                                      <td style={{ padding: '8px', color: '#cbd5e1' }}>{sec.raw_size}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* MITRE ATT&CK */}
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

                </div>
              </>
            )}

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

        {/* ── TAB 6: SUMMARY (UNIFIED MULTI-ENGINE & FORENSIC SYNTHESIS) ─────── */}
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
            {/* 1. Atlas AI Verdict & Remediation */}
            <AiSummary threatData={fileResult || analysisResult || domainResult || ipResult} type={isFile ? 'file' : 'url'} />
            
            {/* 2. Specialized Media & Document Forensics Engine for Files */}
            {isFile && isImage && imageForensics && (
              <ImageForensicsCard report={imageForensics} />
            )}

            {isFile && audioForensics && (
              <AudioForensicsCard report={audioForensics} />
            )}

            {isFile && videoForensics && (
              <VideoForensicsCard report={videoForensics} />
            )}

            {isFile && docForensics && (
              <DocumentForensicsCard report={docForensics} />
            )}

            {isFile && archiveForensics && (
              <ArchiveForensicsCard report={archiveForensics} />
            )}

            {/* 3. Automatic YARA Rule Pattern Matcher for Files */}
            {isFile && (
              <AutomaticYaraCard 
                fileResult={fileResult}
                crowdsourcedYara={fileResult?.extended?.crowdsourcedYara}
              />
            )}

            {/* 4. Multi-Source Threat Feeds */}
            <ThreatFeedCard target={displayTitle} threatScore={score} tags={fileResult?.tags} />

            {/* 5. URL & Domain Specialized Modules */}
            {(isUrlScan || isDomainScan) && (
              <CertInspectorCard domain={analysisResult?.url || domainResult?.domain || targetClean} />
            )}

            {(isUrlScan || isDomainScan) && phishResult && (
              <PhishGuardCard result={phishResult} url={analysisResult?.url || domainResult?.domain || targetClean} />
            )}
            {(isUrlScan || isDomainScan) && (webfoxResult || isWebfoxLoading) && (
              <WebFoxCard recon={webfoxResult || { domain: analysisResult?.url || domainResult?.domain || targetClean, dnsRecords: [], subdomains: [], securityHeaders: [], headerSecurityScore: 0 }} loading={isWebfoxLoading} />
            )}
          </div>
        )}

      </div>
    </div>
  );
};
