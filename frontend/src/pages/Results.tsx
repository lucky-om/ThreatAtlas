import React, { useEffect, useState, useRef } from 'react';
import { motion } from 'framer-motion';
import { useParams, useSearchParams, useNavigate, useLocation } from 'react-router-dom';
import { SEO } from '../components/SEO';
import { Gauge } from '../components/Gauge';
import { EngineGrid } from '../components/EngineGrid';
import { AiSummary } from '../components/AiSummary';
import { TiltWrapper } from '../components/TiltWrapper';
import { PageReveal } from '../components/PageReveal';
import { MountainLoader } from '../components/MountainLoader';
import { YaraScannerModule } from '../components/YaraScannerModule';
import { RefreshCw, Activity, Clock, Shield, Lock, AlertTriangle, Info } from 'lucide-react';
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
import { analyzePhishGuardLive, PhishGuardResult } from '../services/phishguard';
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
  extractArchiveForensics,
  extractPeForensics,
  extractElfForensics,
  extractApkForensics,
  extractEmailForensics,
  extractPcapForensics,
  detectMagicDiscrepancy
} from '../services/mediaForensics';
import { ImageForensicsCard } from '../components/ImageForensicsCard';
import { AudioForensicsCard } from '../components/AudioForensicsCard';
import { VideoForensicsCard } from '../components/VideoForensicsCard';
import { DocumentForensicsCard } from '../components/DocumentForensicsCard';
import { ArchiveForensicsCard } from '../components/ArchiveForensicsCard';
import { PeExecutableCard } from '../components/PeExecutableCard';
import { ElfExecutableCard } from '../components/ElfExecutableCard';
import { ApkForensicsCard } from '../components/ApkForensicsCard';
import { EmailForensicsCard } from '../components/EmailForensicsCard';
import { PcapForensicsCard } from '../components/PcapForensicsCard';

import { MagicDiscrepancyBanner } from '../components/MagicDiscrepancyBanner';
import { CertInspectorCard } from '../components/CertInspectorCard';
import { ThreatFeedCard } from '../components/ThreatFeedCard';
import { Skeleton } from '../components/SkeletonLoader';
import { generatePdfThreatReport } from '../utils/pdfExport';
import { addScanHistoryItem } from '../services/historyStore';
import { getCachedItem, setCachedItem, clearCache } from '../services/cache';
import { formatRelativeTime, formatBytes } from '../utils/sanitize';

type Tab = 'DETECTION' | 'DETAILS' | 'STATIC_ANALYSIS' | 'DYNAMIC_ANALYSIS' | 'RELATIONS' | 'COMMUNITY' | 'SUMMARY' | 'BEHAVIOR';

export const Results: React.FC = () => {
  const location = useLocation();
  const { id: pathId, hash: pathHash, query: pathQuery, tab } = useParams();
  const [searchParams] = useSearchParams();
  
  const uploadedFile = location.state?.uploadedFile as File | undefined;
  
  const rawTarget = pathId || pathHash || pathQuery || searchParams.get('id') || searchParams.get('hash') || searchParams.get('q') || searchParams.get('query') || '';

  const [loading, setLoading] = useState(true);
  const [elapsedSec, setElapsedSec] = useState<number>(0);
  const [liveStage, setLiveStage] = useState<string>('Initializing threat intelligence handshake...');
  const [liveEngineCount, setLiveEngineCount] = useState<number>(0);
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
    try {
      navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch {
      // ignore
    }
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
      if (['DETECTION', 'DETAILS', 'STATIC_ANALYSIS', 'DYNAMIC_ANALYSIS', 'RELATIONS', 'COMMUNITY', 'SUMMARY'].includes(upperTab)) {
        // eslint-disable-next-line react-hooks/set-state-in-effect
        setActiveTab(upperTab);
      }
    }
  }, [tab]);

  // ── PRECISE TARGET CATEGORIZATION ENGINE ──────────────────────────────────
  const targetClean = rawTarget.trim();
  const isFileRoute = Boolean(pathHash || window.location.pathname.startsWith('/file/'));
  const isUrlRoute = Boolean(pathId || window.location.pathname.startsWith('/url/'));
  const isDomainRoute = Boolean(window.location.pathname.startsWith('/domain/'));
  const isIpRoute = Boolean(window.location.pathname.startsWith('/ip-address/') || window.location.pathname.startsWith('/ip/'));

  const isUrlToken = !isFileRoute && (targetClean.startsWith('u-') || targetClean.startsWith('http://') || targetClean.startsWith('https://'));
  const isPureHash = !isUrlToken && isValidHash(targetClean);
  const isPureIp = isValidIp(targetClean);
  const detected = detectInputType(targetClean);

  const isFile = Boolean(
    isFileRoute ||
    fileResult ||
    (isPureHash && !isUrlToken) ||
    (analysisResult?.hash && isValidHash(analysisResult.hash))
  );

  // Auto-correct active tab when data resolves and confirms scan type
  // (e.g., user arrived with ?tab=BEHAVIOR but it's a URL scan)
  useEffect(() => {
    if (!isFile && activeTab === 'BEHAVIOR') {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setActiveTab('DETECTION');
    }
  }, [isFile, activeTab]);

  const executeUnifiedScan = async (forceFresh = false) => {
    setLoading(true);
    setError(null);
    setElapsedSec(0);
    setLiveEngineCount(0);
    setLiveStage('Initializing threat intelligence handshake...');

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

    const startTs = Date.now();
    const elapsedTimer = setInterval(() => {
      setElapsedSec(Math.floor((Date.now() - startTs) / 1000));
    }, 1000);

    try {
      // ── 1. Cryptographic Hash Search (Direct File Lookup) ─────────────────
      if (isHash) {
        setLiveStage('Querying global multi-vendor antivirus database for hash signatures...');
        const apiKey = import.meta.env.VITE_VT_API_KEY || '';
        const headers = apiKey ? { 'x-apikey': apiKey } : undefined;
        const [fileData, behaviorRes] = await Promise.allSettled([
          lookupHash(target),
          fetch(`https://www.virustotal.com/api/v3/files/${target}/behaviours?limit=5`, { headers }).then(r => r.ok ? r.json() : null)
        ]);

        if (fileData.status === 'fulfilled') {
          const data = fileData.value;
          setFileResult(data);
          setCachedItem(target, data);

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
        setLiveStage('Live engine pipeline active — streaming vendor verdicts in real time...');
        // Stream live engine results as they arrive
        const analysisData = await pollAnalysis(target, (progress) => {
          setAnalysisResult(progress);
          const count = progress.engines?.length || 0;
          setLiveEngineCount(count);
          if (count > 0) {
            setLiveStage(`Received live telemetry from ${count} security engines...`);
          }
        });
        setAnalysisResult(analysisData);
        setCachedItem(target, analysisData);

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
              const apiKey = import.meta.env.VITE_VT_API_KEY || '';
              const headers = apiKey ? { 'x-apikey': apiKey } : undefined;
              const [fullFileData, behaviorRes] = await Promise.allSettled([
                lookupHash(analysisData.hash),
                fetch(`https://www.virustotal.com/api/v3/files/${analysisData.hash}/behaviours?limit=5`, { headers }).then(r => r.ok ? r.json() : null)
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
            } catch (_) { /* history write failed */ }
          }
        } else {
          addScanHistoryItem({
            id: analysisData.id || target,
            target: analysisData.url || target,
            type: 'url',
            name: analysisData.url || target,
            verdict: analysisData.verdict || ((analysisData.stats?.malicious || 0) > 0 ? 'malicious' : 'clean'),
            threatScore: analysisData.stats?.malicious || 0,
            maliciousCount: analysisData.stats?.malicious || 0,
            totalEngines: analysisData.engines?.length || 70
          });

          if (analysisData.url) {
            setPhishResult(await analyzePhishGuardLive(analysisData.url));
            setIsWebfoxLoading(true);
            runWebFoxRecon(analysisData.url)
              .then(wf => setWebfoxResult(wf))
              .catch(() => {})
              .finally(() => setIsWebfoxLoading(false));
          }
        }
        return;
      }

      // ── 3. IP Address Search ──────────────────────────────────────────────
      if (isIp) {
        setLiveStage('Resolving IP geolocation, ASN routing, and threat feeds...');
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
        setLiveStage('Querying authoritative DNS records, RDAP WHOIS, and SSL certificates...');
        const targetUrl = `https://${target}`;
        setPhishResult(await analyzePhishGuardLive(targetUrl));
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
      setLiveStage('Evaluating URL structure, HTTP response headers, and phishing telemetry...');
      const targetUrl = target.startsWith('http') ? target : `https://${target}`;
      setPhishResult(await analyzePhishGuardLive(targetUrl));
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
        setLiveStage('URL queued in global pipeline — polling multi-engine scanners...');
        const scanRes = await scanUrl(targetUrl);
        if (scanRes?.data?.id) {
          const data = await pollAnalysis(scanRes.data.id, (progress) => {
            setAnalysisResult(progress);
            const count = progress.engines?.length || 0;
            setLiveEngineCount(count);
            if (count > 0) {
              setLiveStage(`Received live telemetry from ${count} security engines...`);
            }
          });
          setAnalysisResult(data);
          setCachedItem(target, data);
        }
      }
    } catch (err: any) {
      setError(err.message || 'Threat scan failed. Please verify the target.');
    } finally {
      clearInterval(elapsedTimer);
      setLoading(false);
    }
  };

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
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
    const isAnalysis = rawTarget.startsWith('u-') || rawTarget.includes(':') || (rawTarget.length >= 44 && !isValidHash(rawTarget));
    // Detect scan type for loader color BEFORE targetCategory is computed below
    const loaderType: 'file' | 'url' | 'domain' | 'ip' = (() => {
      if (isValidHash(rawTarget) || rawTarget.startsWith('u-')) return rawTarget.startsWith('u-') ? 'url' : 'file';
      if (rawTarget.startsWith('http://') || rawTarget.startsWith('https://')) return 'url';
      if (isValidIp(rawTarget)) return 'ip';
      if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(rawTarget)) return 'domain';
      return 'file';
    })();

    const getEstimatedTime = () => {
      if (!isAnalysis) return '~3s';
      if (loaderType === 'ip') return '~2s';
      if (loaderType === 'domain') return '~4s';
      if (loaderType === 'url') return '~12s';
      
      if (loaderType === 'file') {
        if (uploadedFile) {
          const sizeMB = uploadedFile.size / (1024 * 1024);
          const ext = uploadedFile.name.split('.').pop()?.toLowerCase() || '';
          
          let baseTime = 15;
          if (['exe', 'dll', 'sys', 'apk', 'elf', 'bin'].includes(ext)) baseTime = 40;
          else if (['pdf', 'doc', 'docx', 'xls', 'xlsx', 'rtf'].includes(ext)) baseTime = 25;
          else if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) baseTime = 30;
          else if (['png', 'jpg', 'jpeg', 'gif', 'mp3', 'mp4'].includes(ext)) baseTime = 10;
          
          return `~${Math.round(baseTime + sizeMB)}s`;
        }
        return '~35s';
      }
      return '~15s';
    };

    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        style={{
          position: 'relative', minHeight: '100vh', paddingTop: '80px',
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          backgroundColor: 'var(--bg)', color: 'var(--text)',
        }}
      >
        <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '660px', width: '100%', marginTop: '60px', padding: '0 20px' }}>
          <motion.div
            initial={{ opacity: 0, y: 28, filter: 'blur(12px)' }}
            animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
            transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
            className="glass-card"
            style={{ padding: '40px 36px', textAlign: 'center' }}
          >
            {/* ── Mountain animation ── */}
            <MountainLoader
              scanType={loaderType}
              label={`${loaderType.toUpperCase()} SCAN`}
              sublabel={rawTarget}
              style={{ marginBottom: '24px' }}
            />

            {/* ── Live stage pill ── */}
            <motion.div
              key={liveStage}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.25 }}
              style={{
                background: 'var(--primary-dim)',
                border: '1px solid var(--primary-border)',
                borderRadius: 'var(--radius-md)',
                padding: '10px 16px',
                marginBottom: '20px',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
              }}
            >
              <Activity size={14} style={{ color: 'var(--primary)', flexShrink: 0 }} />
              <div style={{ flex: 1, textAlign: 'left' }}>
                <div style={{ fontSize: '9px', color: 'var(--primary)', fontWeight: 700, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                  Active Operation
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text)', fontWeight: 500, marginTop: '2px', fontFamily: 'var(--font-display)' }}>
                  {liveStage}
                </div>
              </div>
            </motion.div>

            {/* ── Stats row ── */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px', marginBottom: '20px' }}>
              <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '10px 12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '9px', color: 'var(--text-3)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', marginBottom: '3px' }}>
                  <Clock size={9} /> Elapsed
                </div>
                <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text)', fontFamily: 'var(--font-mono)', fontVariantNumeric: 'tabular-nums' }}>
                  {elapsedSec}s
                </div>
              </div>
              <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '10px 12px' }}>
                <div style={{ fontSize: '9px', color: 'var(--text-3)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', marginBottom: '3px' }}>Est.</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>
                  {getEstimatedTime()}
                </div>
              </div>
              <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '10px 12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '9px', color: 'var(--text-3)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', marginBottom: '3px' }}>
                  <Shield size={9} /> Engines
                </div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: liveEngineCount > 0 ? 'var(--success)' : 'var(--text-2)', fontFamily: 'var(--font-mono)' }}>
                  {liveEngineCount > 0 ? `${liveEngineCount} live` : 'Connecting…'}
                </div>
              </div>
            </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-3)', fontFamily: 'var(--font-mono)', borderTop: '1px solid var(--border)', paddingTop: '12px', marginBottom: '32px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Lock size={10} style={{ color: 'var(--success)' }} />
                TLS Encrypted
              </div>
              <div>ThreatAtlas Engine v3</div>
            </div>
            
            {/* ── SKELETON PREVIEW LAYOUT ── */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', textAlign: 'left', borderTop: '1px solid var(--border)', paddingTop: '32px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-3)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                Preparing report structure...
              </div>
              <div style={{ display: 'flex', gap: '16px' }}>
                <Skeleton width="60px" height="60px" borderRadius="12px" />
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '8px', justifyContent: 'center' }}>
                  <Skeleton width="60%" height="24px" />
                  <Skeleton width="40%" height="16px" />
                </div>
              </div>
              
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', marginTop: '8px' }}>
                <Skeleton height="70px" borderRadius="12px" />
                <Skeleton height="70px" borderRadius="12px" />
                <Skeleton height="70px" borderRadius="12px" />
                <Skeleton height="70px" borderRadius="12px" />
              </div>
            </div>
          </motion.div>
        </div>
      </motion.div>
    );
  }

  if (error) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        style={{
          position: 'relative', minHeight: '100vh', paddingTop: '100px',
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          backgroundColor: 'var(--bg)',
        }}
      >
        
        <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '640px', width: '100%', marginTop: '60px', padding: '0 20px' }}>
          <motion.div
            initial={{ opacity: 0, y: 24, filter: 'blur(10px)' }}
            animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
            transition={{ duration: 0.5 }}
            className="glass-card"
            style={{ padding: '48px', textAlign: 'center', borderColor: 'var(--danger-border)' }}
          >
            <motion.div
              initial={{ scale: 0.8 }}
              animate={{ scale: 1 }}
              transition={{ type: 'spring', stiffness: 300, damping: 20 }}
              style={{ marginBottom: '18px' }}
            >
              <AlertTriangle size={52} style={{ color: 'var(--danger)', filter: 'drop-shadow(0 0 12px var(--danger-glow))' }} />
            </motion.div>
            <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '20px', fontWeight: 700, color: 'var(--text)', marginBottom: '12px' }}>
              Scan Error
            </h2>
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--text-2)', lineHeight: 1.6, marginBottom: '28px' }}>
              {error}
            </p>
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              className="btn-primary"
              onClick={() => executeUnifiedScan(true)}
            >
              <RefreshCw size={14} style={{ marginRight: '7px' }} />
              Retry Scan
            </motion.button>
          </motion.div>
        </div>
      </motion.div>
    );
  }

  // isPending tracks only the primary analysis — WebFox loading is shown separately
  const queryAnalysisId = searchParams.get('analysisId');
  const isPending = loading && (analysisResult?.status === 'queued' || analysisResult?.status === 'in-progress' || Boolean(queryAnalysisId && (!fileResult || !fileResult.engines || fileResult.engines.length === 0)));

  // Helper to get HTTP status text
  const getHttpStatusText = (code: number): string => {
    const texts: Record<number, string> = {
      200: 'OK', 201: 'Created', 204: 'No Content', 301: 'Moved Permanently',
      302: 'Found', 304: 'Not Modified', 400: 'Bad Request', 401: 'Unauthorized',
      403: 'Forbidden', 404: 'Not Found', 429: 'Too Many Requests',
      500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable',
    };
    return texts[code] || '';
  };

  // ── PRECISE TARGET CATEGORIZATION ENGINE ──────────────────────────────────
  const isUrlScan = Boolean(!isFile && (isUrlRoute || isUrlToken || detected === 'url' || (analysisResult && !analysisResult.hash)));
  const isDomainScan = Boolean(!isFile && !isUrlScan && (isDomainRoute || domainResult || detected === 'domain'));
  const isIpScan = Boolean(!isFile && !isUrlScan && !isDomainScan && (isIpRoute || ipResult || isPureIp));

  const targetCategory: 'file' | 'url' | 'domain' | 'ip' = isFile ? 'file' : isUrlScan ? 'url' : isDomainScan ? 'domain' : 'ip';

  const stats = fileResult?.stats || analysisResult?.stats || domainResult?.stats || ipResult?.stats;
  const engines = fileResult?.engines || analysisResult?.engines || domainResult?.engines || ipResult?.engines || [];

  const score = stats?.malicious || 0;
  const total = (stats?.malicious || 0) + (stats?.undetected || 0) + (stats?.harmless || 0) + (stats?.suspicious || 0) + (stats?.timeout || 0) || engines.length || 60;

  // Header display details
  const displayTitle = isFile 
    ? (fileResult?.names?.[0] || fileResult?.name || searchParams.get('name') || fileResult?.sha256 || targetClean)
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
  const fileCategory = isFile && fileResult ? getFileCategory(fileResult, targetClean) : 'generic';
  
  const isImage = isFile && fileResult ? (fileCategory === 'image' || isImageFile(fileResult, targetClean)) : false;

  const baseImageForensics = isImage && fileResult ? extractImageForensics(fileResult) : null;
  // If backend provided rich data, we can optionally merge it here. For now, we pass baseImageForensics 
  // but we can augment it with backend data. We'll pass both to ImageForensicsCard below.
  const imageForensics = baseImageForensics;
  const audioForensics = isFile && fileResult && fileCategory === 'audio' && !isImage ? extractAudioForensics(fileResult) : null;
  const videoForensics = isFile && fileResult && fileCategory === 'video' && !isImage ? extractVideoForensics(fileResult) : null;
  const docForensics = isFile && fileResult && fileCategory === 'document' && !isImage ? extractDocumentForensics(fileResult) : null;
  const archiveForensics = isFile && fileResult && fileCategory === 'archive' && !isImage ? extractArchiveForensics(fileResult) : null;
  const peForensics = isFile && fileResult && fileCategory === 'executable' && !isImage ? extractPeForensics(fileResult) : null;
  const elfForensics = isFile && fileResult && fileCategory === 'elf' && !isImage ? extractElfForensics(fileResult) : null;
  const apkForensics = isFile && fileResult && fileCategory === 'apk' && !isImage ? extractApkForensics(fileResult) : null;
  const emailForensics = isFile && fileResult && fileCategory === 'email' && !isImage ? extractEmailForensics(fileResult) : null;
  const pcapForensics = isFile && fileResult && fileCategory === 'pcap' && !isImage ? extractPcapForensics(fileResult) : null;
  const magicDiscrepancy = isFile && fileResult ? detectMagicDiscrepancy(fileResult, targetClean) : null;

  const hasSpecializedFileModule = Boolean(isImage || audioForensics || videoForensics || docForensics || archiveForensics || peForensics || elfForensics || apkForensics || emailForensics || pcapForensics);

  const handleExportPdf = async () => {
    const data = fileResult || analysisResult || domainResult || ipResult;
    if (!data) return;
    setIsExportingPdf(true);
    setShowMoreMenu(false);
    try {
      const summaryText = score > 0 
        ? `VERDICT: CRITICAL / SUSPICIOUS (${score}/${total} vendors flagged malicious). Target exhibits indicators of compromise (IOC), suspicious signature patterns, or hostile communication telemetry.\n* Immediate Action: Quarantine endpoint, block SHA-256 hash/IP at firewall boundary, and inspect SIEM/EDR logs.`
        : `VERDICT: VERIFIED CLEAN (0/${total} detections). Zero security vendors flagged this ${targetCategory}.\n* Structural headers and telemetry check out cleanly. Safe to use under baseline corporate policy.`;

      await generatePdfThreatReport({
        threatData: data,
        targetType: targetCategory,
        targetName: displayTitle,
        score,
        total,
        aiSummaryText: summaryText,
        imageForensics,
        audioForensics,
        videoForensics,
        docForensics,
        archiveForensics,
        peForensics,
        elfForensics,
        apkForensics,
        emailForensics,
        pcapForensics,
        webfoxResult,
        yaraMatches: isFile ? fileResult?.extended?.crowdsourcedYara : undefined
      });
    } catch (err) {
      if (import.meta.env.DEV) console.error('Failed to export PDF threat report:', err);
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
    // Guard: BEHAVIOR tab is only valid for file scans
    if (t === 'BEHAVIOR' && !isFile) return;
    setActiveTab(t);
  };

  return (
    <>
      <SEO 
        title={`${displayTitle || 'Analysis'} - Threat Intelligence Report`}
        description={`Detailed threat intelligence report for ${displayTitle}. Includes engine verdicts, static analysis, and forensic metadata.`}
        path={window.location.pathname}
      />
    {/* Results wrapper: scan-theme-* class applies the correct color palette */}
    <div
      className={`scan-theme-${targetCategory}`}
      style={{ position: 'relative', minHeight: '100vh', paddingTop: '80px', paddingBottom: '64px', color: 'var(--text)' }}
    >
      {/* Scan-type-specific glow — replaces generic digital-grid */}
      <div className="scan-type-glow" aria-hidden="true" />

      <div className="container" style={{ position: 'relative', zIndex: 10, maxWidth: '1280px' }}>
        <PageReveal>

        {isPending && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            style={{
              padding: '14px 20px',
              marginBottom: '24px',
              background: 'var(--primary-dim)',
              border: '1px solid var(--primary-border)',
              borderRadius: 'var(--radius-md)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
              {/* framer-motion spinner \u2014 no external icon font needed */}
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ repeat: Infinity, ease: 'linear', duration: 1.4 }}
                style={{ color: 'var(--primary)', flexShrink: 0 }}
              >
                <RefreshCw size={20} />
              </motion.div>
              <div>
                <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--primary)', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <span>LIVE SCAN IN PROGRESS</span>
                  <span style={{ fontSize: '11px', background: 'var(--primary-dim)', padding: '2px 8px', borderRadius: '4px', color: 'var(--text)', fontFamily: 'var(--font-mono)' }}>
                    {/* Show real engine count \u2014 no hardcoded 70 fallback */}
                    {engines.length > 0 ? `${engines.length} engines responded` : 'Querying engines\u2026'}
                  </span>
                </div>
                <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-2)', fontFamily: 'var(--font-mono)' }}>
                  Security engines are streaming results in real-time. Report is updating live.
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="animate-pulse" style={{ width: '7px', height: '7px', borderRadius: '50%', background: 'var(--success)', display: 'inline-block', boxShadow: '0 0 7px var(--success)' }} />
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--success)', fontWeight: 700 }}>STREAMING LIVE</span>
            </div>
          </motion.div>
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
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: communityVote === 'up' ? 'var(--brand-amber)' : '#64748b', display: 'flex', padding: 0 }}
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
                    <span className="material-symbols-outlined" style={{ color: 'var(--brand-amber)', fontSize: '22px' }}>check_circle</span>
                    <span style={{ color: 'var(--brand-amber)', fontSize: '14px', fontWeight: 600 }}>
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
                  onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--brand)'; e.currentTarget.style.color = '#fff'; }}
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
                    onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--brand)'; e.currentTarget.style.color = '#fff'; }}
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
                    background: 'linear-gradient(135deg, rgba(255, 69, 0, 0.15), rgba(255, 107, 53, 0.15))',
                    border: '1px solid rgba(255, 69, 0, 0.4)',
                    color: 'var(--brand)',
                    borderRadius: '6px',
                    padding: '5px 12px',
                    cursor: isExportingPdf ? 'wait' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '12px',
                    fontWeight: 700,
                    boxShadow: '0 0 12px rgba(255, 69, 0,0.15)',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.boxShadow = '0 0 20px rgba(255, 69, 0,0.3)'; e.currentTarget.style.borderColor = 'var(--brand)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.boxShadow = '0 0 12px rgba(255, 69, 0,0.15)'; e.currentTarget.style.borderColor = 'rgba(255, 69, 0, 0.4)'; }}
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
                        onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255, 69, 0, 0.08)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                      >
                        <span className="material-symbols-outlined" style={{ fontSize: '16px', color: 'var(--brand)' }}>data_object</span>
                        Copy JSON Report
                      </button>

                      <button
                        onClick={() => { setShowMoreMenu(false); navigate('/threat-graph'); }}
                        style={{
                          background: 'none', border: 'none', color: '#cbd5e1', padding: '8px 12px',
                          textAlign: 'left', fontSize: '12px', fontFamily: 'var(--font-mono)', cursor: 'pointer',
                          display: 'flex', alignItems: 'center', gap: '8px', borderRadius: '4px'
                        }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255, 69, 0, 0.08)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                      >
                        <span className="material-symbols-outlined" style={{ fontSize: '16px', color: 'var(--brand-ember)' }}>hub</span>
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
                        onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255, 69, 0, 0.08)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                      >
                        <span className="material-symbols-outlined" style={{ fontSize: '16px', color: 'var(--brand-amber)' }}>open_in_new</span>
                        View Full Report
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
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'header_target' ? 'var(--brand-amber)' : '#64748b', display: 'flex', padding: 0 }}
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
                    background: 'rgba(255, 69, 0, 0.08)',
                    border: '1px solid rgba(255, 69, 0, 0.2)',
                    color: 'var(--brand)',
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
                    <div style={{ fontSize: '13px', color: analysisResult.extended.httpResponse.statusCode < 400 ? 'var(--brand-amber)' : '#ff2a5f', fontFamily: 'var(--font-mono)', marginTop: '2px', fontWeight: 600 }}>
                      {analysisResult.extended.httpResponse.statusCode} {getHttpStatusText(analysisResult.extended.httpResponse.statusCode)}
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
                color: 'var(--brand)'
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
          overflowX: 'auto',
          scrollbarWidth: 'none',
        }}>
          {/* Context-sensitive tabs: BEHAVIOR only for file scans */}
          {(['DETECTION', 'DETAILS', ...(isFile ? ['BEHAVIOR'] : []), 'RELATIONS', 'COMMUNITY', 'SUMMARY'] as Tab[]).map((t) => {
            const isActive = activeTab === t;
            return (
              <button
                key={t}
                onClick={() => handleTabChange(t)}
                style={{
                  background: 'none',
                  border: 'none',
                  borderBottom: isActive ? '2px solid var(--brand)' : '2px solid transparent',
                  padding: '10px 20px',
                  color: isActive ? 'var(--brand)' : '#94a3b8',
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

          {/* WebFox loading badge — separate from primary scan status */}
          {isWebfoxLoading && (
            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '6px', padding: '0 12px', fontSize: '11px', color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>
              <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, ease: 'linear', duration: 1.4 }}>
                <RefreshCw size={11} />
              </motion.div>
              Recon running…
            </div>
          )}
        </div>

        {/* ── TAB 1: DETECTION ─────────────────────────────────────────────────── */}
        {activeTab === 'DETECTION' && (
          <div className="glass-card" style={{ padding: '28px 32px' }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '20px',
              borderBottom: '1px solid var(--border)',
              paddingBottom: '14px',
              flexWrap: 'wrap',
              gap: '10px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: 'var(--text)' }}>
                  Security vendors' analysis
                </h3>
                <Info size={16} style={{ color: 'var(--text-3)' }} />
              </div>

              <div style={{ fontSize: '12px', color: 'var(--text-3)', fontFamily: 'var(--font-mono)' }}>
                Multi-engine verdict verification
              </div>
            </div>

            {engines.length > 0 ? (
              <EngineGrid results={engines} />
            ) : (
              <div style={{ textAlign: 'center', padding: '48px', color: 'var(--text-3)' }} className="font-data-mono">
                {isPending ? "Waiting for engines to return results..." : "No engine data available."}
              </div>
            )}
          </div>
        )}

        {/* ── TAB 2: DETAILS (STRICT CATEGORY ISOLATION) ───────────────────────── */}
        {activeTab === 'DETAILS' && (
          <div className="responsive-grid">
            
            {/* ─────────────────────────────────────────────────────────────────── */}
            {/* 1. URL SCAN DETAILS (NO FILE HASHES, NO YARA, NO PE)               */}
            {/* ─────────────────────────────────────────────────────────────────── */}
            {isUrlScan && (
              <div style={{ gridColumn: 'span 12', display: 'flex', flexDirection: 'column', gap: '24px' }}>
                
                {/* 1A. URL & HTTP Telemetry Properties */}
                <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                    <span className="material-symbols-outlined" style={{ color: 'var(--brand)', fontSize: '20px' }}>http</span>
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
                        <div className="font-data-mono" style={{ color: 'var(--brand-amber)', fontSize: '13px', wordBreak: 'break-all', textAlign: 'right', flex: 1 }}>
                          {analysisResult.extended.httpResponse.finalUrl}
                        </div>
                      </div>
                    )}

                    {analysisResult?.extended?.httpResponse?.servingIp && (
                      <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                        <div style={{ width: '160px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Serving IP</div>
                        <div className="font-data-mono" style={{ color: 'var(--brand)', fontSize: '13px' }}>
                          {analysisResult.extended.httpResponse.servingIp}
                        </div>
                      </div>
                    )}

                    {analysisResult?.extended?.httpResponse?.statusCode && (
                      <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                        <div style={{ width: '160px', color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>Status Code</div>
                        <div className="font-data-mono" style={{ color: analysisResult.extended.httpResponse.statusCode < 400 ? 'var(--brand-amber)' : '#ff2a5f', fontSize: '13px', fontWeight: 600 }}>
                          {analysisResult.extended.httpResponse.statusCode} {getHttpStatusText(analysisResult.extended.httpResponse.statusCode)}
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
                      <span className="material-symbols-outlined" style={{ color: 'var(--brand)', fontSize: '20px' }}>security</span>
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
              <div className="col-span-12" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                
                {/* 2A. Domain Properties & WHOIS */}
                <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                    <span className="material-symbols-outlined" style={{ color: 'var(--brand)', fontSize: '20px' }}>language</span>
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
              <div className="col-span-12" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                
                {/* 3A. IP Geolocation & Routing */}
                <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                    <span className="material-symbols-outlined" style={{ color: 'var(--brand)', fontSize: '20px' }}>public</span>
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
                      <div className="font-data-mono" style={{ color: 'var(--brand)', fontSize: '13px' }}>
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
                <div className="col-span-3 hide-on-mobile">
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
                        ...(magicDiscrepancy?.hasDiscrepancy ? [{ id: 'details-magic-alert', label: '⚠️ Masquerading Alert' }] : []),
                        ...(isImage && imageForensics ? [{ id: 'details-image-forensics', label: '🖼️ Image Forensics & Stego' }] : []),
                        ...(audioForensics ? [{ id: 'details-audio-forensics', label: '🎧 Audio Stream & ID3 Forensics' }] : []),
                        ...(videoForensics ? [{ id: 'details-video-forensics', label: '🎬 Video Stream & Codecs' }] : []),
                        ...(docForensics ? [{ id: 'details-doc-forensics', label: '📄 Document Security & Macros' }] : []),
                        ...(archiveForensics ? [{ id: 'details-archive-forensics', label: '📦 Archive & Container Forensics' }] : []),
                        ...(emailForensics ? [{ id: 'details-email-forensics', label: '📧 Email Headers & Phishing Routing' }] : []),
                        ...(pcapForensics ? [{ id: 'details-pcap-forensics', label: '🌐 Network PCAP Capture Forensics' }] : []),
                        { id: 'details-basic', label: 'Basic properties' },

                        { id: 'details-history', label: 'History' },
                        { id: 'details-names', label: 'Names' },
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
                            background: activeSection === sec.label ? 'rgba(255, 69, 0, 0.08)' : 'transparent',
                            border: 'none',
                            borderRadius: '6px',
                            padding: '8px 12px',
                            color: activeSection === sec.label ? 'var(--brand)' : '#94a3b8',
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

                  {/* Magic Discrepancy Alert */}
                  {magicDiscrepancy && magicDiscrepancy.hasDiscrepancy && (
                    <div id="details-magic-alert">
                      <MagicDiscrepancyBanner discrepancy={magicDiscrepancy} />
                    </div>
                  )}

                  {/* Image Forensics */}
                  {isImage && imageForensics && (
                    <div id="details-image-forensics">
                      <ImageForensicsCard report={imageForensics} file={uploadedFile} />
                    </div>
                  )}

                  {/* Video & Audio Forensics */}
                  {isFile && fileCategory === 'video' && (
                    <div id="details-video-forensics">
                      <VideoForensicsCard file={uploadedFile} />
                    </div>
                  )}

                  {isFile && fileCategory === 'audio' && (
                    <div id="details-audio-forensics">
                      <AudioForensicsCard file={uploadedFile} />
                    </div>
                  )}

                  {/* Document Content */}
                  {isFile && (fileCategory === 'document' || fileCategory === 'generic') && (
                    <div id="details-doc-forensics">
                      <DocumentForensicsCard />
                    </div>
                  )}

                  {/* Archive Forensics */}
                  {archiveForensics && (
                    <div id="details-archive-forensics">
                      <ArchiveForensicsCard report={archiveForensics} />
                    </div>
                  )}

                  {/* Windows PE Executable Forensics (Moved to Static Analysis) */}
                  {/* Linux ELF Executable Forensics (Moved to Static Analysis) */}
                  {/* Android APK Forensics (Moved to Static Analysis) */}



                  {/* Email Forensics */}
                  {emailForensics && (
                    <div id="details-email-forensics">
                      <EmailForensicsCard report={emailForensics} />
                    </div>
                  )}

                  {/* PCAP Forensics */}
                  {pcapForensics && (
                    <div id="details-pcap-forensics">
                      <PcapForensicsCard report={pcapForensics} />
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
                            <button onClick={() => handleCopy(fileResult.md5, 'md5')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'md5' ? 'var(--brand-amber)' : '#64748b' }}>
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
                            <button onClick={() => handleCopy(fileResult.sha1, 'sha1')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'sha1' ? 'var(--brand-amber)' : '#64748b' }}>
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
                            <button onClick={() => handleCopy(fileResult?.sha256 || targetClean, 'sha256')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'sha256' ? 'var(--brand-amber)' : '#64748b' }}>
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
                            <button onClick={() => handleCopy(fileResult.extended?.ssdeep || '', 'ssdeep')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'ssdeep' ? 'var(--brand-amber)' : '#64748b' }}>
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
                            <button onClick={() => handleCopy(fileResult.extended?.tlsh || '', 'tlsh')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === 'tlsh' ? 'var(--brand-amber)' : '#64748b' }}>
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
                      {typeof fileResult?.firstSeen === 'number' && fileResult.firstSeen > 0 ? (
                        <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '10px' }}>
                          <div style={{ color: '#94a3b8', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>First Submission</div>
                          <div style={{ color: '#cbd5e1', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
                            {new Date(fileResult.firstSeen * 1000).toUTCString()} ({formatRelativeTime(fileResult.firstSeen)})
                          </div>
                        </div>
                      ) : null}

                      {typeof fileResult?.lastSeen === 'number' && fileResult.lastSeen > 0 ? (
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
                            <span className="material-symbols-outlined" style={{ fontSize: '16px', color: 'var(--brand)' }}>description</span>
                            <span className="font-data-mono" style={{ fontSize: '13px', color: '#f1f5f9' }}>{nm}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Automatic YARA Rules (Moved to Static Analysis) */}
                  {/* PE Headers & Sections (Moved to Static Analysis) */}

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

        {/* ── TAB 3: STATIC ANALYSIS ───────────────────────────────────────────── */}
        {activeTab === 'STATIC_ANALYSIS' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {isFile && (
              <>
                {/* 1. Automatic YARA Rules (Backend/VT) */}
                <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '28px 32px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', marginBottom: '20px' }}>
                    <span className="material-symbols-outlined" style={{ color: '#22d3ee', fontSize: '20px' }}>rule</span>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>
                      Crowdsourced YARA & Signature Inspection
                    </h3>
                  </div>
                  <AutomaticYaraCard 
                    fileResult={fileResult}
                    crowdsourcedYara={fileResult?.extended?.crowdsourcedYara}
                  />
                </div>

                {/* 2. Embedded Local YARA Scanner */}
                <YaraScannerModule />

                {/* 3. PE/ELF/APK Forensics Cards */}
                {peForensics && <PeExecutableCard report={peForensics} />}
                {elfForensics && <ElfExecutableCard report={elfForensics} />}
                {apkForensics && <ApkForensicsCard report={apkForensics} />}
              </>
            )}
            {!isFile && (
              <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '40px', textAlign: 'center' }}>
                <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: '48px', marginBottom: '16px' }}>find_in_page</span>
                <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: '#f1f5f9', marginBottom: '8px' }}>
                  Static Analysis is for Files
                </h3>
                <p style={{ color: '#94a3b8', fontSize: '14px', maxWidth: '400px', margin: '0 auto' }}>
                  This tab provides static malware analysis (YARA, PE Headers, Strings) for uploaded files. Scan a file to see results here.
                </p>
              </div>
            )}
          </div>
        )}

        {/* ── TAB 4: DYNAMIC ANALYSIS ────────────────────────────────────────── */}
        {activeTab === 'DYNAMIC_ANALYSIS' && (
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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', borderBottom: '1px solid #1e293b', paddingBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="material-symbols-outlined" style={{ color: 'var(--brand-ember)', fontSize: '20px' }}>hub</span>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>Entity Relations</h3>
              </div>
            </div>
            <RelationsCard relations={fileResult?.relations || analysisResult?.relations || domainResult?.relations || ipResult?.relations} entityId={fileResult?.id || analysisResult?.id || domainResult?.id || ipResult?.id} />
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
            <TiltWrapper perspective={1200} maxRotation={3} scaleOnHover={1.01}>
              <AiSummary threatData={fileResult || analysisResult || domainResult || ipResult} type={isFile ? 'file' : 'url'} />
            </TiltWrapper>

            {/* 1b. Magic Discrepancy Alert */}
            {isFile && magicDiscrepancy && magicDiscrepancy.hasDiscrepancy && (
              <MagicDiscrepancyBanner discrepancy={magicDiscrepancy} />
            )}
            
            {/* 2. Specialized Media & Document Forensics Engine for Files */}
              {isFile && isImage && imageForensics && (
                <TiltWrapper perspective={1200} maxRotation={2}>
                  <ImageForensicsCard report={imageForensics} />
                </TiltWrapper>
              )}

            {isFile && fileCategory === 'video' && (
              <VideoForensicsCard file={uploadedFile} />
            )}

            {isFile && fileCategory === 'audio' && (
              <AudioForensicsCard file={uploadedFile} />
            )}

            {isFile && (fileCategory === 'document' || fileCategory === 'generic') && (
              <DocumentForensicsCard />
            )}

            {isFile && archiveForensics && (
              <ArchiveForensicsCard report={archiveForensics} />
            )}

            {isFile && peForensics && (
              <PeExecutableCard report={peForensics} />
            )}

            {isFile && elfForensics && (
              <ElfExecutableCard report={elfForensics} />
            )}

            {isFile && apkForensics && (
              <ApkForensicsCard report={apkForensics} />
            )}

            {isFile && emailForensics && (
              <EmailForensicsCard report={emailForensics} />
            )}

            {isFile && pcapForensics && (
              <PcapForensicsCard report={pcapForensics} />
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
        </PageReveal>
      </div>
    </div>
    </>
  );
};
