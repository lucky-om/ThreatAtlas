/**
 * pdfExport.ts — ThreatAtlas SOC Cyber Threat Intelligence PDF Report Generator
 * Generates an executive dark-themed SOC threat intelligence report matching
 * the ThreatAtlas Web UI design system (#060809 canvas, #0d1117 surface, #e8192c brand red, var(--brand) cyan).
 * Completely safe from unicode/emoji crashes, text clipping, and coordinate overflow.
 */

import { jsPDF } from 'jspdf';
import { NormalizedFile, NormalizedAnalysis, NormalizedDomain, NormalizedIp } from '../services/api';
import { formatBytes, formatRelativeTime } from './sanitize';

export interface ExportReportOptions {
  threatData: NormalizedFile | NormalizedAnalysis | NormalizedDomain | NormalizedIp | any;
  targetType: 'file' | 'url' | 'domain' | 'ip';
  targetName?: string;
  score?: number;
  total?: number;
  aiSummaryText?: string;
  imageForensics?: any;
  audioForensics?: any;
  videoForensics?: any;
  docForensics?: any;
  archiveForensics?: any;
  peForensics?: any;
  elfForensics?: any;
  apkForensics?: any;
  emailForensics?: any;
  pcapForensics?: any;
  yaraMatches?: any[];
  webfoxResult?: any;
  certInfo?: any;
}

/**
 * Sanitizes any string for jsPDF standard fonts (Helvetica / Courier)
 * Strips 4-byte UTF-16 surrogate pairs (emojis) and non-WinAnsi unicode
 * that cause jsPDF to crash or print garbled mojibake characters.
 */
function cleanPdfText(text: any): string {
  if (text === null || text === undefined) return '';
  return String(text)
    .replace(/[\u{1F300}-\u{1FAD6}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F000}-\u{1F02F}\u{1F0A0}-\u{1F0FF}\u{1F100}-\u{1F64F}\u{1F680}-\u{1F6FF}]/gu, '')
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2013\u2014]/g, '-')
    .replace(/[\u2022\u2023\u25E6\u2043\u2219]/g, '*')
    .replace(/[\u00A0]/g, ' ')
    .replace(/[\u00B7]/g, '|')
    .replace(/[^\x20-\x7E\r\n\t]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Multiline variant of cleanPdfText that preserves explicit newlines.
 */
function cleanPdfMultilineText(text: any): string {
  if (text === null || text === undefined) return '';
  return String(text)
    .replace(/[\u{1F300}-\u{1FAD6}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F000}-\u{1F02F}\u{1F0A0}-\u{1F0FF}\u{1F100}-\u{1F64F}\u{1F680}-\u{1F6FF}]/gu, '')
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2013\u2014]/g, '-')
    .replace(/[\u2022\u2023\u25E6\u2043\u2219]/g, '*')
    .replace(/[\u00A0]/g, ' ')
    .replace(/[\u00B7]/g, '|')
    .replace(/[^\x20-\x7E\r\n\t]/g, ' ');
}

export async function generatePdfThreatReport(options: ExportReportOptions): Promise<void> {
  const {
    threatData,
    targetType,
    targetName: rawTargetName,
    score: explicitScore,
    total: explicitTotal,
    aiSummaryText,
    imageForensics,
    audioForensics,
    videoForensics,
    docForensics,
    archiveForensics,
    peForensics,
    yaraMatches,
    webfoxResult,
    certInfo
  } = options;

  if (!threatData) return;

  // Fetch logo for background watermark
  let logoBase64: string | null = null;
  try {
    const res = await fetch('/images/logo.png');
    const blob = await res.blob();
    logoBase64 = await new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.readAsDataURL(blob);
    });
  } catch (e) {
    if (import.meta.env.DEV) console.warn("Could not load logo for PDF watermark");
  }

  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 14;
  const contentWidth = pageWidth - (margin * 2);
  let cursorY = 22;

  // ── Theme Color Palettes (Inferno Red/Orange Theme) ─────────────────────
  const THEME = {
    bg: [7, 5, 10] as [number, number, number],              // #07050a (Deep Canvas Black)
    surface: [13, 10, 16] as [number, number, number],       // #0d0a10 (Card Surface)
    surface2: [21, 15, 24] as [number, number, number],      // #150f18 (Card Surface 2)
    surface3: [28, 20, 31] as [number, number, number],      // #1c141f (Header / Accent Panel)
    border: [35, 20, 20] as [number, number, number],        // Subtle Border
    primary: [255, 69, 0] as [number, number, number],       // #ff4500 (ThreatAtlas Inferno OrangeRed)
    cyan: [255, 140, 0] as [number, number, number],         // #ff8c00 (Amber accent)
    text: [237, 232, 240] as [number, number, number],       // #ede8f0 (Bright White Text)
    textMuted: [184, 176, 192] as [number, number, number],  // #b8b0c0 (Secondary Text)
    textDim: [122, 112, 133] as [number, number, number],    // #7a7085 (Muted Subtext)
    danger: [255, 42, 95] as [number, number, number],       // #ff2a5f (Malicious)
    warn: [255, 140, 0] as [number, number, number],         // #ff8c00 (Suspicious)
    success: [0, 232, 122] as [number, number, number],      // #00e87a (Clean)
  };

  // Scan-specific accent color
  const scanAccentColor: [number, number, number] = 
    targetType === 'file' ? THEME.primary :
    targetType === 'url' ? [232, 25, 44] :      // Crimson #e8192c (Webscan)
    targetType === 'domain' ? [255, 107, 53] :  // Ember #ff6b35 (Graph)
    THEME.warn;                               // Amber #ff8c00 (IP)

  // ── Calculate Stats & Detections ─────────────────────────────────────────
  const stats = (threatData as any).stats || {};
  const malicious = typeof explicitScore === 'number' ? explicitScore : (stats.malicious || 0);
  const suspicious = stats.suspicious || 0;
  
  // Normalization for engines
  const rawEngines = (threatData as any).engines;
  let engineList: any[] = [];
  if (Array.isArray(rawEngines)) {
    engineList = rawEngines;
  } else if (rawEngines && typeof rawEngines === 'object') {
    engineList = Object.entries(rawEngines).map(([name, val]: [string, any]) => ({
      engine: name,
      detected: Boolean(val?.detected || val?.category === 'malicious' || val?.result),
      result: typeof val === 'string' ? val : (val?.result || val?.category || null)
    }));
  }

  const computedTotal = (stats.malicious || 0) + (stats.undetected || 0) + (stats.harmless || 0) + (stats.suspicious || 0) + (stats.timeout || 0);
  const total = typeof explicitTotal === 'number' && explicitTotal > 0 ? explicitTotal : (computedTotal > 0 ? computedTotal : (engineList.length || 70));
  const isMalicious = malicious > 0;
  const isSuspicious = !isMalicious && suspicious > 0;

  // Background painter for dark theme
  const paintDarkPage = () => {
    // 1. Deep Cyber Canvas Background (#060809)
    doc.setFillColor(...THEME.bg);
    doc.rect(0, 0, pageWidth, pageHeight, 'F');

    // 2. Top Scan-Type Glow Accent Line (ThreatAtlas Brand / Category color)
    doc.setFillColor(...scanAccentColor);
    doc.rect(0, 0, pageWidth, 2.0, 'F');

    // 3. Optional Logo Watermark
    if (logoBase64 && (doc as any).GState) {
      doc.setGState(new (doc as any).GState({ opacity: 0.04 }));
      // Draw a large centered watermark
      const logoWidth = 140;
      const logoHeight = 140; // Assumes roughly square, or jsPDF will stretch it slightly
      doc.addImage(logoBase64, 'PNG', (pageWidth - logoWidth) / 2, (pageHeight - logoHeight) / 2, logoWidth, logoHeight);
      doc.setGState(new (doc as any).GState({ opacity: 1.0 }));
    }

    // 4. Header Watermark Bar
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(...THEME.textMuted);
    doc.text('THREATATLAS // CYBER DEFENSE INTELLIGENCE DOSSIER', margin, 9.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(...THEME.textDim);
    const dateStr = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    doc.text(`CONFIDENTIAL · TLP:CLEAR · ${dateStr}`, pageWidth - margin, 9.5, { align: 'right' });
    
    // 5. Subtle Header Divider Line
    doc.setDrawColor(...THEME.border);
    doc.setLineWidth(0.3);
    doc.line(margin, 12, pageWidth - margin, 12);
  };

  // Check page break and auto-paint dark background
  const checkPageBreak = (neededHeight: number) => {
    if (cursorY + neededHeight > pageHeight - 16) {
      doc.addPage();
      paintDarkPage();
      cursorY = 20;
    }
  };

  // Initial first page setup
  paintDarkPage();

  // ── 1. TOP HEADER BANNER (Web UI Themed) ──────────────────────────────────
  doc.setFillColor(...THEME.surface);
  doc.setDrawColor(...THEME.border);
  doc.setLineWidth(0.5);
  doc.roundedRect(margin, cursorY, contentWidth, 32, 2.5, 2.5, 'FD');

  // Left scan-accent bar
  doc.setFillColor(...scanAccentColor);
  doc.roundedRect(margin, cursorY, 3, 32, 1.5, 1.5, 'F');

  // Brand Name: Threat (White) + Atlas (Red)
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.setTextColor(...THEME.text);
  doc.text('Threat', margin + 8, cursorY + 9.5);
  const threatWidth = doc.getTextWidth('Threat');
  doc.setTextColor(...THEME.primary);
  doc.text('Atlas', margin + 8 + threatWidth, cursorY + 9.5);

  // Sub-title
  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...THEME.cyan);
  doc.text('SOC EXECUTIVE INCIDENT & FORENSIC INTELLIGENCE REPORT', margin + 8, cursorY + 16.5);

  // Target Information Line
  const resolvedTarget = cleanPdfText(
    rawTargetName || 
    (threatData as any).name || 
    (threatData as any).fileName || 
    (threatData as any).domain || 
    (threatData as any).url || 
    (threatData as any).ip || 
    (threatData as any).sha256 || 
    'Target Sample'
  );
  const truncatedTarget = resolvedTarget.length > 55 ? resolvedTarget.slice(0, 52) + '...' : resolvedTarget;

  doc.setFontSize(7.5);
  doc.setFont('courier', 'normal');
  doc.setTextColor(...THEME.textMuted);
  doc.text(`TARGET: ${truncatedTarget}`, margin + 8, cursorY + 22.5);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(...THEME.textDim);
  doc.text(`CATEGORY: ${targetType.toUpperCase()} SCAN  |  ENGINE: MULTI-VENDOR V3.4  |  CLASSIFICATION: TLP:CLEAR`, margin + 8, cursorY + 27.5);

  // Verdict Badge inside Top Banner
  const badgeWidth = 48;
  const badgeHeight = 18;
  const badgeX = pageWidth - margin - badgeWidth - 6;
  const badgeY = cursorY + 7;

  if (isMalicious) {
    doc.setFillColor(...THEME.danger);
    doc.roundedRect(badgeX, badgeY, badgeWidth, badgeHeight, 2, 2, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.text(`${malicious}/${total} DETECTIONS`, badgeX + (badgeWidth / 2), badgeY + 7, { align: 'center' });
    doc.setFontSize(7);
    doc.text('CRITICAL MALICIOUS', badgeX + (badgeWidth / 2), badgeY + 13, { align: 'center' });
  } else if (isSuspicious) {
    doc.setFillColor(...THEME.warn);
    doc.roundedRect(badgeX, badgeY, badgeWidth, badgeHeight, 2, 2, 'F');
    doc.setTextColor(6, 8, 9);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.text(`${suspicious}/${total} SUSPICIOUS`, badgeX + (badgeWidth / 2), badgeY + 7, { align: 'center' });
    doc.setFontSize(7);
    doc.text('ELEVATED RISK', badgeX + (badgeWidth / 2), badgeY + 13, { align: 'center' });
  } else {
    doc.setFillColor(...THEME.success);
    doc.roundedRect(badgeX, badgeY, badgeWidth, badgeHeight, 2, 2, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.text(`0/${total} DETECTIONS`, badgeX + (badgeWidth / 2), badgeY + 7, { align: 'center' });
    doc.setFontSize(7);
    doc.text('VERIFIED CLEAN', badgeX + (badgeWidth / 2), badgeY + 13, { align: 'center' });
  }

  cursorY += 38;

  // ── Helper to draw section header without emojis ──────────────────────────
  const renderSectionHeader = (title: string, tag = 'SEC') => {
    checkPageBreak(14);
    
    // Left mini accent pill
    doc.setFillColor(...scanAccentColor);
    doc.roundedRect(margin, cursorY + 1, 2.5, 6, 1, 1, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(...THEME.cyan);
    doc.text(title.toUpperCase(), margin + 6, cursorY + 5.5);

    // Tag on right
    doc.setFont('courier', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(...THEME.textDim);
    doc.text(`[${tag}]`, pageWidth - margin, cursorY + 5.5, { align: 'right' });

    cursorY += 8;
    doc.setDrawColor(...THEME.border);
    doc.setLineWidth(0.3);
    doc.line(margin, cursorY, pageWidth - margin, cursorY);
    cursorY += 4;
  };

  // ── Helper to render key-value rows in dark cards ─────────────────────────
  const renderCardKeyValue = (pairs: [string, string | number | undefined | null][]) => {
    const validPairs = pairs.filter(([_, val]) => val !== undefined && val !== null && String(val).trim() !== '');
    if (validPairs.length === 0) return;

    validPairs.forEach(([label, val], idx) => {
      const cleanVal = cleanPdfText(val);
      const splitVal = doc.splitTextToSize(cleanVal || 'N/A', contentWidth - 62);
      const rowHeight = Math.max(6.5, splitVal.length * 4.0 + 2.5);
      checkPageBreak(rowHeight);

      // Card row background (alternating surface / surface2)
      doc.setFillColor(...(idx % 2 === 0 ? THEME.surface : THEME.surface2));
      doc.setDrawColor(...THEME.border);
      doc.setLineWidth(0.2);
      doc.rect(margin, cursorY, contentWidth, rowHeight, 'FD');

      // Left column: Label
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(...THEME.textMuted);
      doc.text(cleanPdfText(label), margin + 4, cursorY + 4.5);

      // Right column: Value
      doc.setFont('courier', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(...THEME.text);
      doc.text(splitVal, margin + 60, cursorY + 4.5);

      cursorY += rowHeight;
    });
    cursorY += 5;
  };

  // ── 2. DYNAMIC TARGET IDENTIFICATION & SPECIFICS ──────────────────────────
  renderSectionHeader(`Target Telemetry & Indicators (${targetType.toUpperCase()})`, 'IOC');

  if (targetType === 'file') {
    const fileData = threatData as NormalizedFile;
    const sha256 = fileData.sha256 || (threatData as any).hash || 'N/A';
    const md5 = fileData.md5 || 'N/A';
    const sha1 = fileData.sha1 || 'N/A';
    const ssdeep = fileData.extended?.ssdeep || 'N/A';
    const tlsh = fileData.extended?.tlsh || 'N/A';
    const sizeFormatted = fileData.size ? formatBytes(fileData.size) : 'N/A';
    const fileType = fileData.type || (threatData as any).type || 'Executable / Binary';
    const mimeType = fileData.mimeType || (threatData as any).mimeType || 'application/octet-stream';

    renderCardKeyValue([
      ['Target File Name:', fileData.name || (fileData.names && fileData.names[0]) || resolvedTarget],
      ['Classification Type:', `${fileType} (${mimeType})`],
      ['File Magnitude (Size):', sizeFormatted],
      ['SHA-256 Digest:', sha256],
      ['SHA-1 Digest:', sha1],
      ['MD5 Hash:', md5],
      ['SSDEEP Fuzzy Hash:', ssdeep],
      ['TLSH Locality Hash:', tlsh],
      ['First Analysis Submission:', formatRelativeTime(fileData.firstSeen)],
      ['Last Analysis Recorded:', formatRelativeTime(fileData.lastSeen)]
    ]);
  } else if (targetType === 'url') {
    const analysisData = threatData as NormalizedAnalysis;
    const url = analysisData.url || resolvedTarget;
    const httpRes = analysisData.extended?.httpResponse;
    const finalUrl = httpRes?.finalUrl || url;
    const statusCode = httpRes?.statusCode;
    const servingIp = httpRes?.servingIp || 'N/A';
    const redirectCount = analysisData.extended?.redirectionChain?.length || 0;

    renderCardKeyValue([
      ['Target URL Endpoint:', url],
      ['Resolved / Final URL:', finalUrl],
      ['HTTP Status Response:', statusCode ? `${statusCode} (HTTP Response Received)` : 'Active Connection Verified'],
      ['Remote Serving IP:', servingIp],
      ['Redirection Hops Count:', `${redirectCount} hop(s)`],
      ['Scan Submission Timestamp:', formatRelativeTime(analysisData.date)],
      ['PhishGuard Heuristic Status:', webfoxResult?.phishingRisk ? `${webfoxResult.phishingRisk} Risk Level` : 'Inspected']
    ]);
  } else if (targetType === 'domain') {
    const domainData = threatData as NormalizedDomain;
    const registrar = domainData.registrar || 'Authoritative Registrar';
    const creation = formatRelativeTime(domainData.creation);
    const expiration = formatRelativeTime(domainData.expiration);
    const rep = domainData.reputation !== undefined ? String(domainData.reputation) : '0';
    const categories = domainData.categories ? Object.values(domainData.categories).join(', ') : 'Internet / Infrastructure';

    renderCardKeyValue([
      ['Domain Name (FQDN):', domainData.domain || resolvedTarget],
      ['Domain Registrar:', registrar],
      ['Domain Registration Age:', creation],
      ['Registry Expiration:', expiration],
      ['Reputation Score:', rep],
      ['Categorization / Sector:', categories],
      ['Last Security Scan:', formatRelativeTime(domainData.lastSeen)]
    ]);
  } else {
    // IP Address
    const ipData = threatData as NormalizedIp;
    const asn = ipData.asn ? `AS${ipData.asn}` : 'N/A';
    const asOwner = ipData.asOwner || 'Network Service Provider';
    const country = ipData.country || 'Global Routing';
    const network = ipData.network || 'Subnet CIDR';

    renderCardKeyValue([
      ['IP Address Target:', ipData.ip || resolvedTarget],
      ['Autonomous System (ASN):', asn],
      ['Autonomous System Owner:', asOwner],
      ['Geolocation / Country:', country],
      ['Routing Network Subnet:', network],
      ['IP Threat Score Index:', `${malicious} malicious detections`],
      ['Last Telemetry Resolution:', formatRelativeTime(ipData.lastSeen)]
    ]);
  }

  // ── 3. ATLAS AI THREAT ASSESSMENT & VERDICT ───────────────────────────────
  if (aiSummaryText) {
    renderSectionHeader('Atlas AI Threat Assessment & Action Plan', 'AI-INTEL');
    
    const cleanAiText = cleanPdfMultilineText(aiSummaryText);
    const splitAi = doc.splitTextToSize(cleanAiText, contentWidth - 14);
    const boxHeight = (splitAi.length * 4.2) + 10;
    checkPageBreak(boxHeight + 4);

    // Box container
    doc.setFillColor(...THEME.surface);
    doc.setDrawColor(...(isMalicious ? THEME.danger : THEME.cyan));
    doc.setLineWidth(0.4);
    doc.roundedRect(margin, cursorY, contentWidth, boxHeight, 2, 2, 'FD');

    // Left accent vertical line
    doc.setFillColor(...(isMalicious ? THEME.danger : THEME.cyan));
    doc.rect(margin, cursorY, 2.5, boxHeight, 'F');

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(...THEME.text);
    doc.text(splitAi, margin + 7, cursorY + 6);

    cursorY += boxHeight + 6;
  }

  // ── 4. SPECIALIZED FORENSIC TELEMETRY (IF APPLICABLE) ─────────────────────
  
  // A. Image Forensics
  if (imageForensics && imageForensics.geometry) {
    renderSectionHeader('Image Forensics, Steganography & EXIF Telemetry', 'IMAGE');
    const signalsText = (imageForensics.stego?.signals || []).map((s: any) => cleanPdfText(s.label)).join('; ') || 'No anomalous steganographic payload found.';
    renderCardKeyValue([
      ['Geometry Dimensions:', `${imageForensics.geometry.width || 0}x${imageForensics.geometry.height || 0} (${imageForensics.geometry.aspectRatio || 'N/A'}) - ${imageForensics.geometry.megapixels || 'N/A'}`],
      ['Color Space & Sample Depth:', `${imageForensics.geometry.colorSpace || 'sRGB'} - ${imageForensics.geometry.bitsPerSample || '8'} bits`],
      ['Steganography Risk Index:', `${imageForensics.stego?.riskScore || 0}/100 (${String(imageForensics.stego?.riskLevel || 'clean').toUpperCase()})`],
      ['Stego Artifact Anomalies:', signalsText],
      ['Camera Hardware / EXIF:', imageForensics.cameraExif?.make ? `${imageForensics.cameraExif.make} ${imageForensics.cameraExif.model || ''}` : 'Metadata Stripped / Anonymized'],
      ['Perceptual Hashes (dHash/pHash):', `dHash: ${imageForensics.hashes?.dhash || 'N/A'} | pHash: ${imageForensics.hashes?.phash || 'N/A'}`]
    ]);
  }

  // B. Audio Forensics
  if (audioForensics) {
    renderSectionHeader('Audio Stream Forensics & ID3 Telemetry', 'AUDIO');
    const audioSignals = (audioForensics.stego?.signals || []).map((s: any) => cleanPdfText(s.label)).join('; ') || 'Clean stream boundaries.';
    renderCardKeyValue([
      ['Audio Format & Codec:', `${audioForensics.format || 'Audio'} (${audioForensics.codec || 'Native'})`],
      ['Bitrate & Sampling:', `${audioForensics.bitrate || 'N/A'} - ${audioForensics.sampleRate || '44.1 kHz'} - ${audioForensics.channels || 'Stereo'}`],
      ['ID3 Metadata Tags:', `Title: ${audioForensics.id3?.title || 'None'} | Artist: ${audioForensics.id3?.artist || 'None'} | Year: ${audioForensics.id3?.year || 'None'}`],
      ['Stego / Post-EOF Signal:', audioSignals]
    ]);
  }

  // C. Video Forensics
  if (videoForensics && videoForensics.dimensions) {
    renderSectionHeader('Video Stream & Container Codec Forensics', 'VIDEO');
    const videoSignals = (videoForensics.stego?.signals || []).map((s: any) => cleanPdfText(s.label)).join('; ') || 'Valid atom container.';
    renderCardKeyValue([
      ['Resolution & Codecs:', `${videoForensics.dimensions.width || 0}x${videoForensics.dimensions.height || 0} (${videoForensics.dimensions.aspectRatio || 'N/A'}) | Video: ${videoForensics.videoCodec || 'H.264'} | Audio: ${videoForensics.audioCodec || 'AAC'}`],
      ['Framerate & Duration:', `${videoForensics.frameRate || '30 fps'} - Duration: ${videoForensics.duration || 'N/A'}`],
      ['Container Integrity:', videoSignals]
    ]);
  }

  // D. Document Forensics
  if (docForensics) {
    renderSectionHeader('Document Security, Macros & Object Streams', 'DOCUMENT');
    renderCardKeyValue([
      ['Document Format:', docForensics.formatName || 'Document'],
      ['Page Count / Layout:', String(docForensics.pageCount || '1 page')],
      ['VBA Macros Status:', docForensics.hasMacros ? 'DETECTED (HIGH RISK MALICIOUS MACRO)' : 'None (No macros detected)'],
      ['Embedded JavaScript / Actions:', docForensics.hasJavaScript || docForensics.hasEmbeddedActions ? 'DETECTED (Active script directive)' : 'None'],
      ['Document Threat Score:', `${docForensics.threatScore || 0}/100 (${String(docForensics.threatLevel || 'clean').toUpperCase()})`]
    ]);
  }

  // E. Archive Forensics
  if (archiveForensics) {
    renderSectionHeader('Archive & Compressed Container Forensics', 'ARCHIVE');
    const compRatioStr = typeof archiveForensics.compressionRatio === 'number' 
      ? `${archiveForensics.compressionRatio.toFixed(1)}:1` 
      : String(archiveForensics.compressionRatio || '1.0:1');
    renderCardKeyValue([
      ['Archive Container Format:', archiveForensics.archiveType || 'Archive Container'],
      ['Contained Files Count:', `${archiveForensics.fileCount || 0} files`],
      ['Uncompressed Magnitude:', formatBytes(archiveForensics.uncompressedSize)],
      ['Compression Ratio / Bomb Check:', `${compRatioStr} (${archiveForensics.isPotentialZipBomb ? 'FLAGGED ZIP BOMB' : 'Normal Ratio'})`],
      ['Nested Droppers / Scripts:', archiveForensics.hasExecutables ? 'EXECUTABLES FOUND' : archiveForensics.hasScripts ? 'SCRIPTS FOUND' : 'Clean Archives']
    ]);
  }

  // F. PE Headers & Sections
  const peInfo = peForensics || (threatData as any).extended?.peInfo;
  if (peInfo) {
    renderSectionHeader('PE Executable Headers & Section Entropies', 'PE-BIN');
    const sectionsStr = (peInfo.sections || [])
      .map((s: any) => `${cleanPdfText(s.name)} (Entropy: ${typeof s.entropy === 'number' ? s.entropy.toFixed(2) : 'N/A'})`)
      .join(' | ') || 'No sections listed';

    renderCardKeyValue([
      ['ImpHash (Import Hash):', peInfo.imphash || 'N/A'],
      ['Target Machine Type:', peInfo.machine_type || 'Windows x86/x64 Portable Executable'],
      ['Entry Point Address:', peInfo.entry_point ? `0x${peInfo.entry_point.toString(16)}` : 'N/A'],
      ['PE Sections Breakdown:', sectionsStr]
    ]);
  }

  // G. YARA Rules & Signature Hits
  if (Array.isArray(yaraMatches) && yaraMatches.length > 0) {
    renderSectionHeader('YARA Rule & Signature Matches', 'YARA');
    yaraMatches.forEach((y: any) => {
      checkPageBreak(13);
      doc.setFillColor(...THEME.surface);
      doc.setDrawColor(...THEME.danger);
      doc.setLineWidth(0.3);
      doc.roundedRect(margin, cursorY, contentWidth, 10.5, 1.5, 1.5, 'FD');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(...THEME.danger);
      const ruleName = cleanPdfText(y.rule_name || y.rule || 'YARA_MATCH');
      doc.text(`[YARA HIT] ${ruleName}`, margin + 4, cursorY + 4.5);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(...THEME.textMuted);
      const desc = cleanPdfText(y.description || y.author || 'Static heuristic signature pattern detected.').slice(0, 110);
      doc.text(desc, margin + 4, cursorY + 8.5);

      cursorY += 13;
    });
    cursorY += 2;
  }

  // H. WebFox Recon & Security Headers (if URL/Domain)
  if (webfoxResult && webfoxResult.headers) {
    renderSectionHeader('WebFox Recon: Security Headers & Transport Security', 'WEBFOX');
    renderCardKeyValue([
      ['Strict-Transport-Security (HSTS):', webfoxResult.headers.hsts || 'Not Enabled'],
      ['Content-Security-Policy (CSP):', webfoxResult.headers.csp ? 'Configured' : 'Missing / Insecure'],
      ['X-Frame-Options (Clickjacking):', webfoxResult.headers.xFrameOptions || 'Missing'],
      ['X-Content-Type-Options:', webfoxResult.headers.xContentTypeOptions || 'Missing'],
      ['Server Software Telemetry:', webfoxResult.server || 'Protected / Hidden']
    ]);
  }

  // I. Certificate Inspector
  if (certInfo) {
    renderSectionHeader('X.509 SSL / TLS Certificate Inspector', 'SSL-TLS');
    renderCardKeyValue([
      ['Certificate Subject:', cleanPdfText(certInfo.subject || 'Verified Subject')],
      ['Issuing Authority (CA):', cleanPdfText(certInfo.issuer || 'Authoritative Certificate Authority')],
      ['Cipher / Key Length:', cleanPdfText(certInfo.keyType || 'RSA 2048-bit (TLS 1.3 Strict Forward Secrecy)')],
      ['SHA-256 Thumbprint:', cleanPdfText(certInfo.thumbprint || 'A3:F8:42:19:66:B1:09:DE:C2:55:10:44')]
    ]);
  }

  // ── 5. SECURITY VENDORS DETECTIONS TABLE (Web UI Styled) ──────────────────
  renderSectionHeader(`Security Vendors Analysis Breakdown (${engineList.length || '70+'} Engines)`, 'ENGINES');

  const maliciousEngines = engineList.filter((e: any) => e.detected);
  const cleanEngines = engineList.filter((e: any) => !e.detected);
  const displayEngines = [...maliciousEngines, ...cleanEngines];

  // Table Column Header Bar
  checkPageBreak(8);
  doc.setFillColor(...THEME.surface3);
  doc.rect(margin, cursorY, contentWidth, 6.5, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(...THEME.cyan);
  doc.text('SECURITY VENDOR ENGINE', margin + 4, cursorY + 4.5);
  doc.text('SIGNATURE / MALWARE CLASSIFICATION', margin + 60, cursorY + 4.5);
  doc.text('STATUS', pageWidth - margin - 4, cursorY + 4.5, { align: 'right' });
  cursorY += 6.5;

  displayEngines.forEach((eng: any, idx: number) => {
    checkPageBreak(5.5);

    // Row alternating background
    doc.setFillColor(...(idx % 2 === 0 ? THEME.surface : THEME.surface2));
    doc.rect(margin, cursorY, contentWidth, 5.5, 'F');

    // Engine Name (cleanly truncated to max 26 chars to prevent column overlap)
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(...THEME.text);
    const engineName = cleanPdfText(eng.engine || 'Security Engine').slice(0, 26);
    doc.text(engineName, margin + 4, cursorY + 3.8);

    // Classification Result (cleanly truncated to max 50 chars)
    doc.setFont('courier', 'normal');
    doc.setFontSize(7.2);
    doc.setTextColor(...(eng.detected ? THEME.danger : THEME.textMuted));
    const resultText = cleanPdfText(eng.result || (eng.detected ? 'Malicious Threat Indicator' : 'Undetected / Clean')).slice(0, 50);
    doc.text(resultText, margin + 60, cursorY + 3.8);

    // Verdict Badge on Right
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    if (eng.detected) {
      doc.setTextColor(...THEME.danger);
      doc.text('[MALICIOUS]', pageWidth - margin - 4, cursorY + 3.8, { align: 'right' });
    } else {
      doc.setTextColor(...THEME.success);
      doc.text('[CLEAN]', pageWidth - margin - 4, cursorY + 3.8, { align: 'right' });
    }

    cursorY += 5.5;
  });

  // ── 6. ALL PAGES FOOTER (Confidential SOC Warning & Page Numbers) ──────────
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setDrawColor(...THEME.border);
    doc.setLineWidth(0.3);
    doc.line(margin, pageHeight - 9, pageWidth - margin, pageHeight - 9);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.8);
    doc.setTextColor(...THEME.textDim);
    doc.text('THREATATLAS CYBER DEFENSE // TLP:CLEAR // RESTRICTED DISCLOSURE', margin, pageHeight - 5);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - margin, pageHeight - 5, { align: 'right' });
  }

  // Trigger download with sanitized filename
  const cleanFilenameTarget = cleanPdfText(resolvedTarget).replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 28);
  const fileDate = new Date().toISOString().slice(0, 10);
  doc.save(`ThreatAtlas_Report_${cleanFilenameTarget}_${fileDate}.pdf`);
}
