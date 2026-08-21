/**
 * pdfExport.ts — Executive PDF Threat Report Compiler
 * Generates high-fidelity, printable SOC incident reports with complete
 * multi-engine detections, YARA matches, forensics intelligence, and AI analysis.
 */

import { jsPDF } from 'jspdf';
import { NormalizedFile, NormalizedAnalysis, NormalizedDomain, NormalizedIp } from '../services/api';
import { formatBytes } from './sanitize';

export interface ExportReportOptions {
  threatData: NormalizedFile | NormalizedAnalysis | NormalizedDomain | NormalizedIp;
  targetType: 'file' | 'url' | 'domain' | 'ip';
  aiSummaryText?: string;
  imageForensics?: any;
  docForensics?: any;
  yaraMatches?: any[];
}

export function generatePdfThreatReport(options: ExportReportOptions): void {
  const { threatData, targetType, aiSummaryText, imageForensics, docForensics, yaraMatches } = options;
  
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  let cursorY = 20;

  const checkPageBreak = (neededHeight: number) => {
    if (cursorY + neededHeight > pageHeight - 20) {
      doc.addPage();
      cursorY = 20;
      renderHeaderWatermark();
    }
  };

  const renderHeaderWatermark = () => {
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text('ThreatAtlas — Unified Cybersecurity Intelligence Report', 14, 10);
    doc.text(`CONFIDENTIAL · Generated ${new Date().toUTCString()}`, pageWidth - 14, 10, { align: 'right' });
    doc.setDrawColor(30, 41, 59);
    doc.line(14, 12, pageWidth - 14, 12);
  };

  renderHeaderWatermark();

  // ── 1. REPORT BANNER & CLASSIFICATION ──────────────────────────────────────
  doc.setFillColor(15, 23, 42); // #0f172a
  doc.roundedRect(14, cursorY, pageWidth - 28, 28, 3, 3, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(56, 189, 248); // #38bdf8
  doc.text('THREATATLAS', 20, cursorY + 11);

  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184);
  doc.setFont('helvetica', 'normal');
  doc.text('Executive Threat Intelligence & Forensic Analysis', 20, cursorY + 18);
  doc.text(`Target Type: ${targetType.toUpperCase()} | Engine: Multi-Engine Pipeline v3.2`, 20, cursorY + 23);

  // Score Badge in Banner
  const stats = (threatData as any).stats || {};
  const malicious = stats.malicious || 0;
  const total = (stats.malicious || 0) + (stats.undetected || 0) + (stats.harmless || 0) + (stats.suspicious || 0) || 70;
  const isMalicious = malicious > 0;

  if (isMalicious) {
    doc.setFillColor(255, 42, 95); // #ff2a5f
    doc.roundedRect(pageWidth - 65, cursorY + 6, 45, 16, 2, 2, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.text(`${malicious} / ${total} THREATS`, pageWidth - 42.5, cursorY + 16.5, { align: 'center' });
  } else {
    doc.setFillColor(0, 255, 163); // #00ffa3
    doc.roundedRect(pageWidth - 60, cursorY + 6, 40, 16, 2, 2, 'F');
    doc.setTextColor(15, 23, 42);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.text('CLEAN (0/70)', pageWidth - 40, cursorY + 16.5, { align: 'center' });
  }

  cursorY += 34;

  // ── 2. TARGET IDENTIFIERS & METADATA ───────────────────────────────────────
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(241, 245, 249);
  doc.text('Target Properties & Hashes', 14, cursorY);
  cursorY += 6;

  const fileData = threatData as NormalizedFile;
  const targetName = fileData.name || (threatData as any).fileName || (threatData as any).domain || (threatData as any).url || (threatData as any).ip || fileData.sha256 || 'Unknown';
  const sha256 = fileData.sha256 || (threatData as any).hash || 'N/A';
  const md5 = fileData.md5 || 'N/A';
  const sizeFormatted = fileData.size ? formatBytes(fileData.size) : 'N/A';
  const fileType = fileData.type || (threatData as any).type || targetType.toUpperCase();

  const props = [
    ['Entity Name / Identifier:', targetName],
    ['Target Category:', targetType.toUpperCase()],
    ['SHA-256:', sha256],
    ['MD5 Hash:', md5],
    ['File Size / Magnitude:', sizeFormatted],
    ['Identified Type:', fileType]
  ];

  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  
  props.forEach(([label, val]) => {
    checkPageBreak(7);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(71, 85, 105);
    doc.text(label, 16, cursorY);

    doc.setFont('courier', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    const splitVal = doc.splitTextToSize(val, pageWidth - 80);
    doc.text(splitVal, 75, cursorY);
    cursorY += 5.5;
  });

  cursorY += 4;

  // ── 3. AI EXECUTIVE SUMMARY ───────────────────────────────────────────────
  if (aiSummaryText) {
    checkPageBreak(30);
    doc.setFillColor(240, 249, 255);
    doc.setDrawColor(186, 230, 253);
    doc.roundedRect(14, cursorY, pageWidth - 28, 26, 2, 2, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(3, 105, 161);
    doc.text('🤖 AI Threat Intelligence Executive Summary', 18, cursorY + 6);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    const splitAi = doc.splitTextToSize(aiSummaryText.slice(0, 320) + (aiSummaryText.length > 320 ? '...' : ''), pageWidth - 36);
    doc.text(splitAi, 18, cursorY + 12);

    cursorY += 32;
  }

  // ── 4. SPECIALIZED FORENSIC FINDINGS ──────────────────────────────────────
  if (imageForensics) {
    checkPageBreak(35);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('🖼️ Image Forensics & Steganography Analysis', 14, cursorY);
    cursorY += 6;

    const imgProps = [
      ['Resolution & Aspect Ratio:', `${imageForensics.geometry.width}x${imageForensics.geometry.height} (${imageForensics.geometry.aspectRatio})`],
      ['Megapixels & Color Depth:', `${imageForensics.geometry.megapixels} · ${imageForensics.geometry.colorSpace}`],
      ['Steganography Risk Score:', `${imageForensics.stego.riskScore}/100 (${imageForensics.stego.riskLevel.toUpperCase()})`],
      ['Camera Telemetry:', imageForensics.cameraExif.make ? `${imageForensics.cameraExif.make} ${imageForensics.cameraExif.model || ''}` : 'Stripped / Anonymized'],
      ['Perceptual dHash:', imageForensics.hashes.dhash || 'N/A']
    ];

    imgProps.forEach(([l, v]) => {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(71, 85, 105);
      doc.text(l, 16, cursorY);
      doc.setFont('courier', 'normal');
      doc.setTextColor(15, 23, 42);
      doc.text(v, 75, cursorY);
      cursorY += 5;
    });
    cursorY += 4;
  }

  if (docForensics) {
    checkPageBreak(35);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('📄 Document Security & Macro Inspection', 14, cursorY);
    cursorY += 6;

    const dProps = [
      ['Document Format:', docForensics.formatName],
      ['Page Count:', String(docForensics.pageCount || 'N/A')],
      ['VBA Macro Presence:', docForensics.hasMacros ? 'DETECTED (HIGH RISK)' : 'None (Clean)'],
      ['Embedded JavaScript / Actions:', docForensics.hasJavaScript || docForensics.hasEmbeddedActions ? 'DETECTED (ACTIVE)' : 'None'],
      ['Document Risk Level:', `${docForensics.threatScore}/100 (${docForensics.threatLevel.toUpperCase()})`]
    ];

    dProps.forEach(([l, v]) => {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(71, 85, 105);
      doc.text(l, 16, cursorY);
      doc.setFont('courier', 'normal');
      doc.setTextColor(15, 23, 42);
      doc.text(v, 75, cursorY);
      cursorY += 5;
    });
    cursorY += 4;
  }

  // ── YARA Rules & Signatures ───────────────────────────────────────────────
  if (Array.isArray(yaraMatches) && yaraMatches.length > 0) {
    checkPageBreak(30);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('🔬 YARA Rules & Signature Hits', 14, cursorY);
    cursorY += 6;

    yaraMatches.slice(0, 5).forEach((y: any) => {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(255, 42, 95);
      doc.text(`• ${y.rule_name || y.rule || 'YARA_MATCH'}`, 16, cursorY);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      doc.text(String(y.description || y.author || 'Custom heuristic signature match').slice(0, 70), 75, cursorY);
      cursorY += 5;
    });
    cursorY += 4;
  }

  // ── 5. SECURITY VENDOR DETECTIONS TABLE ────────────────────────────────────
  checkPageBreak(40);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('Security Vendors Analysis Breakdown', 14, cursorY);
  cursorY += 6;

  const engines = (threatData as any).engines || [];
  const maliciousEngines = engines.filter((e: any) => e.detected);
  const cleanEngines = engines.filter((e: any) => !e.detected);

  // Table Header
  doc.setFillColor(30, 41, 59);
  doc.rect(14, cursorY, pageWidth - 28, 7, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(255, 255, 255);
  doc.text('Security Vendor Engine', 18, cursorY + 5);
  doc.text('Result / Malware Classification', 100, cursorY + 5);
  doc.text('Status', pageWidth - 20, cursorY + 5, { align: 'right' });
  cursorY += 7;

  // Render Detections (Malicious first, then clean)
  const displayEngines = [...maliciousEngines, ...cleanEngines.slice(0, Math.max(10, 25 - maliciousEngines.length))];

  displayEngines.forEach((eng: any, idx: number) => {
    checkPageBreak(6);
    doc.setFillColor(idx % 2 === 0 ? 255 : 248, idx % 2 === 0 ? 255 : 250, idx % 2 === 0 ? 255 : 252);
    doc.rect(14, cursorY, pageWidth - 28, 6, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(30, 41, 59);
    doc.text(eng.engine, 18, cursorY + 4.2);

    doc.setFont('courier', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(eng.detected ? 255 : 100, eng.detected ? 42 : 116, eng.detected ? 95 : 139);
    doc.text(eng.result || (eng.detected ? 'Malicious' : 'Undetected'), 100, cursorY + 4.2);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(eng.detected ? 255 : 0, eng.detected ? 42 : 163, eng.detected ? 95 : 100);
    doc.text(eng.detected ? 'MALICIOUS' : 'CLEAN', pageWidth - 20, cursorY + 4.2, { align: 'right' });

    cursorY += 6;
  });

  // Footer on final page
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184);
    doc.text(`ThreatAtlas Cyber Intelligence Platform · Page ${i} of ${totalPages}`, pageWidth / 2, pageHeight - 8, { align: 'center' });
  }

  // Trigger download
  const cleanTargetName = targetName.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 30);
  doc.save(`ThreatAtlas_Report_${cleanTargetName}_${new Date().toISOString().slice(0, 10)}.pdf`);
}
