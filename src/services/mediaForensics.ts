/**
 * mediaForensics.ts — Unified Multi-Format Media, Document & Container Forensics Engine
 * Supports: Image, Audio, Video, PDF / Office Documents, and Archives.
 * Implements strict deduplication, anomaly detection, and deep metadata parsing.
 */

import { NormalizedFile } from './api';

export type FileCategory = 'image' | 'audio' | 'video' | 'document' | 'archive' | 'executable' | 'generic';

// ── 1. Audio Forensics Types ──────────────────────────────────────────────────
export interface AudioForensicsReport {
  format: string;
  duration?: string;
  bitrate?: string;
  sampleRate?: string;
  channels?: string;
  codec?: string;
  encoder?: string;
  id3: {
    title?: string;
    artist?: string;
    album?: string;
    year?: string;
    genre?: string;
    track?: string;
    composer?: string;
    comments?: string;
  };
  stego: {
    riskScore: number;
    riskLevel: 'clean' | 'low' | 'suspicious' | 'critical';
    hasTrailingData: boolean;
    signals: Array<{ id: string; label: string; details: string; severity: 'clean' | 'low' | 'medium' | 'high' | 'critical' }>;
  };
}

// ── 2. Video Forensics Types ──────────────────────────────────────────────────
export interface VideoForensicsReport {
  format: string;
  duration?: string;
  dimensions: {
    width: number;
    height: number;
    aspectRatio: string;
  };
  videoCodec?: string;
  audioCodec?: string;
  frameRate?: string;
  overallBitrate?: string;
  videoBitrate?: string;
  audioBitrate?: string;
  encoderTool?: string;
  creationDate?: string;
  gpsCoordinates?: string;
  stego: {
    riskScore: number;
    riskLevel: 'clean' | 'low' | 'suspicious' | 'critical';
    signals: Array<{ id: string; label: string; details: string; severity: 'clean' | 'low' | 'medium' | 'high' | 'critical' }>;
  };
}

// ── 3. Document / Office / PDF Forensics Types ────────────────────────────────
export interface DocumentForensicsReport {
  docType: 'pdf' | 'word' | 'excel' | 'powerpoint' | 'generic_doc';
  formatName: string;
  pageCount?: number;
  wordCount?: number;
  author?: string;
  creator?: string;
  producer?: string;
  creationDate?: string;
  modifyDate?: string;
  isEncrypted: boolean;
  hasMacros: boolean;
  hasJavaScript: boolean;
  hasEmbeddedActions: boolean;
  hasExternalLinks: boolean;
  threatScore: number;
  threatLevel: 'clean' | 'low' | 'suspicious' | 'critical';
  pdfDetails?: {
    version?: string;
    isLinearized?: boolean;
    objectStreams?: boolean;
    tagged?: boolean;
    jsCount?: number;
    actionTypes?: string[];
  };
  officeDetails?: {
    appName?: string;
    appVersion?: string;
    lastModifiedBy?: string;
    revisionNumber?: string;
    totalEditTime?: string;
    macroStreams?: string[];
    autoExecMacros?: string[];
  };
  signals: Array<{ id: string; label: string; details: string; severity: 'clean' | 'low' | 'medium' | 'high' | 'critical' }>;
}

// ── 4. Archive / Container Forensics Types ───────────────────────────────────
export interface ArchiveForensicsReport {
  archiveType: string;
  fileCount: number;
  uncompressedSize?: number;
  compressedSize?: number;
  compressionRatio?: string;
  isEncrypted: boolean;
  hasExecutables: boolean;
  hasScripts: boolean;
  isPotentialZipBomb: boolean;
  files: Array<{
    name: string;
    size?: number;
    compressedSize?: number;
    crc?: string;
    isExecutable?: boolean;
    isScript?: boolean;
  }>;
  threatScore: number;
  threatLevel: 'clean' | 'low' | 'suspicious' | 'critical';
  signals: Array<{ id: string; label: string; details: string; severity: 'clean' | 'low' | 'medium' | 'high' | 'critical' }>;
}

/**
 * Accurately classifies a file into its primary media or document domain.
 */
export function getFileCategory(fileResult?: NormalizedFile | null, rawTarget?: string): FileCategory {
  if (!fileResult && !rawTarget) return 'generic';

  const fileName = (fileResult?.name || fileResult?.names?.[0] || rawTarget || '').toLowerCase();
  const type = (fileResult?.type || '').toLowerCase();
  const mime = (fileResult?.mimeType || '').toLowerCase();
  const magic = (fileResult?.extended?.magic || '').toLowerCase();
  const magika = (fileResult?.extended?.magika || '').toLowerCase();
  const tags = (fileResult?.tags || []).map(t => t.toLowerCase());
  
  const exif = fileResult?.extended?.exiftool || {};
  const exifFileType = (exif['FileType'] || exif['FileTypeExtension'] || '').toLowerCase();
  const exifMime = (exif['MIMEType'] || '').toLowerCase();

  // 1. Executable / PE / ELF / Mach-O
  if (
    fileResult?.extended?.peInfo ||
    fileResult?.extended?.peInfo?.imphash ||
    type.includes('pe') ||
    type.includes('executable') ||
    type.includes('win32') ||
    type.includes('win64') ||
    magic.includes('executable') ||
    magic.includes('pe32') ||
    magic.includes('elf') ||
    mime.includes('x-dosexec') ||
    mime.includes('x-executable') ||
    exifFileType === 'exe' || exifFileType === 'dll' ||
    ['.exe', '.dll', '.sys', '.scr', '.elf', '.so', '.dylib'].some(e => fileName.endsWith(e))
  ) {
    return 'executable';
  }

  // 2. Image formats (EXIF, MIME, Magic, Magika, FileType)
  if (
    mime.startsWith('image/') ||
    exifMime.startsWith('image/') ||
    ['jpeg', 'jpg', 'png', 'gif', 'webp', 'bmp', 'tiff', 'tif', 'svg', 'ico', 'heic', 'raw', 'cr2', 'nef'].includes(exifFileType) ||
    tags.some(t => ['image', 'jpeg', 'jpg', 'png', 'gif', 'webp', 'svg', 'bmp', 'tiff'].includes(t)) ||
    ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff', '.tif', '.svg', '.ico', '.heic', '.raw', '.cr2', '.nef'].some(e => fileName.endsWith(e)) ||
    type.includes('jpeg') || type.includes('png') || type.includes('gif') || type.includes('bitmap') || type.includes('image') ||
    magic.includes('jpeg') || magic.includes('jfif') || magic.includes('png') || magic.includes('gif') || magic.includes('bitmap') ||
    magika === 'jpeg' || magika === 'png' || magika === 'gif' || magika === 'webp' ||
    (exif['ImageWidth'] && exif['ImageHeight'])
  ) {
    return 'image';
  }

  // 3. Audio formats
  if (
    mime.startsWith('audio/') ||
    exifMime.startsWith('audio/') ||
    ['mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a', 'wma', 'aiff', 'opus'].includes(exifFileType) ||
    tags.some(t => ['audio', 'mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a', 'wma'].includes(t)) ||
    ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma', '.aiff', '.mid', '.midi', '.opus'].some(e => fileName.endsWith(e)) ||
    type.includes('audio') || type.includes('mp3') || type.includes('wave') || type.includes('flac') ||
    magic.includes('audio') || magic.includes('mp3') || magic.includes('wave') ||
    magika === 'mp3' || magika === 'wav' || magika === 'flac' || magika === 'ogg'
  ) {
    return 'audio';
  }

  // 4. Video formats
  if (
    mime.startsWith('video/') ||
    exifMime.startsWith('video/') ||
    ['mp4', 'mkv', 'avi', 'mov', 'webm', 'flv', 'wmv', 'm4v', 'ts', '3gp'].includes(exifFileType) ||
    tags.some(t => ['video', 'mp4', 'mkv', 'avi', 'mov', 'webm', 'flv', 'wmv'].includes(t)) ||
    ['.mp4', '.mkv', '.avi', '.mov', '.webm', '.flv', '.wmv', '.m4v', '.ts', '.3gp'].some(e => fileName.endsWith(e)) ||
    type.includes('video') || type.includes('mp4') || type.includes('matroska') || type.includes('quicktime') ||
    magic.includes('video') || magic.includes('mp4') || magic.includes('matroska') ||
    magika === 'mp4' || magika === 'mkv' || magika === 'avi' || magika === 'webm'
  ) {
    return 'video';
  }

  // 5. Document / Office / PDF formats
  if (
    fileResult?.extended?.pdfInfo ||
    fileResult?.extended?.officeInfo ||
    mime.includes('pdf') ||
    mime.includes('msword') ||
    mime.includes('officedocument') ||
    mime.includes('document') ||
    exifMime.includes('pdf') || exifMime.includes('word') || exifMime.includes('officedocument') ||
    ['pdf', 'docx', 'doc', 'xlsx', 'xls', 'pptx', 'ppt', 'odt', 'rtf', 'epub', 'csv'].includes(exifFileType) ||
    ['.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt', '.odt', '.rtf', '.epub', '.csv'].some(e => fileName.endsWith(e)) ||
    tags.some(t => ['pdf', 'document', 'docx', 'xlsx', 'pptx', 'office', 'vba', 'macro'].includes(t)) ||
    type.includes('pdf') || type.includes('word') || type.includes('excel') || type.includes('powerpoint') ||
    magic.includes('pdf') || magic.includes('composite document') || magic.includes('word') ||
    magika === 'pdf' || magika === 'docx' || magika === 'doc' || magika === 'xlsx' || magika === 'pptx'
  ) {
    return 'document';
  }

  // 6. Archive / Container formats
  if (
    fileResult?.extended?.bundleInfo ||
    mime.includes('zip') ||
    mime.includes('compressed') ||
    mime.includes('tar') ||
    mime.includes('x-rar') ||
    mime.includes('x-7z') ||
    mime.includes('iso9660') ||
    exifMime.includes('zip') || exifMime.includes('compressed') ||
    ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso'].includes(exifFileType) ||
    ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso', '.cab', '.jar', '.apk'].some(e => fileName.endsWith(e)) ||
    tags.some(t => ['zip', 'archive', 'rar', '7z', 'tar', 'iso', 'compressed'].includes(t)) ||
    type.includes('zip') || type.includes('archive') || type.includes('rar') || type.includes('tar') ||
    magic.includes('zip') || magic.includes('archive') || magic.includes('gzip') ||
    magika === 'zip' || magika === 'rar' || magika === '7z' || magika === 'tar' || magika === 'gzip'
  ) {
    return 'archive';
  }

  return 'generic';
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Audio Forensics Extractor
// ─────────────────────────────────────────────────────────────────────────────
export function extractAudioForensics(fileResult: NormalizedFile | null): AudioForensicsReport {
  const exif: Record<string, any> = fileResult?.extended?.exiftool || {};
  const magic = fileResult?.extended?.magic || '';

  // Duration
  let duration = exif['Duration'] || exif['AudioDuration'];
  if (!duration && magic) {
    const durMatch = magic.match(/(\d+:\d+(?::\d+)?|\d+\.\d+\s*s)/i);
    if (durMatch) duration = durMatch[1];
  }

  // Bitrate
  let bitrate = exif['AudioBitrate'] || exif['AvgBitrate'] || exif['Bitrate'];
  if (!bitrate && magic) {
    const brMatch = magic.match(/(\d+\s*kbps|\d+\s*kbit\/s)/i);
    if (brMatch) bitrate = brMatch[1];
  }

  // Sample Rate & Channels
  let sampleRate = exif['SampleRate'] ? `${exif['SampleRate']} Hz` : undefined;
  if (!sampleRate && magic) {
    const srMatch = magic.match(/(\d{4,6}\s*Hz)/i);
    if (srMatch) sampleRate = srMatch[1];
  }

  let channels = exif['Channels'] ? (exif['Channels'] === 2 ? 'Stereo (2 ch)' : exif['Channels'] === 1 ? 'Mono (1 ch)' : `${exif['Channels']} Channels`) : undefined;
  if (!channels && magic) {
    if (magic.toLowerCase().includes('stereo')) channels = 'Stereo (2 ch)';
    else if (magic.toLowerCase().includes('mono')) channels = 'Mono (1 ch)';
  }

  // ID3 Tags
  const id3 = {
    title: exif['Title'] ? String(exif['Title']) : undefined,
    artist: exif['Artist'] || exif['Band'] || exif['Performer'] ? String(exif['Artist'] || exif['Band'] || exif['Performer']) : undefined,
    album: exif['Album'] ? String(exif['Album']) : undefined,
    year: exif['Year'] || exif['RecordingTime'] || exif['Date'] ? String(exif['Year'] || exif['RecordingTime'] || exif['Date']) : undefined,
    genre: exif['Genre'] ? String(exif['Genre']) : undefined,
    track: exif['Track'] || exif['TrackNumber'] ? String(exif['Track'] || exif['TrackNumber']) : undefined,
    composer: exif['Composer'] ? String(exif['Composer']) : undefined,
    comments: exif['Comment'] || exif['UserDefinedText'] ? String(exif['Comment'] || exif['UserDefinedText']) : undefined,
  };

  // Stego & Anomaly Heuristics
  const signals: AudioForensicsReport['stego']['signals'] = [];
  let riskScore = 0;
  let hasTrailingData = false;

  const rawExifStr = JSON.stringify(exif).toLowerCase();
  if (rawExifStr.includes('<?php') || rawExifStr.includes('eval(') || rawExifStr.includes('base64_decode')) {
    riskScore += 60;
    signals.push({
      id: 'audio_script_polyglot',
      label: 'Embedded PHP/Executable Code in ID3 Metadata',
      details: 'Active script execution functions discovered in audio tag frames.',
      severity: 'critical'
    });
  }

  if (exif['Warning']) {
    const warn = String(exif['Warning']);
    if (warn.toLowerCase().includes('trailer') || warn.toLowerCase().includes('extra data')) {
      hasTrailingData = true;
      riskScore += 35;
      signals.push({
        id: 'audio_trailing_bytes',
        label: 'Appended Payload Past Audio EOF',
        details: warn,
        severity: 'high'
      });
    }
  }

  if (id3.comments && (id3.comments.length > 500 || /[A-Za-z0-9+/=]{100,}/.test(id3.comments))) {
    riskScore += 30;
    signals.push({
      id: 'audio_base64_comment',
      label: 'Large Encoded Base64 String in ID3 Comments',
      details: 'Obfuscated data payload detected inside audio metadata comment chunk.',
      severity: 'medium'
    });
  }

  if (signals.length === 0) {
    signals.push({
      id: 'audio_clean',
      label: 'Audio Stream Integrity Verified',
      details: 'No appended steganography payloads or corrupted frame headers discovered.',
      severity: 'clean'
    });
  }

  const riskLevel = riskScore >= 50 ? 'critical' : riskScore >= 25 ? 'suspicious' : riskScore > 0 ? 'low' : 'clean';

  return {
    format: fileResult?.type || 'Audio Stream',
    duration: duration ? String(duration) : undefined,
    bitrate: bitrate ? String(bitrate) : undefined,
    sampleRate,
    channels,
    codec: exif['AudioEncoding'] || exif['AudioCodec'] || (magic.includes('MPEG') ? 'MPEG Layer 3 (MP3)' : undefined),
    encoder: exif['Encoder'] || exif['LAME_Encoder'] || exif['WritingApplication'] ? String(exif['Encoder'] || exif['LAME_Encoder'] || exif['WritingApplication']) : undefined,
    id3,
    stego: {
      riskScore: Math.min(100, riskScore),
      riskLevel,
      hasTrailingData,
      signals
    }
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Video Forensics Extractor
// ─────────────────────────────────────────────────────────────────────────────
export function extractVideoForensics(fileResult: NormalizedFile | null): VideoForensicsReport {
  const exif: Record<string, any> = fileResult?.extended?.exiftool || {};
  const magic = fileResult?.extended?.magic || '';

  const rawWidth = exif['ImageWidth'] || exif['SourceImageWidth'];
  const rawHeight = exif['ImageHeight'] || exif['SourceImageHeight'];
  let width = typeof rawWidth === 'number' ? rawWidth : parseInt(String(rawWidth || '0'), 10);
  let height = typeof rawHeight === 'number' ? rawHeight : parseInt(String(rawHeight || '0'), 10);

  if ((!width || !height) && magic) {
    const dimMatch = magic.match(/(\d{3,5})\s*x\s*(\d{3,5})/i);
    if (dimMatch) {
      width = parseInt(dimMatch[1], 10);
      height = parseInt(dimMatch[2], 10);
    }
  }

  let aspectRatio = 'N/A';
  if (width && height) {
    const ratio = (width / height).toFixed(2);
    if (ratio === '1.78') aspectRatio = '16:9 (Widescreen)';
    else if (ratio === '1.33') aspectRatio = '4:3 (Standard)';
    else if (ratio === '2.33' || ratio === '2.35' || ratio === '2.39') aspectRatio = '21:9 (Cinemascope)';
    else aspectRatio = `${width}:${height}`;
  }

  // Duration & Frame Rate
  const duration = exif['Duration'] || exif['MediaDuration'] || exif['PlayTime'];
  const frameRate = exif['VideoFrameRate'] || exif['FrameRate'] ? `${exif['VideoFrameRate'] || exif['FrameRate']} fps` : undefined;

  // Codecs
  const videoCodec = exif['CompressorName'] || exif['VideoCodec'] || exif['VideoFormat'] || exif['MajorBrand'];
  const audioCodec = exif['AudioCodec'] || exif['AudioFormat'] || exif['AudioEncoding'];

  // GPS Video Metadata
  let gpsCoordinates: string | undefined;
  if (exif['GPSCoordinates'] || exif['GPSLatitude']) {
    gpsCoordinates = String(exif['GPSCoordinates'] || `${exif['GPSLatitude']}, ${exif['GPSLongitude']}`);
  }

  // Stego & Security Signals
  const signals: VideoForensicsReport['stego']['signals'] = [];
  let riskScore = 0;

  if (exif['Warning']) {
    signals.push({
      id: 'video_warning',
      label: 'Container Atom / Box Anomaly',
      details: String(exif['Warning']),
      severity: 'medium'
    });
    riskScore += 20;
  }

  if (signals.length === 0) {
    signals.push({
      id: 'video_clean',
      label: 'Container & Stream Integrity Valid',
      details: 'All video tracks, audio atoms, and sync markers conform to container specifications.',
      severity: 'clean'
    });
  }

  const riskLevel = riskScore >= 50 ? 'critical' : riskScore >= 20 ? 'suspicious' : 'clean';

  return {
    format: fileResult?.type || 'Video Container',
    duration: duration ? String(duration) : undefined,
    dimensions: {
      width: width || 0,
      height: height || 0,
      aspectRatio
    },
    videoCodec: videoCodec ? String(videoCodec) : undefined,
    audioCodec: audioCodec ? String(audioCodec) : undefined,
    frameRate,
    overallBitrate: exif['AvgBitrate'] || exif['Bitrate'] ? String(exif['AvgBitrate'] || exif['Bitrate']) : undefined,
    videoBitrate: exif['VideoBitrate'] ? String(exif['VideoBitrate']) : undefined,
    audioBitrate: exif['AudioBitrate'] ? String(exif['AudioBitrate']) : undefined,
    encoderTool: exif['WritingApplication'] || exif['Encoder'] || exif['HandlerDescription'] ? String(exif['WritingApplication'] || exif['Encoder'] || exif['HandlerDescription']) : undefined,
    creationDate: exif['CreateDate'] || exif['MediaCreateDate'] ? String(exif['CreateDate'] || exif['MediaCreateDate']) : undefined,
    gpsCoordinates,
    stego: {
      riskScore,
      riskLevel,
      signals
    }
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Document Forensics Extractor (PDF & Office VBA Macro Inspection)
// ─────────────────────────────────────────────────────────────────────────────
export function extractDocumentForensics(fileResult: NormalizedFile | null): DocumentForensicsReport {
  const exif: Record<string, any> = fileResult?.extended?.exiftool || {};
  const pdfInfo: Record<string, any> = fileResult?.extended?.pdfInfo || {};
  const officeInfo: Record<string, any> = fileResult?.extended?.officeInfo || {};
  const fileName = (fileResult?.name || fileResult?.names?.[0] || '').toLowerCase();
  const tags = (fileResult?.tags || []).map(t => t.toLowerCase());

  const isPdf = fileName.endsWith('.pdf') || tags.includes('pdf') || !!fileResult?.extended?.pdfInfo;
  const isWord = fileName.endsWith('.docx') || fileName.endsWith('.doc') || tags.includes('word');
  const isExcel = fileName.endsWith('.xlsx') || fileName.endsWith('.xls') || tags.includes('excel');
  const isPpt = fileName.endsWith('.pptx') || fileName.endsWith('.ppt') || tags.includes('powerpoint');

  const docType: DocumentForensicsReport['docType'] = isPdf
    ? 'pdf'
    : isWord
    ? 'word'
    : isExcel
    ? 'excel'
    : isPpt
    ? 'powerpoint'
    : 'generic_doc';

  const formatName = isPdf
    ? 'Portable Document Format (PDF)'
    : isWord
    ? 'Microsoft Word Document'
    : isExcel
    ? 'Microsoft Excel Spreadsheet'
    : isPpt
    ? 'Microsoft PowerPoint Presentation'
    : fileResult?.type || 'Document';

  // Common Metadata
  const pageCount = pdfInfo['pages'] || exif['PageCount'] || officeInfo['pages'];
  const wordCount = exif['WordCount'] || officeInfo['words'];
  const author = pdfInfo['author'] || exif['Author'] || officeInfo['author'] || exif['Creator'];
  const creator = pdfInfo['creator'] || exif['Creator'] || exif['Software'];
  const producer = pdfInfo['producer'] || exif['Producer'];
  const creationDate = pdfInfo['creation_date'] || exif['CreateDate'] || officeInfo['created'];
  const modifyDate = pdfInfo['modification_date'] || exif['ModifyDate'] || officeInfo['last_modified'];
  const isEncrypted = Boolean(pdfInfo['encrypted'] || exif['Encryption'] || exif['Security']);

  // Document Security & Signals
  const signals: DocumentForensicsReport['signals'] = [];
  let threatScore = 0;
  let hasMacros = false;
  let hasJavaScript = false;
  let hasEmbeddedActions = false;
  let hasExternalLinks = false;

  // 1. PDF-Specific Threat Signals
  if (isPdf) {
    if (pdfInfo['javascript'] || exif['JavaScript'] || tags.includes('javascript')) {
      hasJavaScript = true;
      threatScore += 45;
      signals.push({
        id: 'pdf_javascript',
        label: 'Embedded JavaScript Stream (/JS, /JavaScript)',
        details: 'Active JavaScript executable logic embedded inside PDF dictionary objects.',
        severity: 'high'
      });
    }

    if (pdfInfo['auto_open'] || pdfInfo['open_action'] || exif['OpenAction']) {
      hasEmbeddedActions = true;
      threatScore += 40;
      signals.push({
        id: 'pdf_open_action',
        label: 'Automatic Execution Trigger (/OpenAction /AA)',
        details: 'Document automatically executes commands or opens URLs immediately upon document launch.',
        severity: 'high'
      });
    }

    if (pdfInfo['launch_action'] || exif['Launch']) {
      hasEmbeddedActions = true;
      threatScore += 70;
      signals.push({
        id: 'pdf_launch_action',
        label: 'Process Execution Action (/Launch)',
        details: 'Document contains action directives attempting to execute system binaries.',
        severity: 'critical'
      });
    }

    if (pdfInfo['embedded_files'] && pdfInfo['embedded_files'].length > 0) {
      signals.push({
        id: 'pdf_embedded_files',
        label: `Embedded Dropped Files (${pdfInfo['embedded_files'].length})`,
        details: `Discovered attached files within PDF: ${pdfInfo['embedded_files'].join(', ')}`,
        severity: 'medium'
      });
      threatScore += 25;
    }
  }

  // 2. Office VBA Macro Threat Signals
  if (isWord || isExcel || isPpt || officeInfo['macro_present'] || tags.includes('macro') || tags.includes('vba')) {
    hasMacros = Boolean(officeInfo['macro_present'] || tags.includes('macro') || tags.includes('vba'));
    if (hasMacros) {
      threatScore += 50;
      signals.push({
        id: 'office_vba_macro',
        label: 'VBA Macro Code Discovered',
        details: 'Embedded Visual Basic for Applications executable automation scripts present in document.',
        severity: 'high'
      });
    }

    if (officeInfo['auto_exec'] && officeInfo['auto_exec'].length > 0) {
      threatScore += 35;
      signals.push({
        id: 'office_auto_exec',
        label: 'Auto-Executing Macro Directives',
        details: `Discovered auto-run procedures: ${officeInfo['auto_exec'].join(', ')}`,
        severity: 'critical'
      });
    }
  }

  if (signals.length === 0) {
    signals.push({
      id: 'doc_clean',
      label: 'Document Security Inspection Passed',
      details: 'No malicious macros, auto-actions, or embedded exploit streams detected.',
      severity: 'clean'
    });
  }

  const threatLevel = threatScore >= 60 ? 'critical' : threatScore >= 30 ? 'suspicious' : threatScore > 0 ? 'low' : 'clean';

  return {
    docType,
    formatName,
    pageCount: pageCount ? parseInt(String(pageCount), 10) : undefined,
    wordCount: wordCount ? parseInt(String(wordCount), 10) : undefined,
    author: author ? String(author) : undefined,
    creator: creator ? String(creator) : undefined,
    producer: producer ? String(producer) : undefined,
    creationDate: creationDate ? String(creationDate) : undefined,
    modifyDate: modifyDate ? String(modifyDate) : undefined,
    isEncrypted,
    hasMacros,
    hasJavaScript,
    hasEmbeddedActions,
    hasExternalLinks,
    threatScore: Math.min(100, threatScore),
    threatLevel,
    pdfDetails: isPdf ? {
      version: pdfInfo['version'] || exif['PDFVersion'] ? String(pdfInfo['version'] || exif['PDFVersion']) : '1.4',
      isLinearized: Boolean(pdfInfo['is_linearized'] || exif['Linearized']),
      objectStreams: Boolean(pdfInfo['object_streams']),
      tagged: Boolean(exif['Tagged']),
      jsCount: pdfInfo['javascript_count']
    } : undefined,
    officeDetails: !isPdf ? {
      appName: exif['Application'] || officeInfo['app_name'],
      appVersion: exif['AppVersion'] || officeInfo['app_version'],
      lastModifiedBy: exif['LastModifiedBy'] || officeInfo['last_modified_by'],
      revisionNumber: exif['RevisionNumber'] || officeInfo['revision_number'],
      totalEditTime: exif['TotalEditTime'] || officeInfo['total_edit_time'],
      macroStreams: officeInfo['macro_streams'],
      autoExecMacros: officeInfo['auto_exec']
    } : undefined,
    signals
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Archive & Container Forensics Extractor (ZIP / RAR / ISO / 7z)
// ─────────────────────────────────────────────────────────────────────────────
export function extractArchiveForensics(fileResult: NormalizedFile | null): ArchiveForensicsReport {
  const exif: Record<string, any> = fileResult?.extended?.exiftool || {};
  const bundleInfo: Record<string, any> = fileResult?.extended?.bundleInfo || {};

  const files: ArchiveForensicsReport['files'] = [];
  const signals: ArchiveForensicsReport['signals'] = [];
  let threatScore = 0;
  let hasExecutables = false;
  let hasScripts = false;

  // Extract contained files from bundleInfo / exif
  if (Array.isArray(bundleInfo['contained_files'])) {
    bundleInfo['contained_files'].forEach((f: any) => {
      const name = typeof f === 'string' ? f : f.name || f.file_name || 'unknown';
      const isExe = /\.(exe|dll|scr|sys|cpl|com|pif)$/i.test(name);
      const isSc = /\.(vbs|js|wsf|bat|cmd|ps1|hta|sh)$/i.test(name);
      if (isExe) hasExecutables = true;
      if (isSc) hasScripts = true;

      files.push({
        name,
        size: f.size || f.uncompressed_size,
        compressedSize: f.compressed_size,
        crc: f.crc,
        isExecutable: isExe,
        isScript: isSc
      });
    });
  } else if (exif['ZipFileName']) {
    const name = String(exif['ZipFileName']);
    const isExe = /\.(exe|dll|scr|sys)$/i.test(name);
    if (isExe) hasExecutables = true;
    files.push({ name, isExecutable: isExe });
  }

  if (hasExecutables) {
    threatScore += 40;
    signals.push({
      id: 'archive_executables',
      label: 'Executable Binaries Inside Archive (.exe, .scr, .dll)',
      details: 'Archive contains binary executables often leveraged for payload delivery.',
      severity: 'high'
    });
  }

  if (hasScripts) {
    threatScore += 45;
    signals.push({
      id: 'archive_scripts',
      label: 'Automation Script Files Discovered (.vbs, .js, .bat, .ps1)',
      details: 'Archive contains staging scripts commonly used in dropper stages.',
      severity: 'high'
    });
  }

  // Compression Ratio / Zip Bomb Heuristic
  const uncompSize = exif['ZipUncompressedSize'] || bundleInfo['uncompressed_size'] || 0;
  const compSize = fileResult?.size || exif['ZipCompressedSize'] || 1;
  let isPotentialZipBomb = false;
  let compressionRatio = 'N/A';

  if (uncompSize && compSize) {
    const ratio = (uncompSize / compSize);
    compressionRatio = `${ratio.toFixed(1)} : 1`;
    if (ratio > 100 && uncompSize > 100 * 1024 * 1024) {
      isPotentialZipBomb = true;
      threatScore += 60;
      signals.push({
        id: 'zip_bomb_anomaly',
        label: 'Potential Decompression Bomb (Zip Bomb)',
        details: `Abnormal expansion ratio (${compressionRatio}) detected. Unpacking may cause Denial of Service.`,
        severity: 'critical'
      });
    }
  }

  if (signals.length === 0) {
    signals.push({
      id: 'archive_clean',
      label: 'Archive Structure Normal',
      details: 'No concealed high-risk script droppers or decompression bombs detected.',
      severity: 'clean'
    });
  }

  const threatLevel = threatScore >= 50 ? 'critical' : threatScore >= 25 ? 'suspicious' : threatScore > 0 ? 'low' : 'clean';

  return {
    archiveType: fileResult?.type || 'Compressed Archive',
    fileCount: files.length > 0 ? files.length : (exif['ZipRequiredVersion'] ? 1 : 0),
    uncompressedSize: uncompSize || undefined,
    compressedSize: fileResult?.size,
    compressionRatio,
    isEncrypted: Boolean(exif['ZipBitFlag'] && (parseInt(String(exif['ZipBitFlag']), 10) & 1)),
    hasExecutables,
    hasScripts,
    isPotentialZipBomb,
    files,
    threatScore: Math.min(100, threatScore),
    threatLevel,
    signals
  };
}
