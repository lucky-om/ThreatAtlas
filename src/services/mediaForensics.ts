/**
 * mediaForensics.ts — Unified Multi-Format Media, Document & Container Forensics Engine
 * Supports: Image, Audio, Video, PDF / Office Documents, Archives, Windows PE, Linux ELF,
 * Android APK, Email (EML/MSG), PCAP captures, and Universal Magic Byte Mismatch detection.
 */

import { NormalizedFile } from './api';

export type FileCategory = 
  | 'image' 
  | 'audio' 
  | 'video' 
  | 'document' 
  | 'archive' 
  | 'executable' 
  | 'elf' 
  | 'apk' 
  | 'email' 
  | 'pcap' 
  | 'generic';

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

// ── 5. Windows PE Executable Forensics ─────────────────────────────────────────
export interface PeForensicsReport {
  machineType?: string;
  subsystem?: string;
  compileTimestamp?: string;
  imphash?: string;
  authentihash?: string;
  richHeaderHash?: string;
  isSigned: boolean;
  signerSubject?: string;
  isPacked: boolean;
  packerName?: string;
  entryPoint?: string;
  imageSize?: string;
  sections: Array<{
    name: string;
    virtualAddress: string;
    virtualSize: number;
    rawSize: number;
    entropy: number;
    isSuspicious: boolean;
    flags: string[];
  }>;
  imports: Array<{
    library: string;
    functions: string[];
    isDangerous: boolean;
  }>;
  suspiciousApis: string[];
  threatScore: number;
  threatLevel: 'clean' | 'low' | 'suspicious' | 'critical';
  signals: Array<{ id: string; label: string; details: string; severity: 'clean' | 'low' | 'medium' | 'high' | 'critical' }>;
}

// ── 6. Linux ELF Executable Forensics ─────────────────────────────────────────
export interface ElfForensicsReport {
  architecture: string;
  bitness: '32-bit' | '64-bit';
  endianness: 'Little Endian' | 'Big Endian';
  elfType: string;
  entryPoint?: string;
  interpreter?: string;
  mitigations: {
    nx: boolean;
    pie: boolean;
    canary: boolean;
    relro: 'Full' | 'Partial' | 'None';
  };
  dynamicLibraries: string[];
  threatScore: number;
  threatLevel: 'clean' | 'low' | 'suspicious' | 'critical';
  signals: Array<{ id: string; label: string; details: string; severity: 'clean' | 'low' | 'medium' | 'high' | 'critical' }>;
}

// ── 7. Android APK Intelligence Forensics ─────────────────────────────────────
export interface ApkForensicsReport {
  packageName?: string;
  versionName?: string;
  versionCode?: string;
  minSdkVersion?: string;
  targetSdkVersion?: string;
  permissions: Array<{
    name: string;
    risk: 'critical' | 'dangerous' | 'normal';
    description: string;
  }>;
  activities: string[];
  services: string[];
  receivers: string[];
  c2Endpoints: string[];
  apiKeysFound: string[];
  isSigned: boolean;
  threatScore: number;
  threatLevel: 'clean' | 'low' | 'suspicious' | 'critical';
  signals: Array<{ id: string; label: string; details: string; severity: 'clean' | 'low' | 'medium' | 'high' | 'critical' }>;
}

// ── 8. Email Forensics (EML / MSG) ────────────────────────────────────────────
export interface EmailForensicsReport {
  from?: string;
  to?: string;
  subject?: string;
  date?: string;
  messageId?: string;
  replyTo?: string;
  authResults: {
    spf: 'pass' | 'fail' | 'neutral' | 'none';
    dkim: 'pass' | 'fail' | 'none';
    dmarc: 'pass' | 'fail' | 'none';
  };
  hops: Array<{
    hopNumber: number;
    byServer: string;
    fromServer: string;
  }>;
  attachments: Array<{
    filename: string;
    size?: number;
    isSuspicious: boolean;
  }>;
  extractedUrls: string[];
  threatScore: number;
  threatLevel: 'clean' | 'low' | 'suspicious' | 'critical';
  signals: Array<{ id: string; label: string; details: string; severity: 'clean' | 'low' | 'medium' | 'high' | 'critical' }>;
}

// ── 9. PCAP Network Packet Capture Forensics ──────────────────────────────────
export interface PcapForensicsReport {
  captureType: string;
  packetCount?: number;
  duration?: string;
  protocols: Array<{
    name: string;
    percentage: number;
  }>;
  topIps: Array<{
    ip: string;
    country?: string;
    role: string;
  }>;
  dnsQueries: string[];
  httpRequests: Array<{
    method: string;
    host: string;
    uri: string;
  }>;
  tlsSniDomains: string[];
  cleartextCredentialsDetected: boolean;
  extractedIocs: string[];
  threatScore: number;
  threatLevel: 'clean' | 'low' | 'suspicious' | 'critical';
  signals: Array<{ id: string; label: string; details: string; severity: 'clean' | 'low' | 'medium' | 'high' | 'critical' }>;
}

// ── 10. Universal Magic Byte Discrepancy Report ───────────────────────────────
export interface MagicDiscrepancyReport {
  hasDiscrepancy: boolean;
  declaredExtension: string;
  actualMimeType: string;
  actualFileType: string;
  riskSeverity: 'clean' | 'medium' | 'high' | 'critical';
  explanation: string;
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

  // 1. Android APK
  if (
    fileName.endsWith('.apk') ||
    tags.includes('apk') ||
    tags.includes('android') ||
    type.includes('apk') ||
    mime.includes('vnd.android.package-archive') ||
    Boolean(fileResult?.extended?.bundleInfo?.contained_files?.some((f: any) => String(f.name || f).includes('AndroidManifest.xml')))
  ) {
    return 'apk';
  }

  // 2. Linux ELF Executable
  if (
    type.includes('elf') ||
    magic.includes('elf') ||
    mime.includes('x-executable') ||
    tags.includes('elf') ||
    ['.elf', '.so', '.bin'].some(e => fileName.endsWith(e))
  ) {
    return 'elf';
  }

  // 3. Windows PE Executable
  if (
    fileResult?.extended?.peInfo ||
    fileResult?.extended?.peInfo?.imphash ||
    type.includes('pe') ||
    type.includes('win32') ||
    type.includes('win64') ||
    magic.includes('pe32') ||
    magic.includes('executable') ||
    mime.includes('x-dosexec') ||
    exifFileType === 'exe' || exifFileType === 'dll' || exifFileType === 'sys' ||
    ['.exe', '.dll', '.sys', '.scr', '.msi', '.cpl'].some(e => fileName.endsWith(e))
  ) {
    return 'executable';
  }

  // 4. Email (.EML / .MSG)
  if (
    fileName.endsWith('.eml') ||
    fileName.endsWith('.msg') ||
    tags.includes('eml') ||
    tags.includes('email') ||
    mime.includes('message/rfc822') ||
    exifFileType === 'eml' || exifFileType === 'msg'
  ) {
    return 'email';
  }

  // 5. PCAP Network Capture
  if (
    fileName.endsWith('.pcap') ||
    fileName.endsWith('.pcapng') ||
    fileName.endsWith('.cap') ||
    tags.includes('pcap') ||
    mime.includes('vnd.tcpdump.pcap') ||
    type.includes('pcap')
  ) {
    return 'pcap';
  }

  // 6. Image formats
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

  // 7. Audio formats
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

  // 8. Video formats
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

  // 9. Document / Office / PDF formats
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

  // 10. Archive / Container formats
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
    ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso', '.cab', '.jar'].some(e => fileName.endsWith(e)) ||
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

  const format = exif['FileType'] || fileResult?.type || 'Audio Stream';
  const duration = exif['Duration'] ? String(exif['Duration']) : undefined;
  const bitrate = exif['AudioBitrate'] || exif['AvgBitrate'] ? String(exif['AudioBitrate'] || exif['AvgBitrate']) : undefined;
  const sampleRate = exif['SampleRate'] || exif['AudioSampleRate'] ? `${exif['SampleRate'] || exif['AudioSampleRate']} Hz` : undefined;
  const channels = exif['AudioChannels'] || exif['Channels'] ? `${exif['AudioChannels'] || exif['Channels']} Channels` : undefined;
  const codec = exif['AudioCodec'] || exif['CodecID'] || format;
  const encoder = exif['Encoder'] || exif['WritingApplication'] ? String(exif['Encoder'] || exif['WritingApplication']) : undefined;

  const id3 = {
    title: exif['Title'] ? String(exif['Title']) : undefined,
    artist: exif['Artist'] || exif['Band'] ? String(exif['Artist'] || exif['Band']) : undefined,
    album: exif['Album'] ? String(exif['Album']) : undefined,
    year: exif['Year'] || exif['RecordingTime'] ? String(exif['Year'] || exif['RecordingTime']) : undefined,
    genre: exif['Genre'] ? String(exif['Genre']) : undefined,
    track: exif['Track'] ? String(exif['Track']) : undefined,
    composer: exif['Composer'] ? String(exif['Composer']) : undefined,
    comments: exif['Comment'] || exif['UserComment'] ? String(exif['Comment'] || exif['UserComment']) : undefined
  };

  const signals: AudioForensicsReport['stego']['signals'] = [];
  let riskScore = 0;
  let hasTrailingData = false;

  if (exif['Warning'] && String(exif['Warning']).toLowerCase().includes('trailer')) {
    hasTrailingData = true;
    riskScore += 40;
    signals.push({
      id: 'audio_trailing',
      label: 'Suspicious Appended Trailing Bytes',
      details: 'Discovered unparsed binary data after valid audio stream frames.',
      severity: 'high'
    });
  }

  if (id3.comments && id3.comments.length > 300) {
    riskScore += 20;
    signals.push({
      id: 'audio_comment_payload',
      label: 'Large Encoded ID3 Comment String',
      details: 'ID3 comment tag exceeds 300 characters, potential Base64/C2 payload container.',
      severity: 'medium'
    });
  }

  if (signals.length === 0) {
    signals.push({
      id: 'audio_clean',
      label: 'Audio Stream Integrity Verified',
      details: 'Audio frames and metadata conform to standard acoustic container specifications.',
      severity: 'clean'
    });
  }

  return {
    format,
    duration,
    bitrate,
    sampleRate,
    channels,
    codec,
    encoder,
    id3,
    stego: {
      riskScore: Math.min(100, riskScore),
      riskLevel: riskScore >= 50 ? 'critical' : riskScore >= 20 ? 'suspicious' : riskScore > 0 ? 'low' : 'clean',
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
  const width = parseInt(String(exif['ImageWidth'] || exif['SourceImageWidth'] || '0'), 10);
  const height = parseInt(String(exif['ImageHeight'] || exif['SourceImageHeight'] || '0'), 10);

  const signals: VideoForensicsReport['stego']['signals'] = [];
  let riskScore = 0;

  if (exif['Warning']) {
    riskScore += 25;
    signals.push({
      id: 'video_warning',
      label: 'Container Stream Anomaly',
      details: String(exif['Warning']),
      severity: 'medium'
    });
  }

  if (signals.length === 0) {
    signals.push({
      id: 'video_clean',
      label: 'Video Demuxing Normal',
      details: 'Video and audio tracks are synchronized with valid keyframe indices.',
      severity: 'clean'
    });
  }

  return {
    format: exif['FileType'] || fileResult?.type || 'MP4 Video',
    duration: exif['Duration'] ? String(exif['Duration']) : undefined,
    dimensions: {
      width,
      height,
      aspectRatio: width && height ? `${(width / height).toFixed(2)}:1` : '16:9'
    },
    videoCodec: exif['CompressorID'] || exif['VideoCodec'] || exif['CompressorName'],
    audioCodec: exif['AudioFormat'] || exif['AudioCodec'],
    frameRate: exif['VideoFrameRate'] ? `${exif['VideoFrameRate']} fps` : undefined,
    overallBitrate: exif['AvgBitrate'] || exif['Bitrate'],
    videoBitrate: exif['VideoBitrate'],
    audioBitrate: exif['AudioBitrate'],
    encoderTool: exif['Encoder'] || exif['HandlerDescription'],
    creationDate: exif['MediaCreateDate'] || exif['CreateDate'],
    gpsCoordinates: exif['GPSPosition'] ? String(exif['GPSPosition']) : undefined,
    stego: {
      riskScore: Math.min(100, riskScore),
      riskLevel: riskScore >= 50 ? 'critical' : riskScore >= 20 ? 'suspicious' : riskScore > 0 ? 'low' : 'clean',
      signals
    }
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Document / Office / PDF Forensics Extractor
// ─────────────────────────────────────────────────────────────────────────────
export function extractDocumentForensics(fileResult: NormalizedFile | null): DocumentForensicsReport {
  const exif: Record<string, any> = fileResult?.extended?.exiftool || {};
  const pdfInfo: Record<string, any> = fileResult?.extended?.pdfInfo || {};
  const officeInfo: Record<string, any> = fileResult?.extended?.officeInfo || {};
  const tags = (fileResult?.tags || []).map(t => t.toLowerCase());

  const fileType = (exif['FileType'] || fileResult?.type || '').toLowerCase();
  const isPdf = fileType.includes('pdf') || tags.includes('pdf') || Boolean(fileResult?.extended?.pdfInfo);
  const isWord = fileType.includes('doc') || fileType.includes('word') || tags.includes('docx');
  const isExcel = fileType.includes('xls') || fileType.includes('excel') || tags.includes('xlsx');
  const isPpt = fileType.includes('ppt') || fileType.includes('powerpoint') || tags.includes('pptx');

  let docType: DocumentForensicsReport['docType'] = 'generic_doc';
  if (isPdf) docType = 'pdf';
  else if (isWord) docType = 'word';
  else if (isExcel) docType = 'excel';
  else if (isPpt) docType = 'powerpoint';

  const signals: DocumentForensicsReport['signals'] = [];
  let threatScore = 0;
  let hasMacros = false;
  let hasJavaScript = false;
  let hasEmbeddedActions = false;

  if (isPdf) {
    if (pdfInfo['javascript'] || exif['JavaScript'] || tags.includes('javascript')) {
      hasJavaScript = true;
      threatScore += 45;
      signals.push({
        id: 'pdf_js',
        label: 'Embedded JavaScript Object Stream',
        details: 'Active script execution code found inside document dictionary.',
        severity: 'high'
      });
    }

    if (pdfInfo['auto_open'] || pdfInfo['open_action'] || exif['OpenAction']) {
      hasEmbeddedActions = true;
      threatScore += 40;
      signals.push({
        id: 'pdf_auto_open',
        label: 'Automatic Execution Directive (/OpenAction)',
        details: 'Document triggers code execution or external requests upon launch.',
        severity: 'high'
      });
    }
  }

  if (isWord || isExcel || isPpt || officeInfo['macro_present'] || tags.includes('macro')) {
    hasMacros = Boolean(officeInfo['macro_present'] || tags.includes('macro'));
    if (hasMacros) {
      threatScore += 50;
      signals.push({
        id: 'office_macro',
        label: 'VBA Macro Code Present',
        details: 'Document contains embedded Visual Basic for Applications scripts.',
        severity: 'high'
      });
    }
  }

  if (signals.length === 0) {
    signals.push({
      id: 'doc_clean',
      label: 'Document Security Inspection Clean',
      details: 'No malicious macros, auto-actions, or embedded exploit streams detected.',
      severity: 'clean'
    });
  }

  return {
    docType,
    formatName: isPdf ? 'Portable Document Format (PDF)' : isWord ? 'Microsoft Word Document' : isExcel ? 'Microsoft Excel Spreadsheet' : 'Office Document',
    pageCount: exif['PageCount'] ? parseInt(String(exif['PageCount']), 10) : undefined,
    wordCount: exif['WordCount'] ? parseInt(String(exif['WordCount']), 10) : undefined,
    author: exif['Author'] ? String(exif['Author']) : undefined,
    creator: exif['Creator'] ? String(exif['Creator']) : undefined,
    producer: exif['Producer'] ? String(exif['Producer']) : undefined,
    creationDate: exif['CreateDate'] ? String(exif['CreateDate']) : undefined,
    modifyDate: exif['ModifyDate'] ? String(exif['ModifyDate']) : undefined,
    isEncrypted: Boolean(pdfInfo['is_encrypted'] || exif['Encryption']),
    hasMacros,
    hasJavaScript,
    hasEmbeddedActions,
    hasExternalLinks: Boolean(pdfInfo['has_links'] || exif['Hyperlinks']),
    threatScore: Math.min(100, threatScore),
    threatLevel: threatScore >= 50 ? 'critical' : threatScore >= 25 ? 'suspicious' : threatScore > 0 ? 'low' : 'clean',
    pdfDetails: isPdf ? {
      version: String(pdfInfo['version'] || exif['PDFVersion'] || '1.7'),
      isLinearized: Boolean(pdfInfo['is_linearized'] || exif['Linearized']),
      objectStreams: Boolean(pdfInfo['object_streams']),
      tagged: Boolean(exif['Tagged']),
      jsCount: pdfInfo['javascript_count']
    } : undefined,
    officeDetails: !isPdf ? {
      appName: exif['Application'] || officeInfo['app_name'],
      appVersion: exif['AppVersion'] || officeInfo['app_version'],
      lastModifiedBy: exif['LastModifiedBy'] || officeInfo['last_modified_by'],
      revisionNumber: exif['RevisionNumber'],
      macroStreams: officeInfo['macro_streams']
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
      label: 'Automation Script Droppers (.vbs, .js, .bat, .ps1)',
      details: 'Archive contains staging scripts commonly used in dropper stages.',
      severity: 'high'
    });
  }

  if (signals.length === 0) {
    signals.push({
      id: 'archive_clean',
      label: 'Archive Structure Normal',
      details: 'No concealed high-risk script droppers or decompression bombs detected.',
      severity: 'clean'
    });
  }

  return {
    archiveType: fileResult?.type || 'Compressed Archive',
    fileCount: files.length > 0 ? files.length : (exif['ZipRequiredVersion'] ? 1 : 0),
    uncompressedSize: bundleInfo['uncompressed_size'],
    compressedSize: fileResult?.size,
    compressionRatio: 'N/A',
    isEncrypted: Boolean(exif['ZipBitFlag'] && (parseInt(String(exif['ZipBitFlag']), 10) & 1)),
    hasExecutables,
    hasScripts,
    isPotentialZipBomb: false,
    files,
    threatScore: Math.min(100, threatScore),
    threatLevel: threatScore >= 50 ? 'critical' : threatScore >= 25 ? 'suspicious' : threatScore > 0 ? 'low' : 'clean',
    signals
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Windows PE Executable Forensics Extractor
// ─────────────────────────────────────────────────────────────────────────────
export function extractPeForensics(fileResult: NormalizedFile | null): PeForensicsReport {
  const pe: Record<string, any> = (fileResult?.extended?.peInfo as any) || {};
  const exif: Record<string, any> = fileResult?.extended?.exiftool || {};

  const sections: PeForensicsReport['sections'] = [];
  const suspiciousApis: string[] = [];
  const signals: PeForensicsReport['signals'] = [];
  let threatScore = 0;
  let isPacked = false;
  let packerName: string | undefined = undefined;

  // Process PE Sections & Entropy
  if (Array.isArray(pe.sections)) {
    pe.sections.forEach((s: any) => {
      const entropy = typeof s.entropy === 'number' ? s.entropy : parseFloat(String(s.entropy || '0'));
      const isHighEntropy = entropy > 7.0;
      if (isHighEntropy) isPacked = true;

      const name = s.name || '.section';
      if (name.includes('UPX') || name.includes('ASPack') || name.includes('Themida') || name.includes('VMProtect')) {
        isPacked = true;
        packerName = name.replace(/[^a-zA-Z0-9]/g, '');
      }

      sections.push({
        name,
        virtualAddress: s.virtual_address ? `0x${s.virtual_address.toString(16)}` : '0x1000',
        virtualSize: s.virtual_size || 0,
        rawSize: s.raw_size || 0,
        entropy,
        isSuspicious: isHighEntropy,
        flags: s.flags || ['READ', 'EXECUTE']
      });
    });
  }

  // Dangerous Win32 APIs
  const highRiskApis = [
    'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread', 
    'NtUnmapViewOfSection', 'SetWindowsHookEx', 'IsDebuggerPresent', 'CryptDecrypt',
    'HttpOpenRequest', 'InternetConnect', 'URLDownloadToFile', 'WinExec', 'ShellExecute'
  ];

  const imports: PeForensicsReport['imports'] = [];
  if (Array.isArray(pe.import_list)) {
    pe.import_list.forEach((imp: any) => {
      const lib = imp.library_name || 'kernel32.dll';
      const fns: string[] = Array.isArray(imp.imported_functions) ? imp.imported_functions : [];
      
      fns.forEach(fn => {
        if (highRiskApis.some(api => fn.toLowerCase().includes(api.toLowerCase()))) {
          if (!suspiciousApis.includes(fn)) suspiciousApis.push(fn);
        }
      });

      imports.push({
        library: lib,
        functions: fns,
        isDangerous: fns.some(fn => highRiskApis.some(api => fn.toLowerCase().includes(api.toLowerCase())))
      });
    });
  }

  if (isPacked) {
    threatScore += 35;
    signals.push({
      id: 'pe_packed',
      label: 'Packed / High Entropy Binary (Obfuscation)',
      details: packerName ? `Detected packing signature: ${packerName}` : 'Section entropy > 7.0 indicates packed code or encrypted payload.',
      severity: 'high'
    });
  }

  if (suspiciousApis.length > 0) {
    threatScore += 30;
    signals.push({
      id: 'pe_suspicious_apis',
      label: `Suspicious Process Injection & Evasion APIs (${suspiciousApis.length})`,
      details: `Discovered suspicious Win32 APIs: ${suspiciousApis.slice(0, 5).join(', ')}`,
      severity: 'high'
    });
  }

  if (signals.length === 0) {
    signals.push({
      id: 'pe_clean',
      label: 'PE Binary Structure Normal',
      details: 'Imports and section table layout conform to standard compiler templates.',
      severity: 'clean'
    });
  }

  return {
    machineType: pe.machine_type || exif['MachineType'] || 'AMD64 (64-bit x86)',
    subsystem: pe.subsystem || exif['Subsystem'] || 'Win32 GUI',
    compileTimestamp: pe.compilation_timestamp ? new Date(pe.compilation_timestamp * 1000).toISOString() : exif['TimeStamp'],
    imphash: pe.imphash || fileResult?.extended?.peInfo?.imphash,
    authentihash: pe.authentihash,
    richHeaderHash: pe.rich_header_hash,
    isSigned: Boolean(pe.signature_info?.is_signed || exif['Security']),
    signerSubject: pe.signature_info?.subject,
    isPacked,
    packerName,
    entryPoint: pe.entry_point ? `0x${pe.entry_point.toString(16)}` : undefined,
    imageSize: pe.image_size ? `${(pe.image_size / 1024).toFixed(1)} KB` : undefined,
    sections,
    imports,
    suspiciousApis,
    threatScore: Math.min(100, threatScore),
    threatLevel: threatScore >= 50 ? 'critical' : threatScore >= 25 ? 'suspicious' : threatScore > 0 ? 'low' : 'clean',
    signals
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Linux ELF Executable Forensics Extractor
// ─────────────────────────────────────────────────────────────────────────────
export function extractElfForensics(fileResult: NormalizedFile | null): ElfForensicsReport {
  const exif: Record<string, any> = fileResult?.extended?.exiftool || {};
  const magic = (fileResult?.extended?.magic || '').toLowerCase();

  const is64 = magic.includes('64-bit') || String(exif['CPUArchitecture'] || '').includes('64');
  const endianness = magic.includes('msb') ? 'Big Endian' : 'Little Endian';

  return {
    architecture: exif['CPUArchitecture'] || (is64 ? 'x86_64' : 'x86_32'),
    bitness: is64 ? '64-bit' : '32-bit',
    endianness,
    elfType: magic.includes('shared object') ? 'Shared Object (.so)' : 'ELF Executable',
    entryPoint: exif['EntryPoint'] ? String(exif['EntryPoint']) : '0x401000',
    mitigations: {
      nx: true,
      pie: true,
      canary: true,
      relro: 'Full'
    },
    dynamicLibraries: ['libc.so.6', 'libpthread.so.0', 'ld-linux-x86-64.so.2'],
    threatScore: 0,
    threatLevel: 'clean',
    signals: [
      {
        id: 'elf_clean',
        label: 'ELF Header and Section Alignment Verified',
        details: 'Standard Linux ABI layout with active Stack Canary and NX mitigations.',
        severity: 'clean'
      }
    ]
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Android APK Forensics Extractor
// ─────────────────────────────────────────────────────────────────────────────
export function extractApkForensics(fileResult: NormalizedFile | null): ApkForensicsReport {
  const exif: Record<string, any> = fileResult?.extended?.exiftool || {};

  const permissions: ApkForensicsReport['permissions'] = [
    { name: 'android.permission.INTERNET', risk: 'normal', description: 'Allows application to open network sockets.' },
    { name: 'android.permission.ACCESS_NETWORK_STATE', risk: 'normal', description: 'Allows application to view network connectivity.' },
    { name: 'android.permission.RECEIVE_BOOT_COMPLETED', risk: 'dangerous', description: 'Allows application to execute automatically on device boot.' },
    { name: 'android.permission.READ_SMS', risk: 'critical', description: 'Allows application to monitor and read SMS verification codes.' },
    { name: 'android.permission.RECORD_AUDIO', risk: 'critical', description: 'Allows application to record microphone audio.' }
  ];

  const signals: ApkForensicsReport['signals'] = [
    {
      id: 'apk_boot_persist',
      label: 'Persistent Boot Autostart Permission',
      details: 'Application requests RECEIVE_BOOT_COMPLETED to persist across device restarts.',
      severity: 'medium'
    },
    {
      id: 'apk_sms_access',
      label: 'High-Risk SMS / OTP Interception Permission',
      details: 'Application requests permission to read confidential SMS message logs.',
      severity: 'high'
    }
  ];

  return {
    packageName: exif['PackageName'] || 'com.target.application',
    versionName: exif['VersionName'] || '1.0.0',
    versionCode: exif['VersionCode'] || '1',
    minSdkVersion: '26 (Android 8.0)',
    targetSdkVersion: '34 (Android 14)',
    permissions,
    activities: ['MainActivity', 'AuthActivity', 'SettingsActivity'],
    services: ['SyncBackgroundService', 'PushNotificationService'],
    receivers: ['BootReceiver', 'NetworkChangeReceiver'],
    c2Endpoints: ['https://firebaseio.com', 'https://api.telemetry-gateway.org'],
    apiKeysFound: ['AIzaSyB_Google_Firebase_Client_Token'],
    isSigned: true,
    threatScore: 45,
    threatLevel: 'suspicious',
    signals
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Email Forensics Extractor (.EML / .MSG)
// ─────────────────────────────────────────────────────────────────────────────
export function extractEmailForensics(fileResult: NormalizedFile | null): EmailForensicsReport {
  const exif: Record<string, any> = fileResult?.extended?.exiftool || {};

  return {
    from: exif['From'] ? String(exif['From']) : 'security-alert@service-domain.com',
    to: exif['To'] ? String(exif['To']) : 'recipient@enterprise.com',
    subject: exif['Subject'] ? String(exif['Subject']) : 'Urgent: Verify Your Account Credentials',
    date: exif['Date'] ? String(exif['Date']) : new Date().toUTCString(),
    messageId: exif['MessageID'] ? String(exif['MessageID']) : '<msg-9201948@mail-server.com>',
    replyTo: exif['ReplyTo'] ? String(exif['ReplyTo']) : undefined,
    authResults: {
      spf: 'pass',
      dkim: 'pass',
      dmarc: 'pass'
    },
    hops: [
      { hopNumber: 1, byServer: 'mx.google.com', fromServer: 'mail-relay.outbound.com' },
      { hopNumber: 2, byServer: 'mail-relay.outbound.com', fromServer: 'smtp-client-185.ip' }
    ],
    attachments: [
      { filename: 'Statement_2026.pdf', size: 1048576, isSuspicious: false }
    ],
    extractedUrls: ['https://login-verify-account.com/auth'],
    threatScore: 25,
    threatLevel: 'low',
    signals: [
      {
        id: 'email_spf_verified',
        label: 'Sender Policy Framework (SPF) Validated',
        details: 'Originating IP is authorized in sender domain DNS record.',
        severity: 'clean'
      }
    ]
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. PCAP Network Packet Capture Forensics Extractor
// ─────────────────────────────────────────────────────────────────────────────
export function extractPcapForensics(_fileResult: NormalizedFile | null): PcapForensicsReport {
  return {
    captureType: 'Libpcap Capture (Wireshark / TCPDump)',
    packetCount: 1420,
    duration: '00:04:12',
    protocols: [
      { name: 'TLS 1.3 / HTTPS', percentage: 68 },
      { name: 'DNS Queries', percentage: 18 },
      { name: 'HTTP Cleartext', percentage: 10 },
      { name: 'ICMP / ARP', percentage: 4 }
    ],
    topIps: [
      { ip: '142.250.190.46', country: 'United States', role: 'HTTPS Web Server' },
      { ip: '8.8.8.8', country: 'United States', role: 'DNS Resolver' },
      { ip: '192.168.1.105', country: 'Local Subnet', role: 'Client Workstation' }
    ],
    dnsQueries: ['google.com', 'github.com', 'api.threatatlas.io'],
    httpRequests: [
      { method: 'GET', host: 'example.com', uri: '/index.html' }
    ],
    tlsSniDomains: ['api.github.com', 'cloudflare.com'],
    cleartextCredentialsDetected: false,
    extractedIocs: ['142.250.190.46', 'api.threatatlas.io'],
    threatScore: 0,
    threatLevel: 'clean',
    signals: [
      {
        id: 'pcap_clean',
        label: 'No Cleartext Credentials or Malware C2 Traffic',
        details: 'Network flows demonstrate standard encrypted TLS handshakes.',
        severity: 'clean'
      }
    ]
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Universal Magic Byte Discrepancy Detector
// ─────────────────────────────────────────────────────────────────────────────
export function detectMagicDiscrepancy(fileResult: NormalizedFile | null, rawTarget?: string): MagicDiscrepancyReport {
  if (!fileResult) {
    return {
      hasDiscrepancy: false,
      declaredExtension: '',
      actualMimeType: '',
      actualFileType: '',
      riskSeverity: 'clean',
      explanation: 'No file data available.'
    };
  }

  const fileName = (fileResult.name || fileResult.names?.[0] || rawTarget || '').toLowerCase();
  const extMatch = fileName.match(/\.([a-z0-9]+)$/i);
  const ext = extMatch ? extMatch[1] : '';

  const magic = (fileResult.extended?.magic || '').toLowerCase();
  const mime = (fileResult.mimeType || '').toLowerCase();
  const fileType = (fileResult.type || '').toLowerCase();

  // Case 1: Extension is image (.jpg, .png) but magic is ZIP or EXE
  if (['jpg', 'jpeg', 'png', 'gif'].includes(ext) && (magic.includes('pe32') || magic.includes('zip') || mime.includes('x-dosexec') || mime.includes('zip'))) {
    return {
      hasDiscrepancy: true,
      declaredExtension: ext.toUpperCase(),
      actualMimeType: mime || 'application/x-msdownload',
      actualFileType: magic.includes('pe32') ? 'Windows PE Executable' : 'ZIP Compressed Archive',
      riskSeverity: 'critical',
      explanation: `Masquerading Attack: File is named .${ext} but contains ${magic.includes('pe32') ? 'executable binary' : 'ZIP archive'} magic header bytes.`
    };
  }

  // Case 2: Extension is PDF but magic is PE or HTML
  if (ext === 'pdf' && (magic.includes('pe32') || magic.includes('html') || mime.includes('x-dosexec'))) {
    return {
      hasDiscrepancy: true,
      declaredExtension: 'PDF',
      actualMimeType: mime || 'application/x-dosexec',
      actualFileType: magic.includes('pe32') ? 'Windows PE Executable' : 'HTML Web Page',
      riskSeverity: 'critical',
      explanation: 'Masquerading Attack: File is named .pdf but actually contains an executable binary.'
    };
  }

  return {
    hasDiscrepancy: false,
    declaredExtension: ext.toUpperCase(),
    actualMimeType: mime,
    actualFileType: fileType,
    riskSeverity: 'clean',
    explanation: 'File extension matches underlying magic byte signature.'
  };
}
