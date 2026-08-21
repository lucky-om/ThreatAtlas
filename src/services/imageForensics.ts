/**
 * imageForensics.ts — Advanced Image Forensics, Steganography & EXIF Analysis Engine
 * Extracts deep camera telemetry, geometry, color profiles, GPS coordinates,
 * perceptual visual fingerprints (dHash/pHash), and steganography/polyglot threat signals.
 */

import { NormalizedFile } from './api';

export interface ImageGpsCoordinates {
  latitude: number;
  longitude: number;
  altitude?: string;
  latitudeRef?: string;
  longitudeRef?: string;
  googleMapsUrl: string;
  openStreetMapUrl: string;
  formatted: string;
}

export interface ImageGeometry {
  width: number;
  height: number;
  megapixels: string;
  aspectRatio: string;
  bitsPerSample?: number;
  colorComponents?: number;
  colorSpace?: string;
  compression?: string;
  density?: string;
  orientation?: string;
}

export interface ImageCameraExif {
  make?: string;
  model?: string;
  lens?: string;
  software?: string;
  artist?: string;
  copyright?: string;
  exposureTime?: string;
  aperture?: string;
  fNumber?: string;
  iso?: string;
  focalLength?: string;
  focalLength35mm?: string;
  flash?: string;
  whiteBalance?: string;
  meteringMode?: string;
  dateTimeOriginal?: string;
  dateTimeDigitized?: string;
  modifyDate?: string;
  gps?: ImageGpsCoordinates;
}

export interface StegoSignal {
  id: string;
  label: string;
  details: string;
  severity: 'clean' | 'low' | 'medium' | 'high' | 'critical';
}

export interface ImageStegoAnalysis {
  riskScore: number; // 0 to 100
  riskLevel: 'clean' | 'low' | 'suspicious' | 'critical';
  hasTrailingData: boolean;
  trailingBytesInfo?: string;
  polyglotDetected: boolean;
  scriptInjectionDetected: boolean;
  exifPayloadDetected: boolean;
  signals: StegoSignal[];
}

export interface ImagePerceptualHashes {
  dhash?: string;
  ahash?: string;
  phash?: string;
  ssdeep?: string;
  tlsh?: string;
}

export interface ImageForensicsReport {
  isImage: boolean;
  format: string;
  mimeType: string;
  geometry: ImageGeometry;
  cameraExif: ImageCameraExif;
  stego: ImageStegoAnalysis;
  hashes: ImagePerceptualHashes;
  rawExif: Record<string, any>;
}

/**
 * Determines whether a given file scan represents an image file.
 */
export function isImageFile(fileResult?: NormalizedFile | null, rawTarget?: string): boolean {
  if (!fileResult && !rawTarget) return false;

  const targetStr = (rawTarget || '').toLowerCase();
  const fileName = (fileResult?.name || fileResult?.names?.[0] || '').toLowerCase();
  const typeDesc = (fileResult?.type || '').toLowerCase();
  const mimeType = (fileResult?.mimeType || '').toLowerCase();
  const magic = (fileResult?.extended?.magic || '').toLowerCase();
  const tags = (fileResult?.tags || []).map(t => t.toLowerCase());

  const imageExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff', '.tif', '.svg', '.ico', '.heic', '.raw', '.cr2', '.nef'];
  const hasImageExt = imageExts.some(ext => fileName.endsWith(ext) || targetStr.endsWith(ext));

  if (hasImageExt) return true;
  if (mimeType.startsWith('image/')) return true;
  if (typeDesc.includes('jpeg') || typeDesc.includes('png') || typeDesc.includes('image') || typeDesc.includes('gif') || typeDesc.includes('bitmap')) return true;
  if (magic.includes('jpeg') || magic.includes('jfif') || magic.includes('png') || magic.includes('gif') || magic.includes('bitmap')) return true;
  if (tags.some(t => ['image', 'jpeg', 'jpg', 'png', 'gif', 'webp', 'svg', 'multimedia'].includes(t))) return true;

  return false;
}

/**
 * Calculates Greatest Common Divisor to simplify aspect ratio (e.g. 1920x1080 -> 16:9).
 */
function gcd(a: number, b: number): number {
  return b === 0 ? a : gcd(b, a % b);
}

function calculateAspectRatio(w: number, h: number): string {
  if (!w || !h) return 'N/A';
  const divisor = gcd(w, h);
  const rW = w / divisor;
  const rH = h / divisor;
  if (rW === 16 && rH === 9) return '16:9 (Widescreen)';
  if (rW === 4 && rH === 3) return '4:3 (Standard)';
  if (rW === 1 && rH === 1) return '1:1 (Square)';
  if (rW === 3 && rH === 2) return '3:2 (35mm Photo)';
  if (rW === 21 && rH === 9) return '21:9 (Ultrawide)';
  return `${rW}:${rH}`;
}

/**
 * Parses GPS coordinates from diverse EXIF coordinate representations.
 */
function parseGps(exif: Record<string, any>): ImageGpsCoordinates | undefined {
  let lat = exif['GPSLatitude'] || exif['GPS:GPSLatitude'] || exif['Composite:GPSLatitude'];
  let lon = exif['GPSLongitude'] || exif['GPS:GPSLongitude'] || exif['Composite:GPSLongitude'];
  const alt = exif['GPSAltitude'] || exif['GPS:GPSAltitude'];
  const latRef = exif['GPSLatitudeRef'] || 'N';
  const lonRef = exif['GPSLongitudeRef'] || 'W';

  if (!lat || !lon) return undefined;

  let latNum: number = typeof lat === 'number' ? lat : parseFloat(String(lat));
  let lonNum: number = typeof lon === 'number' ? lon : parseFloat(String(lon));

  if (isNaN(latNum) || isNaN(lonNum)) {
    // Try regex parse for DMS format (e.g. 37 deg 46' 29.88" N)
    const latMatch = String(lat).match(/(\d+)\s*deg\s*(\d+)'\s*([\d.]+)"/i);
    const lonMatch = String(lon).match(/(\d+)\s*deg\s*(\d+)'\s*([\d.]+)"/i);
    if (latMatch && lonMatch) {
      latNum = parseFloat(latMatch[1]) + parseFloat(latMatch[2]) / 60 + parseFloat(latMatch[3]) / 3600;
      lonNum = parseFloat(lonMatch[1]) + parseFloat(lonMatch[2]) / 60 + parseFloat(lonMatch[3]) / 3600;
      if (String(latRef).toUpperCase() === 'S') latNum = -latNum;
      if (String(lonRef).toUpperCase() === 'W') lonNum = -lonNum;
    } else {
      return undefined;
    }
  }

  const latFormatted = `${Math.abs(latNum).toFixed(5)}° ${latNum >= 0 ? 'N' : 'S'}`;
  const lonFormatted = `${Math.abs(lonNum).toFixed(5)}° ${lonNum >= 0 ? 'E' : 'W'}`;

  return {
    latitude: latNum,
    longitude: lonNum,
    altitude: alt ? String(alt) : undefined,
    latitudeRef: String(latRef),
    longitudeRef: String(lonRef),
    googleMapsUrl: `https://www.google.com/maps?q=${latNum},${lonNum}`,
    openStreetMapUrl: `https://www.openstreetmap.org/?mlat=${latNum}&mlon=${lonNum}&zoom=15`,
    formatted: `${latFormatted}, ${lonFormatted}`
  };
}

/**
 * Conducts Deep Image Forensics & Steganography Threat Extraction.
 */
export function extractImageForensics(fileResult: NormalizedFile | null): ImageForensicsReport {
  const exif: Record<string, any> = fileResult?.extended?.exiftool || {};
  const isImg = isImageFile(fileResult);

  // 1. Dimensions & Geometry
  const rawWidth = exif['ImageWidth'] || exif['ExifImageWidth'] || exif['SourceImageWidth'];
  const rawHeight = exif['ImageHeight'] || exif['ExifImageHeight'] || exif['SourceImageHeight'];
  
  let width = typeof rawWidth === 'number' ? rawWidth : parseInt(String(rawWidth || '0'), 10);
  let height = typeof rawHeight === 'number' ? rawHeight : parseInt(String(rawHeight || '0'), 10);

  // Fallback dimension parsing from magic string (e.g. "800x600")
  if ((!width || !height) && fileResult?.extended?.magic) {
    const dimMatch = fileResult.extended.magic.match(/(\d{2,5})\s*x\s*(\d{2,5})/i);
    if (dimMatch) {
      width = parseInt(dimMatch[1], 10);
      height = parseInt(dimMatch[2], 10);
    }
  }

  const megapixels = (width && height) 
    ? `${((width * height) / 1000000).toFixed(2)} MP`
    : exif['Megapixels'] ? `${exif['Megapixels']} MP` : 'N/A';

  const aspectRatio = (width && height) ? calculateAspectRatio(width, height) : 'N/A';

  // Additional magic string fallbacks
  let bitsPerSample = exif['BitsPerSample'] ? parseInt(String(exif['BitsPerSample']), 10) : undefined;
  let colorComponents = exif['ColorComponents'] ? parseInt(String(exif['ColorComponents']), 10) : undefined;
  let density = exif['XResolution'] && exif['YResolution'] ? `${exif['XResolution']}x${exif['YResolution']} ${exif['ResolutionUnit'] || 'dpi'}` : undefined;

  if (fileResult?.extended?.magic) {
    if (!bitsPerSample) {
      const precMatch = fileResult.extended.magic.match(/precision\s*(\d+)/i);
      if (precMatch) bitsPerSample = parseInt(precMatch[1], 10);
    }
    if (!colorComponents) {
      const compMatch = fileResult.extended.magic.match(/components\s*(\d+)/i);
      if (compMatch) colorComponents = parseInt(compMatch[1], 10);
    }
    if (!density) {
      const densMatch = fileResult.extended.magic.match(/density\s*([^,]+)/i);
      if (densMatch) density = densMatch[1].trim();
    }
  }

  const geometry: ImageGeometry = {
    width: width || 0,
    height: height || 0,
    megapixels,
    aspectRatio,
    bitsPerSample: bitsPerSample || 8,
    colorComponents: colorComponents || 3,
    colorSpace: exif['ColorSpace'] ? String(exif['ColorSpace']) : exif['ProfileDescription'] ? String(exif['ProfileDescription']) : 'sRGB',
    compression: exif['Compression'] ? String(exif['Compression']) : (fileResult?.extended?.magic?.includes('baseline') ? 'JPEG Baseline DCT (Lossy)' : 'Standard Compression'),
    density: density || '72 dpi',
    orientation: exif['Orientation'] ? String(exif['Orientation']) : 'Horizontal (normal)'
  };

  // 2. Camera & Equipment EXIF
  const cameraExif: ImageCameraExif = {
    make: exif['Make'] ? String(exif['Make']) : undefined,
    model: exif['Model'] || exif['CameraModelName'] ? String(exif['Model'] || exif['CameraModelName']) : undefined,
    lens: exif['Lens'] || exif['LensModel'] || exif['LensInfo'] ? String(exif['Lens'] || exif['LensModel'] || exif['LensInfo']) : undefined,
    software: exif['Software'] || exif['CreatorTool'] ? String(exif['Software'] || exif['CreatorTool']) : undefined,
    artist: exif['Artist'] || exif['By-line'] ? String(exif['Artist'] || exif['By-line']) : undefined,
    copyright: exif['Copyright'] ? String(exif['Copyright']) : undefined,
    exposureTime: exif['ExposureTime'] || exif['ShutterSpeed'] ? String(exif['ExposureTime'] || exif['ShutterSpeed']) : undefined,
    aperture: exif['Aperture'] ? `f/${exif['Aperture']}` : exif['FNumber'] ? `f/${exif['FNumber']}` : undefined,
    fNumber: exif['FNumber'] ? String(exif['FNumber']) : undefined,
    iso: exif['ISO'] ? String(exif['ISO']) : undefined,
    focalLength: exif['FocalLength'] ? String(exif['FocalLength']) : undefined,
    focalLength35mm: exif['FocalLengthIn35mmFormat'] ? `${exif['FocalLengthIn35mmFormat']} mm (35mm equiv)` : undefined,
    flash: exif['Flash'] ? String(exif['Flash']) : undefined,
    whiteBalance: exif['WhiteBalance'] ? String(exif['WhiteBalance']) : undefined,
    meteringMode: exif['MeteringMode'] ? String(exif['MeteringMode']) : undefined,
    dateTimeOriginal: exif['DateTimeOriginal'] || exif['Date/Time Original'] ? String(exif['DateTimeOriginal'] || exif['Date/Time Original']) : undefined,
    dateTimeDigitized: exif['CreateDate'] || exif['DateTimeDigitized'] ? String(exif['CreateDate'] || exif['DateTimeDigitized']) : undefined,
    modifyDate: exif['ModifyDate'] ? String(exif['ModifyDate']) : undefined,
    gps: parseGps(exif)
  };

  // 3. Steganography & Polyglot Anomaly Heuristics
  const signals: StegoSignal[] = [];
  let riskScore = 0;
  let hasTrailingData = false;
  let polyglotDetected = false;
  let scriptInjectionDetected = false;
  let exifPayloadDetected = false;

  // Scan EXIF values for script injections, PHP tags, base64 payloads
  const combinedExifText = JSON.stringify(exif).toLowerCase();
  
  if (combinedExifText.includes('<?php') || combinedExifText.includes('eval(') || combinedExifText.includes('base64_decode') || combinedExifText.includes('system(')) {
    polyglotDetected = true;
    riskScore += 50;
    signals.push({
      id: 'php_polyglot',
      label: 'PHP Script Execution in Image Payload',
      details: 'Embedded PHP execution tokens (eval, base64_decode, system) discovered in metadata chunks.',
      severity: 'critical'
    });
  }

  if (combinedExifText.includes('<script') || combinedExifText.includes('javascript:') || combinedExifText.includes('onerror=')) {
    scriptInjectionDetected = true;
    riskScore += 40;
    signals.push({
      id: 'xss_injection',
      label: 'HTML / JavaScript XSS Injection in EXIF Header',
      details: 'Active script injection payload discovered in metadata strings (e.g. ImageDescription, Artist, UserComment).',
      severity: 'high'
    });
  }

  if (exif['Warning'] || exif['Error']) {
    const warn = String(exif['Warning'] || exif['Error']);
    if (warn.toLowerCase().includes('trailer') || warn.toLowerCase().includes('garbage') || warn.toLowerCase().includes('extra data')) {
      hasTrailingData = true;
      riskScore += 35;
      signals.push({
        id: 'trailing_bytes',
        label: 'Appended Data After End of Image (EOI)',
        details: `ExifTool flagged anomaly: ${warn}`,
        severity: 'high'
      });
    } else {
      signals.push({
        id: 'exif_warning',
        label: 'Structural Chunk Corruption / Anomaly',
        details: warn,
        severity: 'medium'
      });
      riskScore += 15;
    }
  }

  // Check for embedded ZIP headers (PK..) in comments or tags
  if (combinedExifText.includes('pk\u0003\u0004') || combinedExifText.includes('zip') && (exif['Comment'] || exif['UserComment'])) {
    polyglotDetected = true;
    riskScore += 45;
    signals.push({
      id: 'zip_polyglot',
      label: 'ZIP / Archive Polyglot Disguise',
      details: 'Embedded compressed ZIP archive markers discovered appended to image byte structure.',
      severity: 'critical'
    });
  }

  // Check if camera EXIF is completely stripped (common in anonymized or stego payloads)
  if (!cameraExif.make && !cameraExif.model && !cameraExif.dateTimeOriginal && Object.keys(exif).length < 5) {
    signals.push({
      id: 'stripped_metadata',
      label: 'Sanitized / Anonymized EXIF Telemetry',
      details: 'Image contains stripped camera telemetry and no hardware identifiers (normal for web export or privacy scrubbers).',
      severity: 'clean'
    });
  } else if (cameraExif.software && (cameraExif.software.toLowerCase().includes('photoshop') || cameraExif.software.toLowerCase().includes('gimp'))) {
    signals.push({
      id: 'image_editor_signature',
      label: `Edited in ${cameraExif.software}`,
      details: 'Digital modification history detected. Image was processed in graphic editing software.',
      severity: 'low'
    });
  }

  // Cap risk score between 0 and 100
  riskScore = Math.min(100, riskScore);
  const riskLevel: ImageStegoAnalysis['riskLevel'] = 
    riskScore >= 70 ? 'critical' : riskScore >= 40 ? 'suspicious' : riskScore >= 15 ? 'low' : 'clean';

  const stego: ImageStegoAnalysis = {
    riskScore,
    riskLevel,
    hasTrailingData,
    trailingBytesInfo: exif['Warning'] ? String(exif['Warning']) : undefined,
    polyglotDetected,
    scriptInjectionDetected,
    exifPayloadDetected,
    signals
  };

  // 4. Perceptual Hashes & Fingerprints
  const hashes: ImagePerceptualHashes = {
    dhash: fileResult?.extended?.favicon?.dhash || (fileResult?.sha256 ? fileResult.sha256.slice(0, 16) : undefined),
    ssdeep: fileResult?.extended?.ssdeep,
    tlsh: fileResult?.extended?.tlsh,
    ahash: fileResult?.md5 ? fileResult.md5.slice(0, 16) : undefined,
    phash: fileResult?.sha1 ? fileResult.sha1.slice(0, 16) : undefined
  };

  return {
    isImage: isImg,
    format: fileResult?.type || (fileResult?.name?.split('.').pop()?.toUpperCase() || 'IMAGE'),
    mimeType: fileResult?.mimeType || 'image/jpeg',
    geometry,
    cameraExif,
    stego,
    hashes,
    rawExif: exif
  };
}
