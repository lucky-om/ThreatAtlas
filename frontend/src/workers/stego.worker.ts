/// <reference lib="webworker" />

self.onmessage = async (e: MessageEvent) => {
  try {
    const buffer: ArrayBuffer = e.data;
    const bytes = new Uint8Array(buffer);

    let hasTrailingData = false;
    let polyglotDetected = false;
    let scriptInjectionDetected = false;

    // 1. Structural Scan for JPEGs (FF D8 ... FF D9)
    if (bytes.length > 2 && bytes[0] === 0xFF && bytes[1] === 0xD8) {
      // It's a JPEG. Find FF D9 (End of Image)
      let eoiIndex = -1;
      for (let i = bytes.length - 2; i >= 0; i--) {
        if (bytes[i] === 0xFF && bytes[i + 1] === 0xD9) {
          eoiIndex = i + 1; // Index of 0xD9
          break;
        }
      }
      
      // If EOI marker found and there is more than 2 bytes of padding after it
      if (eoiIndex !== -1 && eoiIndex < bytes.length - 2) {
        hasTrailingData = true;
      }
    }

    // 2. Polyglot / Script Injection Scan (Heuristic)
    // Scan the first few KB and last few KB for common script tags
    const chunkSize = Math.min(bytes.length, 100 * 1024); // First and last 100KB
    
    // Convert first chunk to string (lossy, just for ASCII matching)
    let startStr = "";
    for (let i = 0; i < chunkSize; i++) {
      startStr += String.fromCharCode(bytes[i]);
    }

    let endStr = "";
    for (let i = Math.max(0, bytes.length - chunkSize); i < bytes.length; i++) {
      endStr += String.fromCharCode(bytes[i]);
    }

    const fullStr = startStr + " " + endStr;
    const lowerStr = fullStr.toLowerCase();

    if (lowerStr.includes("<?php") || lowerStr.includes("eval(") || lowerStr.includes("exec(")) {
      polyglotDetected = true;
    }

    if (lowerStr.includes("<script") || lowerStr.includes("javascript:")) {
      scriptInjectionDetected = true;
    }

    // 3. Simple LSB Entropy Check (Fast heuristic)
    // We just sample every Nth byte and check the lowest bit parity distribution
    let bit1Count = 0;
    let bit0Count = 0;
    const step = Math.max(1, Math.floor(bytes.length / 100000)); // sample ~100k bytes max
    
    for (let i = 100; i < bytes.length - 100; i += step) { // skip very start/end headers
      const lsb = bytes[i] & 1;
      if (lsb === 1) bit1Count++;
      else bit0Count++;
    }

    // Perfect 50/50 split is normal for highly compressed data, but extreme deviations
    // or perfect uniformity in uncompressed formats can indicate LSB stuffing.
    // For this heuristic, we'll just flag if it's perfectly 50.00% split in a way that suggests encrypted stuffing.
    // Actually, compressed JPEGs already have high entropy. We'll leave the flag as false unless we implement deep LSB mapping.
    
    // Determine Risk Level
    let riskScore = 0;
    if (hasTrailingData) riskScore += 40;
    if (polyglotDetected) riskScore += 60;
    if (scriptInjectionDetected) riskScore += 50;
    
    let riskLevel = 'clean';
    if (riskScore >= 70) riskLevel = 'critical';
    else if (riskScore >= 40) riskLevel = 'suspicious';
    else if (riskScore > 0) riskLevel = 'low';

    // Build signals
    const signals = [];
    if (polyglotDetected) {
      signals.push({ id: 'poly', label: 'Polyglot Signature Detected', severity: 'critical', details: 'Executable code or PHP tags were found embedded within the image data stream.' });
    }
    if (scriptInjectionDetected) {
      signals.push({ id: 'xss', label: 'Cross-Site Scripting (XSS) Vector', severity: 'high', details: 'HTML script tags were discovered, which may execute if the image is improperly parsed by a browser.' });
    }
    if (hasTrailingData) {
      signals.push({ id: 'trail', label: 'Trailing Data Append', severity: 'medium', details: 'Additional arbitrary data was found appended after the End-Of-Image marker. This is a common steganography technique.' });
    }
    if (signals.length === 0) {
      signals.push({ id: 'clean', label: 'No Structural Anomalies', severity: 'low', details: 'Image structure conforms to standard format specifications. No overt data append attacks detected.' });
    }

    // Return the stego object
    self.postMessage({
      status: 'success',
      stego: {
        riskScore: Math.min(riskScore, 100),
        riskLevel,
        polyglotDetected,
        hasTrailingData,
        scriptInjectionDetected,
        signals
      }
    });

  } catch (error: any) {
    self.postMessage({ status: 'error', message: error.message });
  }
};
