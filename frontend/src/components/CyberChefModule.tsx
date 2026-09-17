import React, { useState } from 'react';

export const CyberChefModule: React.FC = () => {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [operation, setOperation] = useState<'b64_dec' | 'b64_enc' | 'hex_dec' | 'hex_enc' | 'url_dec' | 'rot13' | 'strings' | 'entropy'>('b64_dec');

  const runOperation = (op: typeof operation, text: string) => {
    setOperation(op);
    if (!text) {
      setOutput('');
      return;
    }

    try {
      if (op === 'b64_dec') {
        setOutput(atob(text.replace(/\s+/g, '')));
      } else if (op === 'b64_enc') {
        setOutput(btoa(text));
      } else if (op === 'hex_dec') {
        const clean = text.replace(/[^a-fA-F0-9]/g, '');
        let str = '';
        for (let i = 0; i < clean.length; i += 2) {
          str += String.fromCharCode(parseInt(clean.substr(i, 2), 16));
        }
        setOutput(str);
      } else if (op === 'hex_enc') {
        let hex = '';
        for (let i = 0; i < text.length; i++) {
          hex += text.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
        }
        setOutput(hex.trim());
      } else if (op === 'url_dec') {
        setOutput(decodeURIComponent(text));
      } else if (op === 'rot13') {
        setOutput(text.replace(/[a-zA-Z]/g, c => {
          const base = c <= 'Z' ? 65 : 97;
          return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
        }));
      } else if (op === 'strings') {
        const matches = text.match(/[A-Za-z0-9/\-_:.]{4,}/g) || [];
        setOutput(matches.join('\n'));
      } else if (op === 'entropy') {
        const freqs: Record<string, number> = {};
        for (let i = 0; i < text.length; i++) {
          const char = text[i];
          freqs[char] = (freqs[char] || 0) + 1;
        }
        let ent = 0;
        for (const c in freqs) {
          const p = freqs[c] / text.length;
          ent -= p * Math.log2(p);
        }
        setOutput(`Shannon Byte Entropy: ${ent.toFixed(4)} / 8.0000\nLength: ${text.length} characters\nUnique Bytes: ${Object.keys(freqs).length}\n\nClassification: ${ent > 7.0 ? 'High Entropy (Encrypted / Compressed / Packed)' : ent > 5.0 ? 'Moderate Entropy (Code / Executable)' : 'Low Entropy (Plaintext / Formatted Data)'}`);
      }
    } catch (e: any) {
      setOutput(`[Decoding Error]: ${e.message}`);
    }
  };

  return (
    <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '10px', padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="material-symbols-outlined" style={{ color: '#ec4899', fontSize: '24px' }}>
            auto_fix_high
          </span>
          <div>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#f1f5f9' }}>
              Universal CyberChef Forensic Decoder & Data Transformer
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '11px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Real-time Base64, Hex, URL, ROT13, Strings carving & Shannon entropy calculator
            </p>
          </div>
        </div>
      </div>

      {/* Operation Buttons */}
      <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
        {[
          { id: 'b64_dec', label: 'Base64 Decode' },
          { id: 'b64_enc', label: 'Base64 Encode' },
          { id: 'hex_dec', label: 'Hex to ASCII' },
          { id: 'hex_enc', label: 'ASCII to Hex' },
          { id: 'url_dec', label: 'URL Decode' },
          { id: 'rot13', label: 'ROT13 Cipher' },
          { id: 'strings', label: 'Extract Strings (len>=4)' },
          { id: 'entropy', label: 'Calculate Shannon Entropy' }
        ].map(btn => (
          <button
            key={btn.id}
            onClick={() => runOperation(btn.id as any, input)}
            style={{
              background: operation === btn.id ? 'rgba(236,72,153,0.15)' : 'rgba(255,255,255,0.03)',
              border: operation === btn.id ? '1px solid #ec4899' : '1px solid rgba(255,255,255,0.06)',
              color: operation === btn.id ? '#ec4899' : '#cbd5e1',
              padding: '6px 12px',
              borderRadius: '6px',
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              cursor: 'pointer',
              fontWeight: operation === btn.id ? 700 : 500
            }}
          >
            {btn.label}
          </button>
        ))}
      </div>

      {/* Input / Output Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
        <div>
          <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', marginBottom: '6px', textTransform: 'uppercase' }}>
            Input Payload (Raw / Encoded)
          </div>
          <textarea
            placeholder="Paste encoded strings, Base64 chunks, Hex dumps, or URL tokens..."
            value={input}
            onChange={e => {
              setInput(e.target.value);
              runOperation(operation, e.target.value);
            }}
            style={{
              width: '100%',
              height: '140px',
              background: 'rgba(0,0,0,0.3)',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#ffffff',
              padding: '10px 12px',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              resize: 'vertical'
            }}
          />
        </div>

        <div>
          <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', marginBottom: '6px', textTransform: 'uppercase' }}>
            Decoded Output
          </div>
          <textarea
            readOnly
            placeholder="Decoded output will stream here..."
            value={output}
            style={{
              width: '100%',
              height: '140px',
              background: 'rgba(0,0,0,0.4)',
              border: '1px solid #1e293b',
              borderRadius: '8px',
              color: 'var(--brand-amber)',
              padding: '10px 12px',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              resize: 'vertical'
            }}
          />
        </div>
      </div>
    </div>
  );
};
