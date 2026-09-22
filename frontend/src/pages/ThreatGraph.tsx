import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { detectInputType, getBackendBase } from '../services/api';
import { SEO } from '../components/SEO';

// ── Node & Link Data Types ──────────────────────────────────────────────────
export type NodeType = 'file' | 'ip' | 'domain' | 'url' | 'mitre' | 'whois' | 'target';

export interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  verdict?: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  threatScore?: number;
  details?: string;
  tags?: string[];
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  color: string;
  targetLink?: string;
}

export interface GraphLink {
  source: string;
  target: string;
  label: string;
  color?: string;
}

export interface PresetCluster {
  name: string;
  root: string;
  nodes: Array<Omit<GraphNode, 'vx' | 'vy'>>;
  links: GraphLink[];
}

// ── Preset Attack Infrastructure Clusters ──────────────────────────────────
const PRESET_CLUSTERS: PresetCluster[] = [
  {
    name: 'WannaCry 2.0 Ransomware Mesh',
    root: 'ed01ebf83334a193730700345de3f9f4d716e11894d3e8e19e7176466f272a2c',
    nodes: [
      { id: 'root', label: 'WannaCry.exe (SHA-256)', type: 'file', verdict: 'malicious', threatScore: 98, details: 'WannaCrypt0r ransomware dropper utilizing MS17-010 EternalBlue exploit.', x: 0, y: 0, radius: 24, color: '#ff2a5f', tags: ['ransomware', 'ms17-010', 'worm'] },
      { id: 'killswitch', label: 'www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com', type: 'domain', verdict: 'suspicious', threatScore: 65, details: 'Sinkholed domain serving as the global execution killswitch.', x: -140, y: -90, radius: 18, color: 'var(--brand-ember)' },
      { id: 'c2_1', label: '194.58.112.174', type: 'ip', verdict: 'malicious', threatScore: 92, details: 'Tor relay and C2 beacon endpoint for extortion payment negotiation.', x: 150, y: -100, radius: 16, color: '#fb923c' },
      { id: 'c2_2', label: '185.220.101.5', type: 'ip', verdict: 'malicious', threatScore: 88, details: 'Known malicious Tor exit node communicating with WannaCry SMB scanner.', x: 170, y: 70, radius: 16, color: '#fb923c' },
      { id: 'mitre1', label: 'T1486 (Data Encrypted for Impact)', type: 'mitre', verdict: 'malicious', threatScore: 90, details: 'Encrypts user files with AES-128 and appends .WNCRY extension.', x: -160, y: 90, radius: 15, color: '#eab308' },
      { id: 'mitre2', label: 'T1210 (Exploitation of Remote Services)', type: 'mitre', verdict: 'malicious', threatScore: 95, details: 'Exploits SMBv1 vulnerability CVE-2017-0144 to spread laterally.', x: 0, y: 150, radius: 15, color: '#eab308' },
      { id: 'tor_onion', label: 'gx7ekbenv2riucmf.onion', type: 'url', verdict: 'malicious', threatScore: 95, details: 'Decryption service payment URL.', x: -70, y: -160, radius: 14, color: 'var(--brand)' }
    ],
    links: [
      { source: 'root', target: 'killswitch', label: 'Queries Killswitch' },
      { source: 'root', target: 'c2_1', label: 'Beacon C2' },
      { source: 'root', target: 'c2_2', label: 'SMB Scanner' },
      { source: 'root', target: 'mitre1', label: 'Executes Technique' },
      { source: 'root', target: 'mitre2', label: 'Spreads Via' },
      { source: 'root', target: 'tor_onion', label: 'Demands Ransom' }
    ]
  },
  {
    name: 'Cobalt Strike APT41 Infrastructure',
    root: '198.54.117.200',
    nodes: [
      { id: 'root', label: '198.54.117.200 (C2 TeamServer)', type: 'ip', verdict: 'malicious', threatScore: 96, details: 'Cobalt Strike 4.8 malleable C2 server hosting DNS stagers and HTTPS beacons.', x: 0, y: 0, radius: 24, color: '#fb923c', tags: ['apt41', 'cobalt-strike', 'c2'] },
      { id: 'stager_dll', label: 'beacon.x64.dll', type: 'file', verdict: 'malicious', threatScore: 95, details: 'Reflective DLL injected into unmanaged memory space via process hollowing.', x: -150, y: -80, radius: 18, color: '#ff2a5f' },
      { id: 'domain1', label: 'update-microsoft-cloud.live', type: 'domain', verdict: 'malicious', threatScore: 90, details: 'Fast-flux domain spoofing legitimate Microsoft telemetry.', x: 140, y: -90, radius: 17, color: 'var(--brand-ember)' },
      { id: 'mitre1', label: 'T1055 (Process Injection)', type: 'mitre', verdict: 'malicious', threatScore: 85, details: 'Reflective DLL injection into svchost.exe.', x: -140, y: 100, radius: 15, color: '#eab308' },
      { id: 'mitre2', label: 'T1071.001 (Web Protocols)', type: 'mitre', verdict: 'malicious', threatScore: 80, details: 'HTTPS beaconing with jittered heartbeat.', x: 120, y: 110, radius: 15, color: '#eab308' },
      { id: 'cert', label: 'Let\'s Encrypt TLS (Thumbprint: a89f..)', type: 'whois', verdict: 'suspicious', threatScore: 50, details: 'Automated TLS certificate issued 2 days prior to active campaign.', x: 0, y: -160, radius: 14, color: '#38bdf8' }
    ],
    links: [
      { source: 'root', target: 'stager_dll', label: 'Hosts Stager' },
      { source: 'root', target: 'domain1', label: 'Resolves Domain' },
      { source: 'root', target: 'mitre1', label: 'Employs' },
      { source: 'root', target: 'mitre2', label: 'Communicates' },
      { source: 'root', target: 'cert', label: 'Secured By' }
    ]
  }
];

export const ThreatGraph: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const initialQuery = searchParams.get('q') || '';

  const [targetInput, setTargetInput] = useState(initialQuery);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [filterType, setFilterType] = useState<string>('all');
  const [physicsRunning, setPhysicsRunning] = useState(true);

  // Nodes & Links state
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [links, setLinks] = useState<GraphLink[]>([]);

  // Canvas viewport state
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const transformRef = useRef<{ x: number; y: number; k: number }>({ x: 450, y: 320, k: 1 });
  const isDraggingRef = useRef(false);
  const dragStartRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const draggedNodeRef = useRef<GraphNode | null>(null);
  const animFrameRef = useRef<number | null>(null);

  // ── Load Preset or Live Search ────────────────────────────────────────────
  const loadPreset = useCallback((presetIdx: number) => {
    const p = PRESET_CLUSTERS[presetIdx];
    const initialNodes: GraphNode[] = p.nodes.map(n => ({
      ...n,
      vx: (Math.random() - 0.5) * 2,
      vy: (Math.random() - 0.5) * 2,
      targetLink: n.type === 'file' ? `/file/${n.id === 'root' ? p.root : n.label.split(' ')[0]}`
                : n.type === 'ip' ? `/ip/${n.label.split(' ')[0]}`
                : n.type === 'domain' ? `/domain/${n.label.split(' ')[0]}`
                : undefined
    }));
    setNodes(initialNodes);
    setLinks(p.links);
    setSelectedNode(initialNodes[0]);
    transformRef.current = { x: 450, y: 320, k: 1 };
  }, []);

  // Live relationship discovery query
  const searchTargetGraph = useCallback(async (queryStr: string) => {
    const q = queryStr.trim();
    if (!q) return;

    setErrorMsg(null);
    setLoading(true);
    const inType = detectInputType(q);
    const centerNode: GraphNode = {
      id: 'root',
      label: q,
      type: inType === 'hash' ? 'file' : inType === 'ip' ? 'ip' : inType === 'domain' ? 'domain' : 'url',
      verdict: 'unknown',
      threatScore: 0,
      details: `Primary investigation pivot for ${q}`,
      x: 0,
      y: 0,
      vx: 0,
      vy: 0,
      radius: 24,
      color: 'var(--brand)',
      targetLink: inType === 'hash' ? `/file/${q}` : inType === 'ip' ? `/ip/${q}` : inType === 'domain' ? `/domain/${q}` : `/url/${q}`
    };

    const newNodes: GraphNode[] = [centerNode];
    const newLinks: GraphLink[] = [];

    try {
      const apiKey = import.meta.env.VITE_VT_API_KEY || '';
      const backendBase = getBackendBase();

      // Helper: proxy VT GET through backend to avoid browser CORS blocks
      const vtProxy = async (vtPath: string) => {
        const r = await fetch(`${backendBase}/api/vt/proxy?path=${encodeURIComponent(vtPath)}`, {
          headers: apiKey ? { 'x-apikey': apiKey } : {},
        });
        if (!r.ok) return null;
        return r.json();
      };

      if (inType === 'domain' || inType === 'ip') {
        const typeParam = inType === 'domain' ? 'domains' : 'ip_addresses';
        const json = await vtProxy(`/${typeParam}/${encodeURIComponent(q)}/resolutions?limit=8`);
        if (json?.data && Array.isArray(json.data)) {
          json.data.forEach((r: any, idx: number) => {
            const ip = r.attributes?.ip_address || r.id;
            if (ip && ip !== q) {
              const angle = (idx / json.data.length) * Math.PI * 2;
              const distance = 140 + Math.random() * 40;
              newNodes.push({
                id: `res_${idx}`,
                label: ip,
                type: 'ip',
                verdict: (r.attributes?.last_analysis_stats?.malicious || 0) > 0 ? 'malicious' : 'clean',
                threatScore: (r.attributes?.last_analysis_stats?.malicious || 0) * 10,
                details: `Resolved IP address from DNS history (Recorded: ${r.attributes?.date ? new Date(r.attributes.date * 1000).toLocaleDateString() : 'N/A'})`,
                x: Math.cos(angle) * distance,
                y: Math.sin(angle) * distance,
                vx: 0,
                vy: 0,
                radius: 16,
                color: '#fb923c',
                targetLink: `/ip/${ip}`
              });
              newLinks.push({ source: 'root', target: `res_${idx}`, label: 'Resolves To' });
            }
          });
        }
      } else if (inType === 'hash') {
        const json = await vtProxy(`/files/${encodeURIComponent(q)}/contacted_ips?limit=8`);
        if (json?.data && Array.isArray(json.data)) {
          json.data.forEach((r: any, idx: number) => {
            const ip = r.id;
            const angle = (idx / json.data.length) * Math.PI * 2;
            const distance = 140 + Math.random() * 40;
            newNodes.push({
              id: `cip_${idx}`,
              label: ip,
              type: 'ip',
              verdict: (r.attributes?.last_analysis_stats?.malicious || 0) > 0 ? 'malicious' : 'clean',
              threatScore: (r.attributes?.last_analysis_stats?.malicious || 0) * 10,
              details: `Network egress connection from dynamic execution sandbox (${r.attributes?.country || 'Unknown Country'})`,
              x: Math.cos(angle) * distance,
              y: Math.sin(angle) * distance,
              vx: 0,
              vy: 0,
              radius: 16,
              color: '#fb923c',
              targetLink: `/ip/${ip}`
            });
            newLinks.push({ source: 'root', target: `cip_${idx}`, label: 'Network Contact' });
          });
        }
      }

    } catch (err: any) {
      if (import.meta.env.DEV) console.error(err);
      setErrorMsg('Failed to discover relationships for ' + q);
      setNodes([]);
      setLinks([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Defer the call out of the synchronous effect to avoid cascading renders
    const id = setTimeout(() => {
      if (initialQuery) {
        searchTargetGraph(initialQuery);
      } else {
        loadPreset(0);
      }
    }, 0);
    return () => clearTimeout(id);
  }, [initialQuery, searchTargetGraph, loadPreset]);

  // ── Physics Simulation Step ───────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let running = true;

    const tick = () => {
      if (physicsRunning) {
        setNodes(prevNodes => {
          const updated = prevNodes.map(n => ({ ...n }));
          const kRepel = 1600;
          const kSpring = 0.04;
          const damp = 0.88;

          // 1. Repulsion between all node pairs
          for (let i = 0; i < updated.length; i++) {
            for (let j = i + 1; j < updated.length; j++) {
              const a = updated[i];
              const b = updated[j];
              const dx = b.x - a.x;
              const dy = b.y - a.y;
              const dist = Math.sqrt(dx * dx + dy * dy) || 1;
              if (dist < 350) {
                const force = (kRepel / (dist * dist)) * (dist < 80 ? 2.5 : 1);
                const fx = (dx / dist) * force;
                const fy = (dy / dist) * force;
                a.vx -= fx;
                a.vy -= fy;
                b.vx += fx;
                b.vy += fy;
              }
            }
          }

          // 2. Spring attraction along links
          links.forEach(l => {
            const source = updated.find(n => n.id === l.source);
            const target = updated.find(n => n.id === l.target);
            if (source && target) {
              const dx = target.x - source.x;
              const dy = target.y - source.y;
              const dist = Math.sqrt(dx * dx + dy * dy) || 1;
              const targetDist = 130;
              const force = (dist - targetDist) * kSpring;
              const fx = (dx / dist) * force;
              const fy = (dy / dist) * force;
              source.vx += fx;
              source.vy += fy;
              target.vx -= fx;
              target.vy -= fy;
            }
          });

          // 3. Center gravity pull
          updated.forEach(n => {
            if (n !== draggedNodeRef.current) {
              n.vx -= n.x * 0.008;
              n.vy -= n.y * 0.008;
              n.vx *= damp;
              n.vy *= damp;
              n.x += n.vx;
              n.y += n.vy;
            }
          });

          return updated;
        });
      }

      // ── Render Frame ──────────────────────────────────────────────────────
      const dpr = window.devicePixelRatio || 1;
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
        canvas.width = width * dpr;
        canvas.height = height * dpr;
      }

      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, width, height);

      // Apply Pan & Zoom Transform
      const { x: panX, y: panY, k: scale } = transformRef.current;
      ctx.translate(panX, panY);
      ctx.scale(scale, scale);

      // Draw Links
      links.forEach(l => {
        const source = nodes.find(n => n.id === l.source);
        const target = nodes.find(n => n.id === l.target);
        if (source && target) {
          ctx.beginPath();
          ctx.moveTo(source.x, source.y);
          ctx.lineTo(target.x, target.y);
          ctx.strokeStyle = 'rgba(129, 140, 248, 0.25)';
          ctx.lineWidth = 1.5;
          ctx.stroke();

          // Link label
          const midX = (source.x + target.x) / 2;
          const midY = (source.y + target.y) / 2;
          ctx.font = '9px monospace';
          ctx.fillStyle = '#64748b';
          ctx.textAlign = 'center';
          ctx.fillText(l.label, midX, midY - 4);
        }
      });

      // Draw Nodes
      nodes.forEach(n => {
        if (filterType !== 'all' && n.type !== filterType) return;

        const isSelected = selectedNode?.id === n.id;

        // Outer glow
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius + 8, 0, Math.PI * 2);
        ctx.fillStyle = isSelected ? `${n.color}40` : `${n.color}15`;
        ctx.fill();

        // Main Node Body
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.fillStyle = n.color;
        ctx.fill();
        ctx.strokeStyle = isSelected ? '#ffffff' : 'rgba(0,0,0,0.6)';
        ctx.lineWidth = isSelected ? 2.5 : 1.5;
        ctx.stroke();

        // Node Label
        ctx.font = isSelected ? 'bold 12px monospace' : '11px monospace';
        ctx.fillStyle = isSelected ? '#ffffff' : '#cbd5e1';
        ctx.textAlign = 'center';
        const displayLabel = n.label.length > 24 ? n.label.slice(0, 22) + '...' : n.label;
        ctx.fillText(displayLabel, n.x, n.y + n.radius + 14);
      });

      ctx.restore();

      if (running) {
        animFrameRef.current = requestAnimationFrame(tick);
      }
    };

    animFrameRef.current = requestAnimationFrame(tick);

    return () => {
      running = false;
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [links, nodes, filterType, physicsRunning, selectedNode]);

  // ── Canvas Interaction Handlers ───────────────────────────────────────────
  const getCanvasCoords = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return { x: 0, y: 0 };
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    const { x: panX, y: panY, k: scale } = transformRef.current;
    return {
      x: (mouseX - panX) / scale,
      y: (mouseY - panY) / scale
    };
  };

  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const { x, y } = getCanvasCoords(e);
    const clickedNode = nodes.find(n => {
      const dx = n.x - x;
      const dy = n.y - y;
      return Math.sqrt(dx * dx + dy * dy) <= n.radius + 5;
    });

    if (clickedNode) {
      draggedNodeRef.current = clickedNode;
      setSelectedNode(clickedNode);
    } else {
      isDraggingRef.current = true;
      dragStartRef.current = { x: e.clientX, y: e.clientY };
    }
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (draggedNodeRef.current) {
      const { x, y } = getCanvasCoords(e);
      draggedNodeRef.current.x = x;
      draggedNodeRef.current.y = y;
    } else if (isDraggingRef.current) {
      const dx = e.clientX - dragStartRef.current.x;
      const dy = e.clientY - dragStartRef.current.y;
      dragStartRef.current = { x: e.clientX, y: e.clientY };
      transformRef.current.x += dx;
      transformRef.current.y += dy;
    }
  };

  const handleMouseUp = () => {
    draggedNodeRef.current = null;
    isDraggingRef.current = false;
  };

  const handleWheel = useCallback((e: WheelEvent) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
    const newScale = Math.min(3, Math.max(0.3, transformRef.current.k * zoomFactor));
    transformRef.current.k = newScale;
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (canvas) {
      canvas.addEventListener('wheel', handleWheel, { passive: false });
    }
    return () => {
      if (canvas) {
        canvas.removeEventListener('wheel', handleWheel);
      }
    };
  }, [handleWheel]);

  return (
    <div style={{ position: 'relative', minHeight: '100vh', paddingTop: '70px', background: '#0b111e', color: '#c3c8d4' }}>
      <SEO title="Threat Graph & Infrastructure Visualizer" description="Interactive threat relationship graph connecting malware hashes, domains, and IPs." path="/threat-graph" />
      

      {/* ── TOP CONTROL HEADER ────────────────────────────────────────────── */}
      <div style={{ borderBottom: '1px solid #1e293b', background: '#111927', padding: '16px 24px', position: 'relative', zIndex: 20 }}>
        <div style={{ maxWidth: '1400px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          
          {/* Title & Badge */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span className="material-symbols-outlined" style={{ color: '#818cf8', fontSize: '28px' }}>hub</span>
            <div>
              <h1 style={{ margin: 0, fontSize: '18px', fontWeight: 800, color: '#f1f5f9' }}>
                3D Threat Graph & Infrastructure Visualizer
              </h1>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                Force-directed entity mapping: C2 nodes, DNS resolutions, files & MITRE ATT&CK®
              </div>
            </div>
          </div>

          {/* Search Bar */}
          <form
            onSubmit={(e) => { e.preventDefault(); searchTargetGraph(targetInput); }}
            style={{ display: 'flex', gap: '8px', flex: 1, maxWidth: '480px' }}
          >
            <div style={{ position: 'relative', width: '100%' }}>
              <span className="material-symbols-outlined" style={{ position: 'absolute', left: '12px', top: '10px', color: '#64748b', fontSize: '18px' }}>search</span>
              <input
                type="text"
                placeholder="Enter IP, Domain, Hash, or C2 endpoint..."
                value={targetInput}
                onChange={e => setTargetInput(e.target.value)}
                style={{
                  width: '100%',
                  padding: '9px 12px 9px 38px',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  color: '#ffffff',
                  fontSize: '13px',
                  fontFamily: 'var(--font-mono)'
                }}
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              style={{
                padding: '0 18px',
                background: 'linear-gradient(135deg, #818cf8, var(--brand-ember))',
                border: 'none',
                borderRadius: '8px',
                color: '#ffffff',
                fontWeight: 700,
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                cursor: 'pointer'
              }}
            >
              {loading ? 'ANALYZING...' : 'PIVOT'}
            </button>
          </form>

          {/* Preset Clusters Selector */}
          <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>DEMOS:</span>
            {PRESET_CLUSTERS.map((p, idx) => (
              <button
                key={p.name}
                type="button"
                onClick={() => loadPreset(idx)}
                style={{
                  padding: '6px 12px',
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: '1px solid #334155',
                  borderRadius: '6px',
                  color: '#cbd5e1',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  cursor: 'pointer'
                }}
                title={`Load ${p.name}`}
              >
                {p.name}
              </button>
            ))}
          </div>

        </div>
        {errorMsg && (
          <div style={{ padding: '8px 12px', background: 'rgba(255, 42, 95, 0.1)', border: '1px solid var(--secondary)', color: 'var(--secondary)', borderRadius: '6px', fontSize: '12px', marginTop: '12px', textAlign: 'center' }}>
            {errorMsg}
          </div>
        )}
      </div>

      {/* ── MAIN WORKSPACE (CANVAS + SIDEBAR) ──────────────────────────────── */}
      <div style={{ position: 'relative', width: '100%', height: 'calc(100vh - 145px)', overflow: 'hidden' }}>
        
        {/* Canvas */}
        <canvas
          ref={canvasRef}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          style={{ width: '100%', height: '100%', cursor: 'grab', background: '#080d16' }}
        />

        {/* Floating Canvas Controls */}
        <div style={{ position: 'absolute', top: '16px', left: '16px', display: 'flex', flexDirection: 'column', gap: '8px', zIndex: 10 }}>
          {/* Zoom Buttons */}
          <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '8px', padding: '4px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <button
              onClick={() => { transformRef.current.k = Math.min(3, transformRef.current.k * 1.2); }}
              title="Zoom In"
              style={{ background: 'none', border: 'none', color: '#94a3b8', padding: '6px', cursor: 'pointer', borderRadius: '4px' }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>add</span>
            </button>
            <button
              onClick={() => { transformRef.current.k = Math.max(0.3, transformRef.current.k * 0.8); }}
              title="Zoom Out"
              style={{ background: 'none', border: 'none', color: '#94a3b8', padding: '6px', cursor: 'pointer', borderRadius: '4px' }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>remove</span>
            </button>
            <button
              onClick={() => { transformRef.current = { x: 450, y: 320, k: 1 }; }}
              title="Reset View"
              style={{ background: 'none', border: 'none', color: '#94a3b8', padding: '6px', cursor: 'pointer', borderRadius: '4px' }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>filter_center_focus</span>
            </button>
            <button
              onClick={() => setPhysicsRunning(p => !p)}
              title={physicsRunning ? 'Pause Physics' : 'Resume Physics'}
              style={{ background: 'none', border: 'none', color: physicsRunning ? '#00ffa3' : 'var(--primary)', padding: '6px', cursor: 'pointer', borderRadius: '4px' }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>{physicsRunning ? 'pause' : 'play_arrow'}</span>
            </button>
          </div>

          {/* Node Filter Pill */}
          <div style={{ background: '#111927', border: '1px solid #1e293b', borderRadius: '8px', padding: '6px 10px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ fontSize: '10px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Filter Nodes:</div>
            {['all', 'file', 'ip', 'domain', 'mitre'].map(t => (
              <button
                key={t}
                onClick={() => setFilterType(t)}
                style={{
                  background: filterType === t ? 'rgba(129,140,248,0.2)' : 'none',
                  border: filterType === t ? '1px solid #818cf8' : 'none',
                  color: filterType === t ? '#818cf8' : '#94a3b8',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  cursor: 'pointer',
                  textAlign: 'left'
                }}
              >
                {t.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {/* Legend */}
        <div style={{ position: 'absolute', bottom: '16px', left: '16px', background: 'rgba(17, 25, 39, 0.9)', border: '1px solid #1e293b', borderRadius: '8px', padding: '10px 14px', zIndex: 10, display: 'flex', gap: '14px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#ff2a5f' }}></span> File / Hash</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#fb923c' }}></span> IP Address</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><span style={{ width: '10px', height: '10px', borderRadius: '50%', background: 'var(--brand-ember)' }}></span> Domain / Host</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#eab308' }}></span> MITRE ATT&CK</div>
        </div>

        {/* ── NODE INSPECTOR SIDEBAR ────────────────────────────────────────── */}
        {selectedNode && (
          <div style={{
            position: 'absolute',
            top: '16px',
            right: '16px',
            width: '360px',
            maxHeight: 'calc(100% - 32px)',
            background: '#111927',
            border: '1px solid #1e293b',
            borderRadius: '12px',
            padding: '24px',
            boxShadow: '0 20px 50px rgba(0,0,0,0.8)',
            zIndex: 20,
            overflowY: 'auto',
            animation: 'fadeInRight 0.2s ease'
          }}>
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '14px', marginBottom: '16px' }}>
              <div>
                <span style={{
                  background: `${selectedNode.color}20`,
                  border: `1px solid ${selectedNode.color}40`,
                  color: selectedNode.color,
                  padding: '2px 8px',
                  borderRadius: '4px',
                  fontSize: '10px',
                  fontWeight: 800,
                  fontFamily: 'var(--font-mono)'
                }}>
                  {selectedNode.type.toUpperCase()} NODE
                </span>
                <h3 style={{ margin: '8px 0 0', fontSize: '15px', fontWeight: 700, color: '#f1f5f9', wordBreak: 'break-all' }}>
                  {selectedNode.label}
                </h3>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', padding: 0 }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: '20px' }}>close</span>
              </button>
            </div>

            {/* Threat Badge */}
            {selectedNode.threatScore !== undefined && (
              <div style={{ marginBottom: '16px', padding: '12px', borderRadius: '8px', background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.04)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '12px', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>Threat Assessment:</span>
                <span style={{
                  color: selectedNode.verdict === 'malicious' ? '#ff2a5f' : selectedNode.verdict === 'suspicious' ? '#fb923c' : '#00ffa3',
                  fontWeight: 800,
                  fontSize: '12px',
                  fontFamily: 'var(--font-mono)'
                }}>
                  {selectedNode.threatScore}/100 ({selectedNode.verdict?.toUpperCase() || 'EVALUATED'})
                </span>
              </div>
            )}

            {/* Details */}
            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', marginBottom: '4px' }}>
                Intelligence Dossier
              </div>
              <div style={{ fontSize: '13px', color: '#cbd5e1', lineHeight: 1.5 }}>
                {selectedNode.details || 'No extended intelligence recorded for this node.'}
              </div>
            </div>

            {/* Tags */}
            {selectedNode.tags && selectedNode.tags.length > 0 && (
              <div style={{ marginBottom: '20px' }}>
                <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', marginBottom: '6px' }}>
                  Threat Tags
                </div>
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                  {selectedNode.tags.map(t => (
                    <span key={t} style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)', color: '#94a3b8', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                      #{t}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Action Buttons */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {selectedNode.targetLink && (
                <button
                  onClick={() => navigate(selectedNode.targetLink!)}
                  style={{
                    width: '100%',
                    padding: '10px',
                    background: 'linear-gradient(135deg, var(--brand), var(--brand-ember))',
                    border: 'none',
                    borderRadius: '8px',
                    color: '#0b111e',
                    fontWeight: 700,
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '6px'
                  }}
                >
                  <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>radar</span>
                  LAUNCH FULL MULTI-ENGINE ANALYSIS
                </button>
              )}

              <button
                onClick={() => {
                  searchTargetGraph(selectedNode.label);
                }}
                style={{
                  width: '100%',
                  padding: '9px',
                  background: 'rgba(255,255,255,0.04)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '8px',
                  color: '#f1f5f9',
                  fontWeight: 600,
                  fontSize: '12px',
                  fontFamily: 'var(--font-mono)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '6px'
                }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>account_tree</span>
                EXPAND NODE RELATIONSHIPS
              </button>
            </div>

          </div>
        )}

      </div>
    </div>
  );
};
