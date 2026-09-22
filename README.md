<div align="center">

<img src="frontend/public/images/logo.png" alt="ThreatAtlas Logo" width="120" />

# ThreatAtlas v2.0

**Free & Open-Source Cyber Threat Intelligence Platform**

[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](./LICENSE)
[![Powered by VirusTotal](https://img.shields.io/badge/Powered%20by-VirusTotal-blue.svg)](https://www.virustotal.com)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)](https://threatatlas.luckyverse.tech)
[![Frontend](https://img.shields.io/badge/Frontend-Local-black.svg)](https://react.dev)
[![Backend](https://img.shields.io/badge/Backend-Local-46E3B7.svg)](https://nodejs.org)
**[🌐 Local Server → http://localhost:3002](http://localhost:3002)**

</div>

---

ThreatAtlas is a full-stack cybersecurity threat intelligence platform that lets you analyze files, URLs, IP addresses, domains, and hashes against **90+ security engines** — instantly and for free. Built on React + TypeScript (frontend) and Node.js/Express (backend), powered by the VirusTotal Public API v3.

---

## ✨ Features

### 🔍 Core Scanners
| Scanner | Description |
|---------|-------------|
| **File Scanner** | Upload any file up to 32 MB for multi-engine AV analysis |
| **URL Scanner** | Detect phishing, malware, and malicious redirects |
| **IP Intelligence** | Geolocation, ASN, WHOIS, and 90+ engine verdicts |
| **Domain Lookup** | Registrar info, DNS records, reputation scores |
| **Hash Lookup** | Instant results for SHA-256, SHA-1, MD5 |
| **Bulk IOC Hunter** | Scan multiple indicators of compromise at once |

### 🕵️ WebFox — Website Recon Engine
- DNS Records (A, AAAA, MX, TXT, NS, SOA)
- WHOIS & domain age analysis
- SSL/TLS certificate inspection
- WAF detection (23 vendors including Cloudflare, Akamai, AWS)
- Security headers grading (CSP, HSTS, X-Frame-Options, etc.)
- Tech stack fingerprinting
- Subdomain enumeration (crt.sh + HackerTarget + AlienVault OTX)
- Sitemap & robots.txt crawler
- JavaScript secret scanner (API keys, tokens, JWT)

### 🎣 PhishGuard — Phishing Detection Engine
- Homograph / IDN attack detection
- Brand impersonation detection (50+ brands)
- Entropy-based URL analysis
- Typosquatting detection via Levenshtein distance
- OpenPhish live blacklist integration
- Suspicious TLD & pattern analysis
- URL redirect chain unwinding
- Punycode decoding

### 🔬 Forensics Suite
| Module | Capability |
|--------|-----------|
| **Image Forensics** | EXIF metadata, GPS coordinates, steganography (LSB) |
| **PDF Forensics** | Embedded JS detection, OpenAction, launch actions, macros |
| **PE Executable** | Section analysis, imports, entropy, rich header |
| **ELF Executable** | Section headers, dynamic symbols, libraries |
| **APK Forensics** | Manifest, permissions, certificates, string analysis |
| **Archive Forensics** | ZIP/RAR/7z inspection, file listing |
| **Email Forensics** | Header analysis, SPF/DKIM/DMARC, routing path |
| **PCAP Forensics** | Network capture inspection |
| **Video/Audio** | FFprobe metadata extraction |
| **Document** | Office document analysis |

### 🧠 AI & Intelligence
- **Atlas AI Chatbot** — Contextual cybersecurity assistant (Powered by Atlas AI LLaMA-3.3-70B)
- **AI Summary** — Automatic threat verdict generation grounded in scan facts
- **Threat Graph** — Force-directed visualization of threat relationships
- **YARA Scanner** — Rule-based pattern matching
- **CyberChef** — Embedded encoding/decoding toolkit

### 📊 Platform
- Persistent scan history with JSON/CSV export
- One-click PDF report generation
- Community comments from VirusTotal
- Real-time polling with progress feedback
- Animated threat score gauge (0–100)
- Per-engine breakdown with filtering

---

## 🏗️ Architecture

```
ThreatAtlas/
├── frontend/                   # React + TypeScript + Vite
│   ├── src/
│   │   ├── components/         # 40+ UI components
│   │   ├── pages/              # 16 route pages
│   │   ├── services/           # API, cache, history, forensics engines
│   │   ├── utils/              # PDF export, input sanitization
│   │   └── workers/            # Steganography web worker
│   ├── public/                 # Static assets, favicon, robots.txt
│   └── .env.example            # Required env vars
│
└── backend/                    # Node.js + Express + TypeScript
    ├── src/
    │   └── server.ts           # All API routes + keepalive ping
    └── .env.example            # Required env vars
```

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend Framework** | React 18 + TypeScript |
| **Build Tool** | Vite 5 |
| **Animations** | Framer Motion |
| **Icons** | Lucide React |
| **PDF Export** | jsPDF |
| **EXIF Parsing** | exifr |
| **Backend** | Node.js + Express 5 |
| **Media Analysis** | fluent-ffmpeg |
| **PDF Analysis** | pdf-parse |
| **WHOIS** | whois-json |
| **AI Chatbot** | Atlas AI API (LLaMA-3.3-70B) |
| **Threat Intel** | VirusTotal Public API v3 |
| **Phishing Intel** | OpenPhish feed |

---

## 🚀 Getting Started

### Prerequisites
- Node.js 18+
- npm 9+
- A [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) (free)
- An Atlas AI / [Groq API key](https://console.groq.com/keys) (free, optional — for AI features)

### Clone & Install

```bash
git clone https://github.com/lucky-om/ThreatAtlas.git
cd ThreatAtlas

# Install all dependencies (root + frontend + backend)
npm run install:all
```

### Configure Environment

**Frontend** — create `frontend/.env`:
```env
VITE_VT_API_KEY=your_virustotal_api_key
VITE_API_BASE_URL=http://localhost:3001
```

**Backend** — create `backend/.env`:
```env
PORT=3001
VT_API_KEY=your_virustotal_api_key
ATLAS_API_KEY=your_atlas_api_key   # optional
```

### Run Locally

```bash
# Run both frontend + backend simultaneously
npm run dev

# Frontend only (port 3002)
npm run dev:frontend

# Backend only (port 3001)
npm run dev:backend
```

Open **http://localhost:3002** in your browser.

---

## 🌍 Deployment

ThreatAtlas is designed to run securely on your **Local Machine**. This keeps your API keys entirely on your own hardware.

### Running Locally

1. Navigate to the project root.
2. Start both frontend and backend simultaneously: `npm run dev`
3. Access the frontend at `http://localhost:3002`.

---

## 🔐 Security

See [SECURITY.md](./SECURITY.md) for the full vulnerability disclosure policy.

**Key practices:**
- All API keys stored in environment variables — never hardcoded
- Input sanitization via `sanitizeInput()` / `sanitizeUrl()` before all API calls
- HTML output escaping throughout rendering pipeline
- `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options` headers
- No persistent cookies — scan history stored in `localStorage` only
- Uploaded files auto-deleted from server after processing

---

## 📄 Pages & Routes

| Route | Page |
|-------|------|
| `/` | Home — main scanner hub |
| `/file` | File Scanner |
| `/url` | URL Scanner |
| `/search` | Hash / Domain / IP Search |
| `/webscan` | WebFox Website Recon |
| `/ip-intelligence` | IP Geolocation & Intel |
| `/threat-graph` | Threat Relationship Graph |
| `/ioc-hunter` | Bulk IOC Scanner |
| `/yara` | YARA Rule Scanner |
| `/file/:hash` | File Analysis Results |
| `/url/:id` | URL Analysis Results |
| `/domain/:query` | Domain Analysis Results |
| `/ip-address/:query` | IP Analysis Results |
| `/about` | About ThreatAtlas |
| `/privacy` | Privacy Policy |
| `/terms` | Terms & Conditions |
| `/rules` | API Rules & Fair Use |
| `/contact` | Contact |

---

## 🗺️ Roadmap

- [x] VirusTotal multi-engine scanning (file, URL, IP, domain, hash)
- [x] WebFox website recon engine
- [x] PhishGuard phishing detection
- [x] Full forensics suite (image, PDF, PE, ELF, APK, email, media)
- [x] Atlas AI chatbot & AI-powered summaries
- [x] Threat graph visualization
- [x] YARA rule scanner
- [x] Bulk IOC hunter
- [x] PDF report export
- [x] Persistent scan history
- [ ] VirusTotal Enterprise API support
- [ ] MITRE ATT&CK technique mapping
- [ ] Malware family clustering
- [ ] Threat hunting notebooks
- [ ] API endpoint for programmatic access

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'feat: your feature description'`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request

Please read [SECURITY.md](./SECURITY.md) before submitting security-related changes.

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](./LICENSE) file for details.

---

## 🙏 Acknowledgements

- [VirusTotal](https://www.virustotal.com) — Multi-engine threat intelligence infrastructure
- [Groq](https://groq.com) — Ultra-fast LLM inference for Atlas AI
- [OpenPhish](https://openphish.com) — Community phishing intelligence feed
- [Lucide](https://lucide.dev) — Beautiful open-source icon library
- [Framer Motion](https://www.framer.com/motion/) — Fluid React animations
- Security community worldwide — for making threat intelligence a public good

---

<p align="center">
  Built with ❤️ for defenders everywhere &nbsp;·&nbsp;
  <a href="https://threatatlas.luckyverse.tech">threatatlas.luckyverse.tech</a>
</p>
