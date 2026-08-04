# ThreatAtlas

> **Free Threat Intelligence Platform — threatatlas.luckyverse.tech**

[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](./LICENSE)
[![Powered by VirusTotal](https://img.shields.io/badge/Powered%20by-VirusTotal-blue.svg)](https://www.virustotal.com)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)](https://threatatlas.luckyverse.tech)

ThreatAtlas is a cybersecurity threat intelligence platform that lets you analyze files, URLs, IP addresses, domains, and cryptographic hashes against **90+ security engines** — instantly and for free. Built as a purpose-designed interface over the VirusTotal Public API v3.

---

## Features

- **File Analysis** — Upload any file up to 32MB for multi-engine antivirus scanning
- **URL Scanner** — Check URLs for phishing, malware, and malicious redirects
- **IP Intelligence** — Geolocation, ASN data, and 90+ engine verdicts for any IP
- **Domain Lookup** — Registrar info, reputation scores, and historical scan data
- **Hash Lookup** — Instant results for SHA256, SHA1, and MD5 hashes — no re-upload needed
- **Real-time Polling** — Automatically polls for analysis completion with progress feedback
- **Threat Score Gauge** — Visual SVG gauge showing threat severity (0–100)
- **Engine Breakdown** — Per-vendor detection results with filtering (detected/clean/timeout)
- **Rate Limit Awareness** — Built-in client-side rate limiting and retry handling
- **Responsive Design** — Works on desktop, tablet, and mobile
- **No Registration Required** — Start scanning immediately, no account needed

## Pages

| Page | URL | Description |
|------|-----|-------------|
| Home / Scanner | `/` | Main scanner with file upload, URL/IP/domain/hash input |
| Scan Results | `/results.html` | Detailed analysis report for a file or URL |
| IP & Domain Lookup | `/lookup.html` | Intelligence lookup for IPs and domains |
| About | `/about.html` | Platform info, API details, mission |
| Privacy Policy | `/privacy.html` | Data handling and GDPR information |
| Terms & Conditions | `/terms.html` | Usage terms and legal disclaimers |
| Rules & Regulations | `/rules.html` | API rules, rate limits, acceptable use policy |
| 404 | `/404.html` | Custom error page with built-in quick-scan |
| Sitemap | `/sitemap.xml` | XML sitemap for search engines |
| Robots | `/robots.txt` | Crawler rules |

## Project Structure

```
threatatlas/
├── index.html          # Home page + scanner
├── results.html        # Scan results page
├── lookup.html         # IP & domain lookup
├── about.html          # About page
├── privacy.html        # Privacy policy
├── terms.html          # Terms & conditions
├── rules.html          # API rules & regulations
├── 404.html            # Custom 404 error page
├── sitemap.xml         # XML sitemap
├── robots.txt          # Crawler rules
├── LICENSE             # MIT License
├── SECURITY.md         # Security policy & vulnerability disclosure
├── README.md           # This file
└── assets/
    ├── css/
    │   └── main.css    # Global design system & all component styles
    └── js/
        ├── api.js      # VirusTotal API v3 client with rate limiting
        ├── ui.js       # UI component library (gauges, toasts, tables)
        └── main.js     # Home page controller
```

## Technology Stack

- **Frontend:** Vanilla HTML5, CSS3, JavaScript (ES6+)
- **Styling:** Custom CSS with design tokens — no frameworks
- **API:** [VirusTotal Public API v3](https://docs.virustotal.com/reference/overview)
- **Fonts:** Space Grotesk, IBM Plex Sans, JetBrains Mono (Google Fonts)
- **Hosting:** Static subdomain — `threatatlas.luckyverse.tech`

## Design System

ThreatAtlas uses a custom "threat intelligence operator" aesthetic:

| Token | Value | Usage |
|-------|-------|-------|
| Background | `#080d16` | Page background (deep space) |
| Surface | `#0f1925` | Cards and panels |
| Primary (Ember) | `#e8541a` | Brand, CTAs, danger indicators |
| Secondary (Teal) | `#00bfa0` | Clean/safe verdicts |
| Warning | `#f59e0b` | Suspicious indicators |
| Headline Font | Space Grotesk | H1–H4 |
| Body Font | IBM Plex Sans | Paragraphs and labels |
| Mono Font | JetBrains Mono | Hashes, IPs, code |

## API Configuration

ThreatAtlas uses the VirusTotal Public API. The API key is configured in `assets/js/api.js`.

**Public API Limits:**
- 4 requests per minute
- 500 requests per day
- 32 MB max file size

> **Security Note:** Do not commit API keys to public repositories. If deploying your own instance, move the API key to a server-side proxy or environment variable. See `SECURITY.md` for details.

## Getting Started (Local Development)

ThreatAtlas is a fully static site — no build tools or package managers required.

```bash
# Clone the repository
git clone https://github.com/yourusername/threatatlas.git
cd threatatlas

# Serve locally with any HTTP server
# Option 1: Python
python -m http.server 8080

# Option 2: Node.js
npx serve .

# Option 3: VS Code Live Server extension
# Open index.html and click "Go Live"
```

Open `http://localhost:8080` in your browser.

> **Note:** The VirusTotal API requires HTTPS in production. For local testing, the browser may block API calls due to mixed content policies. Use a local HTTPS server or browser extension if needed.

## Deployment

ThreatAtlas is designed for static hosting. Deploy to any web host:

- **Subdomain (recommended):** Upload all files to your subdomain's document root
- **GitHub Pages:** Push to a `gh-pages` branch and configure custom domain
- **Netlify / Vercel:** Drag and drop the directory or connect your repository
- **Apache / Nginx:** Copy files to your web root directory

### Nginx Configuration (recommended)

```nginx
server {
    listen 443 ssl http2;
    server_name threatatlas.luckyverse.tech;

    root /var/www/threatatlas;
    index index.html;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Custom 404
    error_page 404 /404.html;

    # Cache static assets
    location ~* \.(css|js|ico|woff2)$ {
        expires 7d;
        add_header Cache-Control "public, immutable";
    }

    location / {
        try_files $uri $uri.html $uri/ =404;
    }
}
```

## Security

See [SECURITY.md](./SECURITY.md) for our security policy, including how to report vulnerabilities.

Key security practices implemented:
- Content-Security-Policy headers on every page
- `X-Content-Type-Options: nosniff` on every page
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` restricting camera, microphone, geolocation
- No third-party tracking scripts
- sessionStorage only (no persistent cookies)
- Input sanitization via `escHtml()` in all UI rendering

## Roadmap

Future features planned for ThreatAtlas:

- [ ] AI-powered threat summarization (natural language descriptions of malware behavior)
- [ ] Threat graph visualization (related IPs, domains, files)
- [ ] Bulk hash checker (upload a list of hashes)
- [ ] Notification system for re-scan alerts
- [ ] Dark/light theme toggle
- [ ] WHOIS deep dive page
- [ ] Export reports as PDF
- [ ] Community voting on verdicts

## Contributing

Contributions are welcome! Please read `SECURITY.md` before submitting any security-related changes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add: your feature description'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License — see the [LICENSE](./LICENSE) file for details.

## Acknowledgements

- [VirusTotal](https://www.virustotal.com) — Multi-engine scanning infrastructure and API
- [Google Fonts](https://fonts.google.com) — Space Grotesk, IBM Plex Sans, JetBrains Mono
- Security community worldwide — for making threat intelligence a public good

---

<p align="center">
  Built with ❤️ for defenders everywhere · <a href="https://threatatlas.luckyverse.tech">threatatlas.luckyverse.tech</a>
</p>
