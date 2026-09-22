# Security Policy

## Overview

The ThreatAtlas team takes security seriously. This document describes our security policy, responsible disclosure process, and the security practices implemented across the v2.0 platform (React frontend + Node.js/Express backend).

---

## Supported Versions

| Version | Status |
|---------|--------|
| **v2.0** (current — `threatatlas.luckyverse.tech`) | ✅ Actively maintained |
| v1.x (legacy static HTML) | ❌ No longer supported |
| Forks / archived | ❌ Not supported |

Security patches are applied to the current live version only.

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.** Instead, use one of the following private disclosure channels:

### Preferred: GitHub Private Security Advisory
Use GitHub's [Private Security Advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) feature directly in this repository.

### Alternative: Email
Contact the maintainer via the email listed on the [GitHub profile](https://github.com/lucky-om).

### What to Include

| Field | Description |
|-------|-------------|
| **Description** | Clear description of the vulnerability |
| **Impact** | What an attacker could achieve |
| **Steps to Reproduce** | Detailed reproduction steps |
| **Proof of Concept** | Code, screenshots, or video (if applicable) |
| **Affected Component** | Frontend / Backend / API / specific file |
| **Suggested Fix** | Your recommended remediation (optional) |

---

## Response Timeline

| Stage | Target |
|-------|--------|
| Initial acknowledgement | Within 48 hours |
| Vulnerability assessment | Within 5 business days |
| Fix — Critical severity | Within 14 days |
| Fix — Medium / Low severity | Within 30 days |
| Public disclosure | After fix is deployed |

Reporters who follow coordinated disclosure will be credited in the fix commit (unless anonymity is requested). We follow the [OWASP Vulnerability Disclosure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html).

---

## Scope

### ✅ In Scope

- Cross-Site Scripting (XSS) in the frontend
- Content injection / HTML injection vulnerabilities
- Server-Side Request Forgery (SSRF) via backend proxy endpoints
- Information disclosure (e.g., API key leakage in responses)
- CORS misconfiguration exposing sensitive data
- Insecure Direct Object References (IDOR)
- CSRF vulnerabilities
- Clickjacking / UI redress attacks
- Security header misconfigurations
- Open redirects to malicious sites
- Path traversal in file upload endpoints
- Denial of service via file upload (bypassing size limits)
- Injection attacks (command, header, log)

### ❌ Out of Scope

- Vulnerabilities in VirusTotal's own API or infrastructure (report to VirusTotal directly)
- Rate limiting bypass at the VirusTotal infrastructure level
- Self-XSS requiring the victim to take multiple deliberate actions
- Social engineering / phishing attacks against users
- Physical security attacks
- Volumetric DoS/DDoS against hosting infrastructure
- Scanner result accuracy (determined by VirusTotal and third-party engines)
- Known vulnerabilities in dependencies with no available patch
- Issues already listed in **Known Security Considerations** below

---

## Security Architecture

### Frontend Security

The React frontend implements the following:

**Input Sanitization**
- All user input passes through `sanitizeInput()` and `sanitizeUrl()` in [`frontend/src/utils/sanitize.ts`](./frontend/src/utils/sanitize.ts) before any API calls
- Functions strip: `<script>` tags, HTML tags, dangerous URI schemes (`javascript:`, `data:`, `vbscript:`), and control characters (`\x00`–`\x1F`)
- All scan targets are validated and normalized before submission

**API Key Handling**
- The VirusTotal API key is stored in `VITE_VT_API_KEY` environment variable (never hardcoded)
- API calls to VirusTotal are made directly from the browser (VirusTotal supports browser CORS for the public API)
- The Groq AI key is stored in `VITE_GROQ_API_KEY` and only used for the optional AI chatbot feature
- Neither key is ever logged, stored in localStorage, or sent to our backend

**Storage**
- No persistent cookies
- Scan history stored in `localStorage` only (user-controlled, client-side only)
- Response cache stored in `localStorage` and in-memory Map — cleared on `clearCache()` call
- No server-side session or user data

### Backend Security

**CORS**
- CORS is natively unrestricted as this tool is designed for pure local environments.

```typescript
// backend/src/server.ts
app.use(cors({
  origin: '*', // Allow absolutely anything
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-apikey', 'Authorization', 'Access-Control-Allow-Private-Network']
}));
```

**File Upload Security**
- Multer enforces a hard **32 MB** file size limit (`LIMIT_FILE_SIZE` → HTTP 413)
- Uploaded files are stored in a temporary `uploads/` directory
- Files are **immediately deleted** after processing (EXIF extraction, PDF parsing, etc.)
- Cleanup runs in both the success and error paths via `fs.unlinkSync()`

**Proxy Endpoints**
- The `/api/ipgeo` endpoint proxies `ip-api.com` requests server-side (prevents client-side CORS leakage)
- The `/api/webfox/*` endpoints proxy DNS, WHOIS, and TLS operations that cannot run in the browser
- No user-controlled values are passed directly to OS-level commands

**Error Handling**
- Error responses never expose internal stack traces or file system paths in production
- All uncaught errors are handled by the global Express error middleware

### Dependency Security

```bash
# Run from /frontend or /backend to check for vulnerabilities
npm audit
```

Dependencies are kept minimal and reviewed regularly. The project avoids transitive dependencies where possible.

---

## Known Security Considerations

| Item | Severity | Status | Notes |
|------|----------|--------|-------|
| VT API key in browser env var (`VITE_VT_API_KEY`) | ℹ️ Low | By design | This is a public VirusTotal API key. Vite bakes `VITE_*` vars into the JS bundle. Only use a free public API key — never a premium key. |
| Groq API key in browser env var (`VITE_GROQ_API_KEY`) | ⚠️ Medium | By design | The chatbot is an optional feature. If concerned, proxy Groq calls through the backend instead. |
| `ip-api.com` free tier rate limits | ℹ️ Info | By design | Our backend proxy handles rate limits gracefully; results are cached client-side for 10 min. |
| File upload stored on server briefly | ℹ️ Low | Mitigated | Files are deleted immediately after processing in both success and error paths. |

---

## Security Best Practices for Self-Hosters

If you deploy your own instance locally, apply these additional measures:

### General
- Use TLS 1.2+ if exposed externally
- Keep Node.js runtime updated to latest LTS
- Rotate API keys regularly
- Monitor your VirusTotal API quota for unexpected spikes (could indicate key leakage)

---

## Bug Bounty

ThreatAtlas does not currently operate a formal bug bounty program. However, valid security reports are gratefully acknowledged, and responsible disclosers are credited in fix commits and release notes.

---

## References

- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)
- [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [VirusTotal Security Contacts](https://support.virustotal.com/hc/en-us)
- [Groq Terms of Service](https://groq.com/terms-of-service/)

---

*Last updated: September 2026 — ThreatAtlas v2.0*
