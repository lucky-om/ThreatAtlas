# Security Policy

## Overview

The ThreatAtlas team takes security seriously. This document describes our security policy, responsible disclosure process, and security practices implemented in the platform.

---

## Supported Versions

ThreatAtlas is a static web application hosted at `threatatlas.luckyverse.tech`. Security patches are applied to the current live version only.

| Version | Supported |
|---------|-----------|
| Current (live) | ✅ Supported |
| Archived/forked | ❌ Not supported |

---

## Reporting a Vulnerability

If you discover a security vulnerability in ThreatAtlas, **please do not open a public GitHub issue**. Instead, use one of the following private disclosure channels:

### Preferred: GitHub Private Disclosure
Use GitHub's [Private Security Advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) feature in this repository.

### Alternative: Email
Contact the maintainer directly via the email listed on the GitHub profile.

### What to Include

When reporting a vulnerability, please include:

- **Description:** Clear description of the vulnerability
- **Impact:** What an attacker could achieve by exploiting it
- **Steps to Reproduce:** Detailed reproduction steps
- **Proof of Concept:** Code, screenshots, or video (if applicable)
- **Suggested Fix:** If you have ideas on how to remediate it

---

## Response Timeline

| Stage | Target Time |
|-------|-------------|
| Initial acknowledgement | 48 hours |
| Vulnerability assessment | 5 business days |
| Fix development | 14 days (critical), 30 days (medium/low) |
| Public disclosure | After fix is deployed |

We follow [coordinated vulnerability disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html). Reporters who follow this policy will be credited in the fix commit message (unless they request anonymity).

---

## Scope

### In Scope

The following are within scope for security reports:

- Cross-Site Scripting (XSS) vulnerabilities in the web interface
- Content injection vulnerabilities
- Information disclosure (e.g., accidental exposure of API keys in client-side code)
- Insecure direct object references
- CSRF vulnerabilities
- Clickjacking vulnerabilities
- Security misconfigurations in headers or policies
- Open redirects to malicious sites

### Out of Scope

The following are **not** in scope:

- Vulnerabilities in VirusTotal's own API or infrastructure (report to VirusTotal directly)
- Rate limiting bypass at the VirusTotal infrastructure level
- Self-XSS attacks requiring the victim to take multiple deliberate actions
- Social engineering attacks
- Physical security
- DoS/DDoS attacks against the hosting infrastructure
- Scanner results accuracy (this is VirusTotal's domain)
- Vulnerabilities in third-party libraries that are already publicly known and for which no fix exists

---

## Security Architecture

### Client-Side Security

The following security measures are implemented on every page:

```http
Content-Security-Policy: default-src 'self';
  script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
  font-src https://fonts.gstatic.com;
  connect-src 'self' https://www.virustotal.com;
  img-src 'self' data: https:;

X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### API Key Handling

> ⚠️ **Important for self-hosters:** The VirusTotal API key in `assets/js/api.js` is a public API key. If you fork this repository and deploy your own instance, you should:
>
> 1. Replace the API key with your own VirusTotal API key
> 2. Consider implementing a server-side proxy to avoid exposing your key in client-side code
> 3. Never commit a premium API key to a public repository

### Data Handling

- No user accounts or persistent authentication
- No cookies set by ThreatAtlas (sessionStorage only, cleared on tab close)
- No third-party tracking scripts or analytics that collect personal data
- All scan submissions pass directly to VirusTotal — ThreatAtlas does not store them

### Input Sanitization

All user input rendered into the DOM is processed through the `escHtml()` function in `assets/js/ui.js` which escapes `&`, `<`, `>`, `"`, and `'` characters to prevent XSS injection.

### Dependency Security

ThreatAtlas has **zero JavaScript dependencies**. No npm packages, no CDN-loaded scripts, no third-party libraries that could be compromised via supply chain attacks. All functionality is implemented in vanilla JavaScript.

---

## Server-Side Recommendations

If you are self-hosting ThreatAtlas, apply the following server-side security headers in addition to the meta-tag CSP:

```nginx
# Nginx example
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self' https://www.virustotal.com; img-src 'self' data: https:;" always;
```

Also ensure:
- TLS 1.2+ only (disable TLS 1.0 and 1.1)
- HTTPS redirect (301) from HTTP
- HSTS preload submission if appropriate
- Regular dependency and certificate monitoring

---

## Known Security Considerations

| Item | Status | Notes |
|------|--------|-------|
| API key in client-side JS | ⚠️ Known limitation | Public API key only; premium key requires server-side proxy |
| `unsafe-inline` in CSP | ⚠️ Known limitation | Required for inline `<style>` tags; nonce-based CSP planned |
| No server-side validation | ℹ️ By design | Static site; all validation is client-side |
| File upload to VirusTotal | ℹ️ By design | Files are processed by VirusTotal and may be shared with partners |

---

## Bug Bounty

ThreatAtlas does not currently operate a formal bug bounty program. However, we do publicly acknowledge responsible disclosures in our changelog and are grateful for the security community's contributions.

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [VirusTotal Security Contacts](https://support.virustotal.com/hc/en-us)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)

---

*Last updated: July 2026*
