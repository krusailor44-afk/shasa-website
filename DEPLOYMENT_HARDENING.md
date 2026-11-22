# Production Security Hardening & Edge Caching Guide

This document defines the security configuration and edge caching rules for **Shasa Engineering** (`https://www.shasaengineering.online/`).

---

## 1. Security Headers Configuration

The production Cloudflare Pages deployment applies strict security headers at the edge (configured in `_headers` and enforced via `_worker.js` responses):

| Header | Value | Purpose |
| :--- | :--- | :--- |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Forces HTTPS and protects against SSL stripping attacks. |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-sniffing exploits. |
| `X-Frame-Options` | `DENY` | Completely blocks clickjacking and framing of all endpoints. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Protects visitor referral paths on cross-origin requests. |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Denies access to sensitive browser device features. |
| `Content-Security-Policy` | Defined below | Restricts executable scripts, stylesheets, fonts, and network connections. |

### Content-Security-Policy (CSP) Breakdown
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://www.shasaengineering.online; base-uri 'self'; form-action 'self'; frame-ancestors 'none';
```
- **`default-src 'self'`**: Disallows loading resources from unapproved third-party domains by default.
- **`script-src 'self' 'unsafe-inline'`**: Enables the lightweight vanilla JS telemetry loader, email clipboard copy handler, and interactive terminal simulation.
- **`style-src` & `font-src`**: Restricts styling to local CSS and Google Fonts (`fonts.googleapis.com` / `fonts.gstatic.com`).
- **`connect-src 'self' https://www.shasaengineering.online`**: Locks AJAX/fetch operations exclusively to first-party endpoints (`/telemetry.json`).
- **`frame-ancestors 'none'`**: Complements `X-Frame-Options: DENY` in modern browsers.

---

## 2. Cloudflare Cache Rules Specification

To eliminate unnecessary origin load during traffic spikes while preserving security on administrative endpoints and freshness for edge telemetry, configure the following **Cache Rules** in Cloudflare Dashboard under **Caching &rarr; Cache Rules**:

### Rule 1: Edge Cache Public Portfolio (`/`)
- **Rule Name:** `Cache Public Portfolio Homepage`
- **Expression:**
  ```text
  (http.host eq "shasaengineering.online" or http.host eq "www.shasaengineering.online") and (http.request.uri.path eq "/" or http.request.uri.path eq "/robots.txt" or http.request.uri.path eq "/sitemap.xml")
  ```
- **Cache Eligibility:** `Eligible for cache`
- **Edge TTL:** `Override origin` &rarr; `4 hours` (or `1 hour`)
- **Browser TTL:** `Override origin` &rarr; `1 hour`
- **Serve Stale Content While Revalidating:** `Enabled`

### Rule 2: Bypass Cache for Private & Dynamic Endpoints
- **Rule Name:** `Bypass Cache for Portal and Dynamic Telemetry`
- **Expression:**
  ```text
  http.request.uri.path starts_with "/portal" or http.request.uri.path eq "/telemetry.json"
  ```
- **Cache Eligibility:** `Bypass cache`

---

## 3. Threat Model & OpSec Verification

1. **Unadvertised Management Endpoints:** The private Homelab Vault (`/portal`) is removed from all public navigation, footer links, and `robots.txt`. It requires Cloudflare Zero Trust authentication, master password validation, and RFC 6238 TOTP 2FA.
2. **Sanitized Telemetry:** Real local hostnames, usernames, private IP ranges (`10.0.0.0/8`, `192.168.0.0/16`), and specific port bindings are stripped from all public HTML and telemetry payloads.
3. **Decoupled Branding:** The personal engineering portfolio represents Krutarth Sailor and Shasa Engineering independently from corporate employers.
