# Production Security Hardening & Penetration Test Remediation Guide

This document provides the complete, authoritative security remediation plan for **Shasa Engineering** (`https://shasaengineering.online`, `https://www.shasaengineering.online`) and the internal homelab management plane (`https://server.shasaengineering.online` / TrueNAS SCALE).

---

## 1. Penetration Test Findings & Remediation Matrix

| Finding Record | Vulnerability Class | Affected Surface | Root Cause | Remediation Applied |
| :--- | :--- | :--- | :--- | :--- |
| **#21 & #22** | Security Misconfiguration / Clickjacking | Apex & WWW (`/`, `/portal`) | Missing HSTS, CSP, XFO, XCTO, COOP, CORP headers | Enforced in `_worker.js`, `_headers`, and Cloudflare Transform Rules |
| **#23** | CORS Misconfiguration | Apex `/portal` (Cloudflare Access 302) | Verbatim reflection of caller `Origin` with `ACAC: true` and no `Vary: Origin` | Cloudflare Response Transform Rule stripping `ACAO` and `ACAC` |
| **#24** | Missing Rate Limiting / Lockout | `www.shasaengineering.online/portal` | Form processed unlimited invalid submissions with HTTP 200 | Server-side IP sliding-window (5 attempts/15m) + Global vault limiter (30/hr) emitting HTTP 429 + `Retry-After` + single-use TOTP replay suppression |
| **#25 & #30** | Information Disclosure | `server.shasaengineering.online/ui/*.map` | Production Angular `.map` source maps & `en.json` publicly served | Cloudflare Zero Trust Access gate + WAF rule blocking `*.map` |
| **#26 & #28** | Information Disclosure | `wss://server.shasaengineering.online/api/current` | Unauthenticated WebSocket JSON-RPC errors leak Python tracebacks | Cloudflare Zero Trust Access gate + WAF origin restriction |
| **#27** | Information Disclosure | `server.shasaengineering.online/api/current` | Pre-auth JSON-RPC methods leak host UUID & auth schemes | Cloudflare Zero Trust Access gate |
| **#29** | Information Disclosure | `server.shasaengineering.online/api/docs/` | API documentation & exact TrueNAS build disclosed pre-auth | Cloudflare Zero Trust Access gate + WAF rule blocking `/api/docs/` |
| **#31** | Security Misconfiguration | `server.shasaengineering.online/ui/` | Appliance advertises `HSTS: max-age=0` (HSTS disabled) | Cloudflare Response Transform Rule overriding `max-age=0` with `max-age=31536000; includeSubDomains` |

---

## 2. Application Hardening (`_worker.js` & `_headers`)

### A. Server-Side Stateful Rate Limiting on `POST /portal`
Implemented in `_worker.js`:
- **Client IP Tracking:** Keyed on `CF-Connecting-IP` (with fallback to `x-real-ip` / `x-forwarded-for`).
- **IP Attempt Threshold:** Max 5 failed attempts per 15-minute sliding window.
- **Lockout Response:** On attempt 6, returns `HTTP 429 Too Many Requests` with a strict `Retry-After: <seconds>` header and a locked-down dark-mode UI with dynamic countdown.
- **Progressive Backoff:** Subsequent violations multiply lockout duration ($15\text{m} \rightarrow 30\text{m} \rightarrow 45\text{m} \rightarrow 60\text{m}$).
- **Global Vault Limiter:** Max 30 aggregate failed attempts per 60 minutes across all clients triggers an emergency vault cooldown.
- **Single-Use TOTP Replay Suppression:** Authenticator codes are tracked in a sliding 180-second window. Any attempt to replay a code within the active window is immediately rejected.
- **Persistent Lockout State on GET:** Clients under active lockout also receive `HTTP 429` on `GET /portal`.
- **Structured Audit Logging:** Every failure, replay, and lockout trigger logs structured JSON to `console.warn` / `console.error` with client IP, timestamp, attempt count, and incident IDs.

### B. Origin-Level Security Headers
Emitted across all responses in `_worker.js` and `_headers`:
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://www.shasaengineering.online https://cloudflareinsights.com; base-uri 'self'; form-action 'self'; frame-ancestors 'none';
```

---

## 3. Cloudflare Edge & Zero Trust Configuration

### A. Close the `www` Access Gap
Currently, `shasaengineering.online/portal` is gated by Cloudflare Access, while `www.shasaengineering.online/portal` serves the in-worker 2FA gate. To achieve defense-in-depth:

#### Option 1: Redirect `www/portal` to Apex (Recommended & Instant)
In Cloudflare Dashboard &rarr; **Rules** &rarr; **Redirect Rules** &rarr; **Create Rule**:
- **Rule Name:** `Redirect WWW Portal to Access Apex Gate`
- **When incoming requests match:**
  ```text
  (http.host eq "www.shasaengineering.online" and http.request.uri.path starts_with "/portal")
  ```
- **Type:** Dynamic
- **Target URL Expression:**
  ```text
  concat("https://shasaengineering.online", http.request.uri.path)
  ```
- **Status Code:** `301 - Moved Permanently` (or `302 - Temporary Redirect`)
- **Preserve query string:** `Enabled`

#### Option 2: Extend Zero Trust Access Application
In **Zero Trust Dashboard** &rarr; **Access** &rarr; **Applications**:
1. Edit the application protecting `shasaengineering.online/portal`.
2. Under **Application domain**, add `www.shasaengineering.online` with path `/portal*`.

---

### B. Cloudflare WAF Rate Limiting Rule (`/portal`)
In Cloudflare Dashboard &rarr; **Security** &rarr; **WAF** &rarr; **Rate limiting rules** &rarr; **Create rule**:
- **Rule Name:** `Protect Homelab Portal 2FA Form`
- **If incoming requests match:**
  ```text
  (http.request.uri.path starts_with "/portal" and http.request.method eq "POST")
  ```
- **Rate:** `5` requests per `10 seconds` per IP
- **Action:** `Block` (or `Managed Challenge`)
- **Duration:** `15 minutes`

---

### C. Cloudflare Response Header Transform Rules

Navigate to **Rules** &rarr; **Transform Rules** &rarr; **Modify Response Header**:

#### Rule 1: Eliminate CORS Reflection on `/portal` (Finding #23 Fix)
- **Rule Name:** `Strip CORS on Portal Redirects`
- **When incoming requests match:**
  ```text
  (http.request.uri.path starts_with "/portal")
  ```
- **Actions:**
  - `Remove` &rarr; Header name: `Access-Control-Allow-Origin`
  - `Remove` &rarr; Header name: `Access-Control-Allow-Credentials`

#### Rule 2: Enforce Global Security Headers at the Edge
- **Rule Name:** `Apply Global Edge Security Headers`
- **When incoming requests match:**
  ```text
  (http.host eq "shasaengineering.online" or http.host eq "www.shasaengineering.online")
  ```
- **Actions (Set static headers):**
  - `X-Content-Type-Options`: `nosniff`
  - `X-Frame-Options`: `DENY`
  - `Referrer-Policy`: `strict-origin-when-cross-origin`
  - `Permissions-Policy`: `camera=(), microphone=(), geolocation=(), payment=(), usb=()`
  - `Cross-Origin-Opener-Policy`: `same-origin`
  - `Cross-Origin-Resource-Policy`: `same-origin`

#### Rule 3: Override TrueNAS HSTS `max-age=0` (Finding #31 Fix)
- **Rule Name:** `Fix TrueNAS HSTS Header`
- **When incoming requests match:**
  ```text
  (http.host eq "server.shasaengineering.online")
  ```
- **Actions:**
  - `Set static` &rarr; `Strict-Transport-Security`: `max-age=31536000; includeSubDomains; preload`

---

### D. Cloudflare SSL/TLS HSTS Configuration
In Cloudflare Dashboard &rarr; **SSL/TLS** &rarr; **Edge Certificates** &rarr; **HTTP Strict Transport Security (HSTS)**:
1. Click **Change HSTS Settings**.
2. **Enable HSTS:** `On`
3. **Max-Age:** `12 months (31536000 seconds)`
4. **Apply HSTS to subdomains (includeSubDomains):** `Enabled`
5. **Preload:** `Enabled`
6. **No-sniff header:** `Enabled`

---

## 4. TrueNAS Admin Plane Hardening (`server.shasaengineering.online`)

### A. Primary Fix: Enforce Cloudflare Zero Trust Access
The TrueNAS SCALE admin interface should never be directly accessible from the public internet. Put it behind Cloudflare Access matching `nas.shasaengineering.online`:

1. Navigate to **Zero Trust Dashboard** &rarr; **Access** &rarr; **Applications** &rarr; **Add an application**.
2. Choose **Self-hosted**.
3. **Application Name:** `TrueNAS SCALE Admin Plane`
4. **Application Domain:** `server.shasaengineering.online`, Path: `*`
5. **Session Duration:** `24 Hours`
6. Under **Policies**:
   - **Policy Name:** `Allow Homelab Admins Only`
   - **Action:** `Allow`
   - **Rule Type (Include):**
     - Selector: `Emails` &rarr; `sailor.krutarth@yahoo.in`
7. Save Application.
*Effect: All anonymous HTTP, WebSocket (`/api/current`), source maps (`/ui/*.map`), and API docs (`/api/docs/*`) requests immediately receive a 302 redirect to Cloudflare Access login, completely shutting down unauthenticated reconnaissance.*

---

### B. Defense-in-Depth Cloudflare WAF Rules on TrueNAS
In Cloudflare Dashboard &rarr; **Security** &rarr; **WAF** &rarr; **Custom Rules**:

#### Rule 1: Block Public Access to Source Maps & API Docs
- **Rule Name:** `Block TrueNAS Source Maps and API Docs`
- **Expression:**
  ```text
  (http.host eq "server.shasaengineering.online" and (http.request.uri.path contains ".map" or http.request.uri.path starts_with "/api/docs"))
  ```
- **Action:** `Block`

#### Rule 2: Restrict WebSocket Upgrade Origins
- **Rule Name:** `Restrict TrueNAS JSON-RPC WebSocket Origin`
- **Expression:**
  ```text
  (http.host eq "server.shasaengineering.online" and http.request.uri.path starts_with "/api/" and http.request.headers["upgrade"][0] eq "websocket" and not (http.request.headers["origin"][0] in {"https://server.shasaengineering.online" "https://nas.shasaengineering.online"}))
  ```
- **Action:** `Block`

---

## 5. Automated Verification Test Suite

A self-contained test script is provided in [`scripts/verify-hardening.sh`](file:///C:/Users/Krutarth%20Sailor/.gemini/antigravity/scratch/shasa-website/scripts/verify-hardening.sh).

### Run Verification:
```bash
chmod +x scripts/verify-hardening.sh
./scripts/verify-hardening.sh
```

### What the Script Verifies:
1. **Rate Limiting:** Sends 5 consecutive failed POST requests to `/portal`; verifies attempt 6 returns `HTTP 429 Too Many Requests` with a valid `Retry-After:` header, and subsequent GET confirms active lockout.
2. **Security Headers:** Audits Apex and WWW for `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `COOP`, `CORP`, and `CSP`.
3. **CORS Reflection:** Tests Apex `/portal` with `Origin: https://evil-attacker.example` and `Origin: null` to ensure arbitrary origin reflection and credential exposure are eliminated.
4. **TrueNAS Admin Plane:** Verifies `server.shasaengineering.online` does not expose `/ui/`, source maps (`*.map`), or `/api/docs/` to anonymous callers, and verifies `max-age=0` HSTS is disabled.
